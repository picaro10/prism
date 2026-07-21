# PRISM v1.0.0 — Fase 2: AI triage layer

> **Estado:** Diseño aprobado, pendiente de plan de implementación
> **Fecha:** 2026-06-09 (Día 3)
> **Componente nuevo:** `src/ai/` (capa LLM sobre el JSON estático)

## Contexto

Fase 1 (v0.1–v0.9.1) construyó la "máquina de rayos X": 6 analizadores estáticos que
escanean todo, cada archivo, cada vez. La visión del proyecto siempre fue fusionarla con
"el médico" — un LLM que juzga contexto, como hacía Claude Code en el loop manual
(distinguir un mount path de Docker de una credencial real, un fixture de código de
producción). Fase 2 integra ese juicio.

Esta versión toma **un solo trabajo**: triage de findings (veredicto real vs falso-positivo
en contexto). Resumen ejecutivo, guía de remediación y re-scoring quedan para v1.1+ — mismo
escalonamiento de bajo riesgo que v0.8/v0.9.

## Alcance

- **`prism analyze <path> --ai`**: corre Fase 1 y luego triage. Sin `--ai`, PRISM es idéntico
  a hoy (sin red, sin API key, sin costo — Fase 1 sigue siendo útil sola).
- **Triage**: por cada finding, un veredicto `real | false-positive | uncertain` + confianza
  + razonamiento, leyendo el código real del archivo.
- **NO** re-puntúa (la capa estática manda el score; la IA anota). **NO** resumen narrativo,
  remediación, ni comando separado. **NO** muta los findings existentes.

## Modelo y API

De la referencia de la API de Claude (`claude-api` skill):
- SDK oficial **`@anthropic-ai/sdk`** (proyecto TS/ESM).
- Modelo **`claude-opus-4-8`** (default; override vía `--ai-model`).
- `thinking: { type: 'adaptive' }`, `output_config: { effort: 'high' }` (triage es juicio).
- **Structured outputs**: `client.messages.parse()` + **Zod** vía `zodOutputFormat` →
  veredictos validados por schema, sin parseo manual. Nuevas deps: `@anthropic-ai/sdk`, `zod`.
- **Prompt caching**: prefijo estable (system prompt + contexto de proyecto: stack, scores,
  summary) con `cache_control: { type: 'ephemeral' }` → ~0.1× en lecturas a través de las
  N llamadas por archivo. El contenido volátil (archivo + sus findings) va después del
  breakpoint.
- No se necesita streaming (los veredictos son chicos; `max_tokens` ~4000 por llamada).

## Arquitectura — `src/ai/`

Diseñado con un **seam de testeo**: toda la lógica es pura salvo un `LLMClient` inyectable.

### `src/ai/types.ts`

```ts
export type Classification = 'real' | 'false-positive' | 'uncertain';

export interface Verdict {
  /** Stable key linking back to a finding: `${id}|${file ?? ''}|${line ?? ''}` */
  findingKey: string;
  classification: Classification;
  /** 0.0–1.0 model-reported confidence */
  confidence: number;
  /** One or two sentences explaining the verdict */
  reasoning: string;
}

export interface TriageResult {
  verdicts: Verdict[];
  summary: { real: number; falsePositive: number; uncertain: number };
}

/** Input for one triage call: a file's content + the findings on it. */
export interface TriageUnit {
  /** File path, or null for project-level findings (no file). */
  file: string | null;
  /** File content (empty string for project-level / unreadable). */
  content: string;
  findings: Finding[];
}

/** The injectable seam. Real impl calls Claude; tests inject a fake. */
export interface LLMClient {
  triage(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]>;
}

export interface ProjectContext {
  projectName: string;
  stack: string;
  overallScore: number;
  /** Per-category one-line summaries, for the cached prefix. */
  categorySummaries: string[];
}
```

`findingKey(f: Finding): string` — exported pure helper, `${f.id}|${f.file ?? ''}|${f.line ?? ''}`.

### `src/ai/prompt.ts` (pure)

- `buildSystemPrompt(): string` — the "doctor" persona + triage instructions: judge each
  finding as real/false-positive/uncertain *given the code and project context*; a finding
  in a fixture/template/generated file is almost always a false positive; a mount path is not
  a hardcoded secret; reason briefly; output strictly per the schema. Stable across calls
  (cacheable).
- `buildProjectContextBlock(ctx: ProjectContext): string` — cacheable project summary.
- `buildUserContent(unit: TriageUnit): string` — the volatile per-file block: file path,
  file content (truncated to a max, e.g. 8000 lines / 200KB to bound tokens), and the list of
  findings on it (id, severity, title, description, line, meta).

### `src/ai/client.ts`

- `AnthropicLLMClient implements LLMClient` — constructs `new Anthropic()` (reads
  `ANTHROPIC_API_KEY` from env), calls `client.messages.parse()` with:
  - `model` (default `claude-opus-4-8`), `max_tokens: 4096`, `thinking: {type:'adaptive'}`,
    `output_config: { effort: 'high', format: zodOutputFormat(VerdictArraySchema) }`.
  - `system` as an array with the persona+context block carrying `cache_control`.
  - `messages`: one user turn with `buildUserContent(unit)`.
  - **Alignment:** `buildUserContent` labels each finding with its `findingKey`. The schema
    requires the model to **echo `findingKey`** in each verdict. `triage.ts` then validates
    every returned key against the set of keys it sent: keys not sent are dropped; findings
    with no returned verdict get a synthesized `uncertain` verdict (confidence 0, reasoning
    "no verdict returned") so every finding has exactly one verdict and counts reconcile.
- Zod schema `VerdictSchema` mirrors `Verdict` (includes `findingKey: z.string()`,
  `classification` enum, `confidence` 0–1, `reasoning`). `messages.parse()` handles
  validation/retry against the schema.
- Typed error handling: `Anthropic.AuthenticationError` → rethrow as a clear "invalid/missing
  API key" error; `Anthropic.RateLimitError` / `APIError` → wrap with context. The SDK
  auto-retries 429/5xx.

### `src/ai/triage.ts`

- `runTriage(report: AuditReport, readFile: FileReader, client: LLMClient): Promise<TriageResult>`:
  1. Build `ProjectContext` from the report.
  2. Group `report.findings` by `file` (null-file findings → one project-level group).
  3. For each group: read the file content (try/catch → empty string on error), build a
     `TriageUnit`, call `client.triage(unit, ctx)`. Groups processed sequentially (prompt
     cache warms on the first call; keeps it simple — no parallel-write cache races).
  4. Flatten verdicts, compute `summary` counts, return `TriageResult`.
- Pure except for the injected `client` and `readFile`.

## Integración

- `PrismConfig` gains `ai?: boolean` and `aiModel?: string`.
- `AuditReport` gains `aiTriage?: TriageResult`.
- `runAudit(config, onProgress)`: after building the static report, if `config.ai`:
  - Construct `AnthropicLLMClient` (throws clear error if no `ANTHROPIC_API_KEY`).
  - `report.aiTriage = await runTriage(report, readFile, client)`.
  - Errors from triage are caught: log a warning via `onProgress`, leave `aiTriage` undefined,
    still return the static report (Fase 1 result must survive an AI failure).
- CLI (`src/cli/index.ts`): add `--ai` and `--ai-model <id>` options; set `config.ai`.

## Reporting

- **CLI reporter** (`src/reporters/cli.ts`): when `report.aiTriage` exists, for each finding
  render its verdict inline — `✓ real` (green) / `✗ likely FP` (dim) / `? uncertain` (yellow)
  + the reasoning. Add a triage summary line: `AI triage: N real · M false positives · K uncertain`.
  Findings without a verdict (shouldn't happen, but defensive) render unchanged.
- **JSON reporter** (`src/reporters/json.ts`): `aiTriage` is part of the report object, so it
  serializes automatically — verify it's included.

## API key / degradation

- `--ai` with no `ANTHROPIC_API_KEY` → clear error, non-zero exit, before any analysis cost.
- API errors mid-triage → warning, static report still printed/saved.
- `--ai` is strictly opt-in; default runs are offline and free.

## Testing

### Unit (`tests/ai/*.test.ts`), all with a `FakeLLMClient` — no network
- `findingKey`: stable composite key (with/without file/line).
- `prompt.ts`: system prompt contains the triage rubric; `buildUserContent` includes file
  content + each finding's id/title; project-context block includes stack + score.
- `triage.ts` via `FakeLLMClient` returning canned verdicts:
  - Groups findings by file (N files → N calls; project-level findings → 1 call).
  - Reads file content and passes it in the unit (assert the fake received it).
  - Flattens verdicts and computes correct `summary` counts.
  - A file that fails to read → empty content, still triaged (no crash).
  - Alignment: a fake returning a verdict for an unknown key → dropped; a finding with no
    returned verdict → synthesized `uncertain` (so every finding has exactly one verdict).
- Engine integration: `runAudit` with `ai: true` and an injected fake client attaches
  `aiTriage` to the report without mutating findings or the score. (Requires the engine to
  accept an optional client injection point for tests — see plan.)
- "No API key" path: constructing `AnthropicLLMClient` (or the engine AI branch) without
  `ANTHROPIC_API_KEY` throws the clear error.

### Real-world verification (manual, NOT in the suite)
Run `prism analyze /opt/orion_new --ai` and `/opt/tecofri-n8n --ai` with a real key:
- The fixture-context findings (if any leak) and the known mount-path style → `false-positive`.
- A genuinely real finding (e.g. a real committed secret) → `real`.
- Spot-check reasoning quality. Record token cost.

## Fuera de alcance (explícito)

- Resumen ejecutivo narrativo del proyecto.
- Guía de remediación / fixes propuestos.
- Re-scoring del overall score con base en los veredictos.
- Comando `prism triage <report.json>` sobre JSONs guardados.
- Paralelización de las llamadas por archivo (sequential v1; revisit if latency hurts).
- Batch API / cost-optimized async.

Todo candidato a v1.1+.

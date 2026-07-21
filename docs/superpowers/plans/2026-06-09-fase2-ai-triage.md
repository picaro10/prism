# Fase 2: AI Triage Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `--ai` triage layer to PRISM: an LLM judges each static finding as `real | false-positive | uncertain` (reading the file's code), attached to the report without mutating findings or the score.

**Architecture:** A new `src/ai/` module with a pure core (group findings by file → build prompts → assemble verdicts) behind an injectable `LLMClient` seam. The real client uses `@anthropic-ai/sdk` (`claude-opus-4-8`, adaptive thinking, Zod structured outputs, prompt caching). Tests inject a `FakeLLMClient` — no network, no cost, no flakiness. The engine runs triage after the static report when `config.ai` is set; Fase 1 is unchanged and offline by default.

**Tech Stack:** TypeScript + Node 22, Vitest, `@anthropic-ai/sdk`, `zod`. The project is git-initialized — commit after each task.

> Baseline: 169 tests passing, `tsc --noEmit` clean, `npm run lint` exit 0. Every checkpoint runs all three.

---

## File Structure

- **Create** `src/ai/types.ts` — `Classification`, `Verdict`, `TriageResult`, `TriageUnit`, `ProjectContext`, `LLMClient` interface, `findingKey()` helper.
- **Create** `src/ai/prompt.ts` — pure prompt builders: `buildSystemPrompt`, `buildProjectContextBlock`, `buildUserContent`.
- **Create** `src/ai/triage.ts` — `runTriage(report, readFile, client)` orchestration (pure except injected deps).
- **Create** `src/ai/client.ts` — `AnthropicLLMClient implements LLMClient` (the only file that imports the SDK) + the Zod schema.
- **Modify** `src/core/types.ts` — add `ai?`/`aiModel?` to `PrismConfig`, `aiTriage?` to `AuditReport`.
- **Modify** `src/core/engine.ts` — run triage when `config.ai`; accept an optional injected client for tests.
- **Modify** `src/cli/index.ts` — `--ai` / `--ai-model` options.
- **Modify** `src/reporters/cli.ts` — render verdicts + triage summary.
- **Create** `tests/ai/types.test.ts`, `tests/ai/prompt.test.ts`, `tests/ai/triage.test.ts`, plus engine-integration tests in `tests/core/engine.test.ts`.

The pure core (types, prompt, triage) is fully testable with a fake client. `client.ts` (SDK calls) is exercised only by manual real-world verification, never the unit suite.

---

## Task 1: Install dependencies

**Files:** `package.json` (modified by npm)

- [ ] **Step 1: Install the SDK and Zod**

Run:
```bash
cd /opt/prism && npm install @anthropic-ai/sdk zod
```
Expected: both added to `dependencies`; `npm install` exits 0.

- [ ] **Step 2: Verify the suite still passes (no code changed yet)**

Run: `npx vitest run` then `npx tsc --noEmit`
Expected: 169 passed, tsc clean.

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "build: add @anthropic-ai/sdk and zod for AI triage"
```

---

## Task 2: `src/ai/types.ts` — types + `findingKey`

**Files:**
- Create: `src/ai/types.ts`
- Test: `tests/ai/types.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/ai/types.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { findingKey } from '../../src/ai/types.js';
import type { Finding } from '../../src/core/types.js';

function f(partial: Partial<Finding>): Finding {
  return {
    id: 'SEC-001',
    category: 'security',
    severity: 'high',
    title: 't',
    description: 'd',
    ...partial,
  };
}

describe('findingKey', () => {
  it('combines id, file and line', () => {
    expect(findingKey(f({ id: 'SEC-ENV', file: 'src/a.ts', line: 3 }))).toBe('SEC-ENV|src/a.ts|3');
  });

  it('handles a project-level finding with no file or line', () => {
    expect(findingKey(f({ id: 'TST-001' }))).toBe('TST-001||');
  });

  it('handles a file with no line', () => {
    expect(findingKey(f({ id: 'STR-011', file: 'src/big.ts' }))).toBe('STR-011|src/big.ts|');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/ai/types.test.ts`
Expected: FAIL — cannot resolve `../../src/ai/types.js`.

- [ ] **Step 3: Write minimal implementation**

Create `src/ai/types.ts`:

```ts
import type { Finding, AnalysisCategory } from '../core/types.js';

export type Classification = 'real' | 'false-positive' | 'uncertain';

export interface Verdict {
  /** Stable key linking back to a finding: `${id}|${file ?? ''}|${line ?? ''}`. */
  findingKey: string;
  classification: Classification;
  /** 0.0–1.0 model-reported confidence. */
  confidence: number;
  /** One or two sentences explaining the verdict. */
  reasoning: string;
}

export interface TriageResult {
  verdicts: Verdict[];
  summary: { real: number; falsePositive: number; uncertain: number };
}

/** One triage call's input: a file's content + the findings on it. */
export interface TriageUnit {
  /** File path, or null for project-level findings. */
  file: string | null;
  /** File content ('' for project-level or unreadable). */
  content: string;
  findings: Finding[];
}

export interface ProjectContext {
  projectName: string;
  stack: string;
  overallScore: number;
  /** Per-category one-line summaries (cacheable prefix). */
  categorySummaries: string[];
}

/** Injectable seam. Real impl calls Claude; tests inject a fake. */
export interface LLMClient {
  triage(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]>;
}

/** Stable identifier for a finding, used to align verdicts back to findings. */
export function findingKey(f: Finding): string {
  return `${f.id}|${f.file ?? ''}|${f.line ?? ''}`;
}

// Re-export for convenience in the ai module.
export type { Finding, AnalysisCategory };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/ai/types.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Checkpoint + commit**

Run: `npx vitest run` && `npx tsc --noEmit`
```bash
git add src/ai/types.ts tests/ai/types.test.ts
git commit -m "feat(ai): add triage types and findingKey helper"
```

---

## Task 3: `src/ai/prompt.ts` — pure prompt builders

**Files:**
- Create: `src/ai/prompt.ts`
- Test: `tests/ai/prompt.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/ai/prompt.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { buildSystemPrompt, buildProjectContextBlock, buildUserContent } from '../../src/ai/prompt.js';
import type { TriageUnit, ProjectContext } from '../../src/ai/types.js';

const ctx: ProjectContext = {
  projectName: 'demo',
  stack: 'typescript',
  overallScore: 7.5,
  categorySummaries: ['security: 8.0 — clean', 'tests: 6.0 — low ratio'],
};

describe('buildSystemPrompt', () => {
  it('states the triage job and the three classifications', () => {
    const p = buildSystemPrompt();
    expect(p).toMatch(/false-positive/);
    expect(p).toMatch(/real/);
    expect(p).toMatch(/uncertain/);
    // Names the key heuristic: fixtures/generated are usually FPs
    expect(p.toLowerCase()).toMatch(/fixture|generated|test/);
    // Instructs to echo the finding key
    expect(p.toLowerCase()).toMatch(/findingkey|finding key/);
  });
});

describe('buildProjectContextBlock', () => {
  it('includes project name, stack, score and category summaries', () => {
    const b = buildProjectContextBlock(ctx);
    expect(b).toMatch(/demo/);
    expect(b).toMatch(/typescript/);
    expect(b).toMatch(/7\.5/);
    expect(b).toMatch(/low ratio/);
  });
});

describe('buildUserContent', () => {
  it('includes the file path, content, and each finding with its key', () => {
    const unit: TriageUnit = {
      file: 'src/a.ts',
      content: 'const SECRET = "abc";',
      findings: [
        { id: 'SEC-001', category: 'security', severity: 'high', title: 'Hardcoded secret', description: 'd', file: 'src/a.ts', line: 1 },
      ],
    };
    const c = buildUserContent(unit);
    expect(c).toMatch(/src\/a\.ts/);
    expect(c).toMatch(/const SECRET/);
    expect(c).toMatch(/SEC-001\|src\/a\.ts\|1/); // the findingKey
    expect(c).toMatch(/Hardcoded secret/);
  });

  it('handles a project-level unit with no file', () => {
    const unit: TriageUnit = {
      file: null,
      content: '',
      findings: [
        { id: 'TST-001', category: 'tests', severity: 'critical', title: 'No tests', description: 'd' },
      ],
    };
    const c = buildUserContent(unit);
    expect(c).toMatch(/TST-001/);
    expect(c).toMatch(/project-level|no file/i);
  });

  it('truncates very large file content', () => {
    const big = 'x\n'.repeat(20000);
    const unit: TriageUnit = { file: 'big.ts', content: big, findings: [] };
    const c = buildUserContent(unit);
    expect(c.length).toBeLessThan(big.length);
    expect(c).toMatch(/truncated/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/ai/prompt.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

Create `src/ai/prompt.ts`:

```ts
import type { TriageUnit, ProjectContext } from './types.js';
import { findingKey } from './types.js';

/** Max characters of file content sent per triage call (bounds token cost). */
const MAX_CONTENT_CHARS = 60_000;

export function buildSystemPrompt(): string {
  return [
    'You are a senior security and code-quality reviewer triaging the findings of a static',
    'analyzer (PRISM). The static layer flags patterns; your job is to judge each finding in',
    'context by reading the actual code.',
    '',
    'For each finding, classify it as exactly one of:',
    '- "real": a genuine issue worth a human\'s attention.',
    '- "false-positive": the pattern matched but, given the code and project context, it is not',
    '  a real problem (e.g. a Docker mount path mistaken for a hardcoded secret; a finding on a',
    '  test fixture, generated file, or template; an intentional, documented choice).',
    '- "uncertain": you cannot tell from the available context.',
    '',
    'Guidance: findings on fixtures, generated code, templates, or vendored code are almost',
    'always false positives. A value that is a file path or env-var reference is not a hardcoded',
    'secret. Be skeptical but fair — do not call a genuine issue a false positive just because',
    'it is low severity.',
    '',
    'For every finding you are given, return one verdict object. Echo back the exact findingKey',
    'string you were given for that finding. Keep reasoning to one or two sentences.',
  ].join('\n');
}

export function buildProjectContextBlock(ctx: ProjectContext): string {
  return [
    `Project: ${ctx.projectName}`,
    `Stack: ${ctx.stack}`,
    `Overall static score: ${ctx.overallScore}/10`,
    'Category summaries:',
    ...ctx.categorySummaries.map((s) => `  - ${s}`),
  ].join('\n');
}

export function buildUserContent(unit: TriageUnit): string {
  const parts: string[] = [];

  if (unit.file) {
    parts.push(`File: ${unit.file}`);
    let content = unit.content;
    if (content.length > MAX_CONTENT_CHARS) {
      content = `${content.slice(0, MAX_CONTENT_CHARS)}\n… [content truncated]`;
    }
    parts.push('```');
    parts.push(content);
    parts.push('```');
  } else {
    parts.push('These are project-level findings (no specific file).');
  }

  parts.push('');
  parts.push('Findings to triage:');
  for (const f of unit.findings) {
    parts.push(`- findingKey: ${findingKey(f)}`);
    parts.push(`  id: ${f.id} | severity: ${f.severity} | title: ${f.title}`);
    parts.push(`  description: ${f.description}`);
    if (f.line !== undefined) parts.push(`  line: ${f.line}`);
    if (f.meta) parts.push(`  meta: ${JSON.stringify(f.meta)}`);
  }

  return parts.join('\n');
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/ai/prompt.test.ts`
Expected: PASS.

- [ ] **Step 5: Checkpoint + commit**

Run: `npx vitest run` && `npx tsc --noEmit`
```bash
git add src/ai/prompt.ts tests/ai/prompt.test.ts
git commit -m "feat(ai): add pure prompt builders"
```

---

## Task 4: `src/ai/triage.ts` — orchestration

**Files:**
- Create: `src/ai/triage.ts`
- Test: `tests/ai/triage.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/ai/triage.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { runTriage } from '../../src/ai/triage.js';
import { findingKey } from '../../src/ai/types.js';
import type { LLMClient, TriageUnit, Verdict, ProjectContext } from '../../src/ai/types.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}

function report(findings: Finding[]): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '', completedAt: '', durationMs: 0,
    overallScore: 7,
    categories: [{ category: 'security', score: 8, maxScore: 10, findings: [], summary: 'sec ok' }],
    findings,
    projectMeta: { stack: { primary: 'typescript', secondary: [] }, totalLoc: 0, totalFiles: 0, hasGit: true, hasDocker: false, hasCi: false, frameworks: [] },
    prismVersion: '1.0.0',
  };
}

// Fake client: records the units it received, returns a canned verdict per finding.
class FakeClient implements LLMClient {
  units: TriageUnit[] = [];
  contexts: ProjectContext[] = [];
  constructor(private fn: (u: TriageUnit) => Verdict[]) {}
  async triage(unit: TriageUnit, ctx: ProjectContext): Promise<Verdict[]> {
    this.units.push(unit);
    this.contexts.push(ctx);
    return this.fn(unit);
  }
}

const reader = async (p: string) => `// content of ${p}`;

describe('runTriage', () => {
  it('groups findings by file (one call per file + one for project-level)', async () => {
    const findings = [
      finding({ id: 'A', file: 'src/a.ts', line: 1 }),
      finding({ id: 'B', file: 'src/a.ts', line: 2 }),
      finding({ id: 'C', file: 'src/b.ts', line: 1 }),
      finding({ id: 'D' }), // project-level
    ];
    const client = new FakeClient((u) => u.findings.map((f) => ({ findingKey: findingKey(f), classification: 'real', confidence: 0.9, reasoning: 'r' })));
    await runTriage(report(findings), reader, client);
    // 2 files (a.ts, b.ts) + 1 project-level group = 3 calls
    expect(client.units).toHaveLength(3);
    const aUnit = client.units.find((u) => u.file === 'src/a.ts')!;
    expect(aUnit.findings).toHaveLength(2);
    expect(aUnit.content).toBe('// content of src/a.ts'); // reader was used
    const projUnit = client.units.find((u) => u.file === null)!;
    expect(projUnit.findings).toHaveLength(1);
    expect(projUnit.content).toBe('');
  });

  it('flattens verdicts and computes summary counts', async () => {
    const findings = [
      finding({ id: 'A', file: 'src/a.ts' }),
      finding({ id: 'B', file: 'src/b.ts' }),
      finding({ id: 'C', file: 'src/c.ts' }),
    ];
    const verdictByFile: Record<string, Verdict['classification']> = {
      'src/a.ts': 'real', 'src/b.ts': 'false-positive', 'src/c.ts': 'uncertain',
    };
    const client = new FakeClient((u) => u.findings.map((f) => ({ findingKey: findingKey(f), classification: verdictByFile[u.file!], confidence: 0.8, reasoning: 'r' })));
    const result = await runTriage(report(findings), reader, client);
    expect(result.summary).toEqual({ real: 1, falsePositive: 1, uncertain: 1 });
    expect(result.verdicts).toHaveLength(3);
  });

  it('synthesizes an uncertain verdict for a finding the model did not return', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' }), finding({ id: 'B', file: 'src/a.ts' })];
    // model returns a verdict only for the first finding, plus an unknown key
    const client = new FakeClient((u) => [
      { findingKey: findingKey(u.findings[0]), classification: 'real', confidence: 0.9, reasoning: 'r' },
      { findingKey: 'BOGUS|x|1', classification: 'real', confidence: 0.5, reasoning: 'noise' },
    ]);
    const result = await runTriage(report(findings), reader, client);
    expect(result.verdicts).toHaveLength(2); // one real + one synthesized
    const second = result.verdicts.find((v) => v.findingKey === findingKey(findings[1]))!;
    expect(second.classification).toBe('uncertain');
    expect(second.confidence).toBe(0);
    // the BOGUS verdict was dropped
    expect(result.verdicts.find((v) => v.findingKey === 'BOGUS|x|1')).toBeUndefined();
  });

  it('triages a file even when reading it fails', async () => {
    const findings = [finding({ id: 'A', file: 'src/missing.ts' })];
    const failReader = async () => { throw new Error('ENOENT'); };
    const client = new FakeClient((u) => u.findings.map((f) => ({ findingKey: findingKey(f), classification: 'real', confidence: 1, reasoning: 'r' })));
    const result = await runTriage(report(findings), failReader, client);
    expect(client.units[0].content).toBe('');
    expect(result.verdicts).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/ai/triage.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

Create `src/ai/triage.ts`:

```ts
import type { AuditReport, FileReader } from '../core/types.js';
import type { LLMClient, TriageResult, TriageUnit, Verdict, ProjectContext } from './types.js';
import { findingKey } from './types.js';

function buildContext(report: AuditReport): ProjectContext {
  return {
    projectName: report.projectName,
    stack: report.projectMeta.stack.primary,
    overallScore: report.overallScore,
    categorySummaries: report.categories.map((c) => `${c.category}: ${c.score}/10 — ${c.summary}`),
  };
}

export async function runTriage(
  report: AuditReport,
  readFile: FileReader,
  client: LLMClient,
): Promise<TriageResult> {
  const ctx = buildContext(report);

  // Group findings by file; null-file findings form one project-level group.
  const byFile = new Map<string | null, typeof report.findings>();
  for (const f of report.findings) {
    const key = f.file ?? null;
    const group = byFile.get(key);
    if (group) group.push(f);
    else byFile.set(key, [f]);
  }

  const verdicts: Verdict[] = [];

  for (const [file, findings] of byFile) {
    let content = '';
    if (file) {
      try {
        content = await readFile(file);
      } catch {
        content = '';
      }
    }
    const unit: TriageUnit = { file, content, findings };
    const returned = await client.triage(unit, ctx);

    // Align verdicts to the findings we sent: keep only known keys, synthesize for missing.
    const sentKeys = new Set(findings.map((f) => findingKey(f)));
    const byKey = new Map<string, Verdict>();
    for (const v of returned) {
      if (sentKeys.has(v.findingKey)) byKey.set(v.findingKey, v);
    }
    for (const f of findings) {
      const k = findingKey(f);
      verdicts.push(
        byKey.get(k) ?? { findingKey: k, classification: 'uncertain', confidence: 0, reasoning: 'no verdict returned' },
      );
    }
  }

  const summary = {
    real: verdicts.filter((v) => v.classification === 'real').length,
    falsePositive: verdicts.filter((v) => v.classification === 'false-positive').length,
    uncertain: verdicts.filter((v) => v.classification === 'uncertain').length,
  };

  return { verdicts, summary };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/ai/triage.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Checkpoint + commit**

Run: `npx vitest run` && `npx tsc --noEmit`
```bash
git add src/ai/triage.ts tests/ai/triage.test.ts
git commit -m "feat(ai): add triage orchestration with verdict alignment"
```

---

## Task 5: `src/ai/client.ts` — Anthropic SDK client

**Files:**
- Create: `src/ai/client.ts`
- Test: none in the unit suite (SDK calls are exercised by manual verification only). A type-only smoke check via `tsc` is the gate.

- [ ] **Step 1: Write the implementation**

Create `src/ai/client.ts`:

```ts
import Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import type { LLMClient, TriageUnit, ProjectContext, Verdict } from './types.js';
import { buildSystemPrompt, buildProjectContextBlock, buildUserContent } from './prompt.js';

const VerdictSchema = z.object({
  findingKey: z.string(),
  classification: z.enum(['real', 'false-positive', 'uncertain']),
  confidence: z.number(),
  reasoning: z.string(),
});
const VerdictArraySchema = z.object({ verdicts: z.array(VerdictSchema) });

export class AnthropicLLMClient implements LLMClient {
  private client: Anthropic;
  private model: string;

  constructor(model = 'claude-opus-4-8') {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error(
        'AI triage requires an ANTHROPIC_API_KEY environment variable. Set it, or run without --ai.',
      );
    }
    this.client = new Anthropic();
    this.model = model;
  }

  async triage(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]> {
    const response = await this.client.messages.parse({
      model: this.model,
      max_tokens: 4096,
      thinking: { type: 'adaptive' },
      output_config: { effort: 'high', format: zodOutputFormat(VerdictArraySchema) },
      system: [
        { type: 'text', text: buildSystemPrompt() },
        { type: 'text', text: buildProjectContextBlock(projectContext), cache_control: { type: 'ephemeral' } },
      ],
      messages: [{ role: 'user', content: buildUserContent(unit) }],
    });
    return response.parsed_output?.verdicts ?? [];
  }
}
```

- [ ] **Step 2: Type-check**

Run: `npx tsc --noEmit`
Expected: clean. If `messages.parse`, `zodOutputFormat`, or `output_config`/`thinking` field shapes mismatch the installed SDK version, **stop and report** the exact type error — do not invent field names. (The controller will reconcile against the installed `@anthropic-ai/sdk` types; these names come from the claude-api reference and may need the SDK's exact path, e.g. `@anthropic-ai/sdk/helpers/zod`.)

- [ ] **Step 3: Verify the suite still passes**

Run: `npx vitest run`
Expected: 169 + (Tasks 2–4 additions) still green. `client.ts` has no unit tests but must not break compilation of the suite.

- [ ] **Step 4: Commit**

```bash
git add src/ai/client.ts
git commit -m "feat(ai): add Anthropic SDK triage client"
```

---

## Task 6: Wire types into the core contract

**Files:**
- Modify: `src/core/types.ts`
- Test: covered by Task 7 (engine integration).

- [ ] **Step 1: Add fields to `PrismConfig` and `AuditReport`**

In `src/core/types.ts`, add to the `PrismConfig` interface:
```ts
  /** Run the AI triage layer after static analysis. */
  ai?: boolean;
  /** Override the triage model (default claude-opus-4-8). */
  aiModel?: string;
```

Add an import-free reference and a field on `AuditReport`. Near the top of the file (after existing imports, or inline as a type-only import to avoid a cycle), add:
```ts
import type { TriageResult } from '../ai/types.js';
```
Then add to the `AuditReport` interface:
```ts
  /** AI triage verdicts (present only when run with --ai). */
  aiTriage?: TriageResult;
```

> Note: `src/ai/types.ts` imports `Finding`/`AnalysisCategory` from `core/types.ts`, and `core/types.ts` now imports `TriageResult` from `ai/types.ts`. This is a **type-only** cycle (`import type` on both sides) — TypeScript erases type-only imports, so there is no runtime cycle. Keep both as `import type`.

- [ ] **Step 2: Type-check**

Run: `npx tsc --noEmit`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/core/types.ts
git commit -m "feat(ai): add ai config + aiTriage report fields"
```

---

## Task 7: Engine integration

**Files:**
- Modify: `src/core/engine.ts`
- Test: `tests/core/engine.test.ts` (append)

First read `src/core/engine.ts` to see how `runAudit` builds the report, what `readFile` it uses for analyzers, and how it returns. The triage must run AFTER the static report is assembled, reusing the same file reader.

- [ ] **Step 1: Write the failing test**

Append to `tests/core/engine.test.ts` (add imports as needed at the top — `runAudit`, `LLMClient`/`Verdict` types):

```ts
import type { LLMClient, Verdict } from '../../src/ai/types.js';
import { findingKey } from '../../src/ai/types.js';

describe('runAudit — AI triage integration', () => {
  const FIXTURE = resolve(__dirname, '../fixtures/sample-project');

  it('attaches aiTriage when an LLM client is injected, without mutating findings or score', async () => {
    const fake: LLMClient = {
      async triage(unit) {
        return unit.findings.map((f): Verdict => ({
          findingKey: findingKey(f),
          classification: 'false-positive',
          confidence: 0.7,
          reasoning: 'fixture',
        }));
      },
    };
    const baseline = await runAudit({ targetPath: FIXTURE, output: 'cli' });
    const withAi = await runAudit({ targetPath: FIXTURE, output: 'cli', ai: true }, undefined, fake);

    expect(withAi.aiTriage).toBeDefined();
    expect(withAi.aiTriage!.verdicts.length).toBe(withAi.findings.length);
    // score and findings unchanged vs the baseline run
    expect(withAi.overallScore).toBe(baseline.overallScore);
    expect(withAi.findings.length).toBe(baseline.findings.length);
  });

  it('does not run triage when ai is not set (no client needed)', async () => {
    const report = await runAudit({ targetPath: FIXTURE, output: 'cli' });
    expect(report.aiTriage).toBeUndefined();
  });
});
```

> `resolve` and `runAudit` are already imported at the top of `engine.test.ts` (verify; add `import { resolve } from 'node:path'` and the `runAudit` import if missing).

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/core/engine.test.ts`
Expected: FAIL — `runAudit` does not accept a third arg / `aiTriage` undefined.

- [ ] **Step 3: Write minimal implementation**

In `src/core/engine.ts`:

(a) Add imports at the top:
```ts
import type { LLMClient } from '../ai/types.js';
import { runTriage } from '../ai/triage.js';
```

(b) Change the `runAudit` signature to accept an optional injected client (for tests) — the real client is constructed lazily only when `config.ai` and no client was injected:
```ts
export async function runAudit(
  config: PrismConfig,
  onProgress?: (message: string) => void,
  injectedClient?: LLMClient,
): Promise<AuditReport> {
```

(c) Find where the function builds the final `report` object and `return`s it. Immediately BEFORE the `return report;`, insert the triage step. You need the same per-file reader the analyzers use — locate the `readFile`/file-reader variable in `runAudit` (e.g. a function that reads a path relative to the project root). Use it here:
```ts
    if (config.ai) {
      try {
        let client = injectedClient;
        if (!client) {
          const { AnthropicLLMClient } = await import('../ai/client.js');
          client = new AnthropicLLMClient(config.aiModel);
        }
        onProgress?.('Running AI triage...');
        report.aiTriage = await runTriage(report, readFile, client);
        onProgress?.('AI triage complete');
      } catch (err) {
        // Triage failure must not destroy the static report.
        onProgress?.(`AI triage failed: ${err instanceof Error ? err.message : 'unknown error'}`);
      }
    }
```
Replace `readFile` with the actual reader identifier used in `runAudit`. If the report is built as `const report = {...}` followed by `return report`, set `report.aiTriage` as shown. If `report` is returned inline (`return {...}`), first hoist it to a `const report = {...}` so it can be mutated, then add the block, then `return report`.

> The dynamic `import('../ai/client.js')` keeps the SDK out of the module graph for non-`--ai` runs and out of the test path (tests inject `injectedClient`, so the SDK is never imported during `npx vitest run`).

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/core/engine.test.ts`
Expected: PASS (existing engine tests + 2 new).

- [ ] **Step 5: Checkpoint + commit**

Run: `npx vitest run` && `npx tsc --noEmit`
```bash
git add src/core/engine.ts tests/core/engine.test.ts
git commit -m "feat(ai): run triage in the engine when --ai is set"
```

---

## Task 8: CLI flags

**Files:**
- Modify: `src/cli/index.ts`

- [ ] **Step 1: Add the options**

In `src/cli/index.ts`, on the `analyze` command (after the existing `.option(...)` calls, before `.action(...)`), add:
```ts
  .option('--ai', 'Run the AI triage layer (requires ANTHROPIC_API_KEY)', false)
  .option('--ai-model <id>', 'Override the AI triage model (default claude-opus-4-8)')
```

In the `.action(...)` body, where `config` is built, add:
```ts
      ai: Boolean(options.ai),
      aiModel: options.aiModel ? String(options.aiModel) : undefined,
```
(Match the existing `config` object's style — it already maps options like `output`, `verbose`.)

- [ ] **Step 2: Type-check + manual smoke (no key needed)**

Run: `npx tsc --noEmit`
Run: `npx tsx src/cli/index.ts analyze . 2>&1 | head -5` (no `--ai` — must work exactly as before)
Run: `npx tsx src/cli/index.ts analyze . --ai 2>&1 | grep -i "ANTHROPIC_API_KEY"` — expected: the clear "requires an ANTHROPIC_API_KEY" message appears (since no key is set in this env), AND the static report is NOT destroyed (the engine catches the error). Confirm exit doesn't crash with a stack trace.

- [ ] **Step 3: Commit**

```bash
git add src/cli/index.ts
git commit -m "feat(ai): add --ai and --ai-model CLI flags"
```

---

## Task 9: CLI reporter — render verdicts

**Files:**
- Modify: `src/reporters/cli.ts`
- Test: none required (presentation); a manual visual check via the fake-key run.

First read `src/reporters/cli.ts` to see how findings are rendered (the loop over findings, chalk usage).

- [ ] **Step 1: Implement verdict rendering**

In `src/reporters/cli.ts`:

(a) At the top, after existing imports, add a small helper map (use the existing `chalk` import):
```ts
import type { Verdict } from '../ai/types.js';

function verdictLabel(v: Verdict): string {
  if (v.classification === 'real') return chalk.green('✓ real');
  if (v.classification === 'false-positive') return chalk.dim('✗ likely FP');
  return chalk.yellow('? uncertain');
}
```

(b) Build a lookup when `report.aiTriage` exists, near where the report is first used:
```ts
  const verdictByKey = new Map<string, Verdict>();
  if (report.aiTriage) {
    for (const v of report.aiTriage.verdicts) verdictByKey.set(v.findingKey, v);
  }
```
(Import `findingKey` from `../ai/types.js` to compute the key per finding.)

(c) In the per-finding render loop, after the finding's existing lines, if a verdict exists, print it:
```ts
    const verdict = verdictByKey.get(findingKey(finding));
    if (verdict) {
      console.log(`      ${verdictLabel(verdict)} ${chalk.dim(`(${Math.round(verdict.confidence * 100)}%)`)} — ${verdict.reasoning}`);
    }
```
(Match the indentation/format of the surrounding finding output.)

(d) After the findings, if `report.aiTriage` exists, print a summary line:
```ts
  if (report.aiTriage) {
    const s = report.aiTriage.summary;
    console.log('');
    console.log(`  ${chalk.bold('AI triage:')} ${chalk.green(`${s.real} real`)} · ${chalk.dim(`${s.falsePositive} false positives`)} · ${chalk.yellow(`${s.uncertain} uncertain`)}`);
  }
```

- [ ] **Step 2: Type-check + verify suite**

Run: `npx tsc --noEmit` && `npx vitest run`
Expected: clean + all green (reporter has no unit tests, but must compile).

- [ ] **Step 3: Commit**

```bash
git add src/reporters/cli.ts
git commit -m "feat(ai): render triage verdicts in the CLI report"
```

---

## Task 10: Real-world verification + version bump + log

**Files:**
- Modify: `package.json`, `src/cli/index.ts` (version `0.9.1` → `1.0.0`)
- Modify: `SESSION_LOG.md`, `README.md`

> **This task needs a real `ANTHROPIC_API_KEY` and spends tokens.** The controller cannot run it — hand the commands to the user. Everything before this task is fully green offline.

- [ ] **Step 1: User runs the real triage**

Provide these commands for the user to run (they set their own key):
```bash
export ANTHROPIC_API_KEY=sk-ant-...   # user's key
cd /opt/prism
npx tsx src/cli/index.ts analyze /opt/orion_new --ai -o json -f /tmp/orion-ai.json
node -e "const r=require('/tmp/orion-ai.json'); console.log(r.aiTriage.summary); r.aiTriage.verdicts.slice(0,15).forEach(v=>console.log(v.classification.padEnd(15), v.findingKey, '—', v.reasoning))"
npx tsx src/cli/index.ts analyze /opt/tecofri-n8n --ai 2>&1 | tail -30
```

- [ ] **Step 2: Verify verdict quality (with the user)**

Confirm: known false positives (any fixture-context leaks, mount-path style findings) are classified `false-positive`; a genuinely real finding (e.g. a real committed secret if present) is `real`; reasoning is sane. Record the token cost from the run. If verdicts are systematically wrong, return to the prompt (Task 3) — do not ship a triage that contradicts reality.

- [ ] **Step 3: Bump version to 1.0.0**

Edit `package.json`: `"version": "0.9.1"` → `"version": "1.0.0"`.
Edit `src/cli/index.ts`: `.version('0.9.1')` → `.version('1.0.0')`.
Run: `npx tsx src/cli/index.ts --version` → Expected: `1.0.0`.

- [ ] **Step 4: Update README + SESSION_LOG**

- README: add a "Fase 2 — AI triage" section documenting `--ai` / `--ai-model`, the `ANTHROPIC_API_KEY` requirement, and that it annotates (does not re-score).
- SESSION_LOG: add a `### v1.0.0 — Fase 2: capa de triage con IA` entry following the format: what was built (the `src/ai/` module, the seam, structured outputs, prompt caching), the design decisions (triage-only, opt-in, no re-scoring), real-world results from Step 1 (verdict accuracy + token cost), final test count. Update the header version line and test count. Mark Fase 2 as begun; note v1.1+ candidates (executive summary, remediation, re-scoring, separate `triage` command).

- [ ] **Step 5: Final checkpoint + commit**

Run: `npx vitest run` && `npx tsc --noEmit` && `npm run lint`
```bash
git add -A
git commit -m "release: v1.0.0 — Fase 2 AI triage layer"
```

---

## Self-Review notes

- **Spec coverage:** `--ai` flag (Task 8) ✓ · triage verdict real/FP/uncertain + confidence + reasoning (Tasks 2–4) ✓ · reads file code (Task 4 reader + Task 3 content block) ✓ · model/adaptive/effort/Zod/prompt-caching (Task 5) ✓ · per-file grouping + project-level group (Task 4) ✓ · findingKey alignment + synthesized uncertain + drop unknown (Task 4) ✓ · `aiTriage` on report, no mutation/no re-score (Tasks 6,7) ✓ · engine runs triage, survives failure (Task 7) ✓ · CLI render + summary (Task 9) ✓ · no-API-key clear error (Task 5 ctor) ✓ · FakeLLMClient unit tests, no network (Tasks 4,7) ✓ · real-world verification handed to user (Task 10) ✓.
- **Type consistency:** `LLMClient.triage(unit, ctx)` signature identical across types/triage/client/tests. `Verdict` fields (`findingKey`, `classification`, `confidence`, `reasoning`) identical in types, Zod schema, prompt, reporter. `findingKey` formula `${id}|${file??''}|${line??''}` identical in types (Task 2), used in triage (Task 4), prompt (Task 3), reporter (Task 9). `runTriage(report, readFile, client)` identical in triage (Task 4) and engine (Task 7). `runAudit(config, onProgress?, injectedClient?)` defined Task 7, used in Task 7 tests.
- **Placeholder scan:** no TBD/TODO; every code step has complete code. The two SDK-shape risks (Task 5 `messages.parse`/`zodOutputFormat` path; Task 7 reader identifier) are called out explicitly with "stop and report" guidance rather than guessed silently.
- **Risk flags for the executor:** Task 5 SDK field names come from the claude-api reference — if the installed SDK version's types differ, reconcile against the actual SDK, don't force the names. Task 7 requires reading the real `readFile` identifier from `engine.ts` before editing.

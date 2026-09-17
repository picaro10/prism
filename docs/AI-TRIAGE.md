# AI triage

The optional adversarial LLM layer: how it judges, what it reads, what it remembers, and how it is measured. Static analysis needs none of this.

### `--ai` — AI triage (Fase 2)

```
# Static analysis + LLM triage of every finding
prism analyze <path> --ai

# Override the triage model (default: claude-opus-4-8)
prism analyze <path> --ai --ai-model claude-sonnet-4-6

# Exercise the full AI pipeline with canned responses — no network, no API key
prism analyze <path> --dry-run
```

`--dry-run` runs the whole triage → remediation → summary pipeline with canned verdicts (each
clearly marked `[dry-run]`), so you can see the report shape or test the flow at **zero token
cost** and without a key. It also works on the `triage` command.

The static layer flags patterns; the AI layer **judges them in context**. With `--ai`, PRISM
sends each finding (and the surrounding file's code) to Claude, which classifies it as
`✓ real`, `✗ likely FP`, or `? uncertain`, with a confidence and a one-line reason — the same
judgment that distinguishes a Docker mount path from a hardcoded secret, or a test fixture
from production code.

- **Two providers.** Default is the Anthropic API (`ANTHROPIC_API_KEY`), with full native
  features (structured outputs, adaptive thinking, prompt caching). You can also use
  **OpenRouter** (`OPENROUTER_API_KEY`), which is OpenAI-compatible — set `--ai-provider openrouter`
  (auto-detected when only `OPENROUTER_API_KEY` is present). The OpenRouter default model is
  `openai/gpt-4.1-mini` (cheap, for development); override with `--ai-model <slug>` (e.g.
  `--ai-model anthropic/claude-opus-4.8`). OpenRouter uses JSON mode instead of Anthropic-native
  structured outputs.
- **Opt-in.** Without `--ai`, PRISM needs no key and **no source code ever leaves the machine**.
  Three static checks do use the network when available — `npm audit` (registry advisory DB),
  the OSV.dev lookup, and the npm update check — sending only package names/versions, never code;
  offline, each reports an explicit UNKNOWN finding instead of a silent clean. `--ai` fails fast
  if the selected provider's key is missing.
- **Privacy note.** `--ai` sends snippets of the analyzed project's source (including the lines
  that triggered each finding — a flagged secret's line among them) to the selected external
  provider (Anthropic or OpenRouter). Do not use `--ai` on code you cannot share with a third
  party. The static-only mode never transmits anything.
- **It annotates, it does not re-score.** The static score is unchanged; the AI overlay informs
  the human. If the AI call fails, the static report is still produced.
- **False-positives are double-checked.** Any verdict the first pass calls `false-positive` gets
  an adversarial re-check that must confirm it with concrete code evidence — otherwise the
  finding stays `real`/`uncertain`. This catches lenient or hallucinated FPs (disable with
  `--no-ai-verify`). Calls run concurrently (`--ai-concurrency <n>`, default 5).
- **Verdict cache: unchanged code is never judged twice.** Every final verdict and fix is
  stored under a key made of the prompts, the judge (provider, model, panel), the finding and a
  hash of the exact content the model read. The next run — the next CI push, `prism triage` on
  a saved report, or the same run after a Ctrl-C — reuses what it already knows and only pays
  for what changed (`AI triage: … · 12 from cache`, and cached verdicts are tagged `[cached]`).
  Editing a prompt, switching models or touching the file all miss on purpose; verdicts
  synthesized from a failed call are never stored. The cache lives in the **operator's** cache
  directory (`PRISM_CACHE_DIR`, else `$XDG_CACHE_HOME/prism`, `%LOCALAPPDATA%\prism\cache`, or
  `~/.cache/prism`), never inside the audited project, and only for local targets — a clone or
  zip is a throwaway directory. `--no-ai-cache` (or `ai.cache: false` in the config) judges
  everything again. Cache `~/.cache/prism` in CI to keep the saving across runs.
- **Context tiers: the model reads code only when code can change the verdict.** Every rule
  declares how much context its triage needs (`CONTEXT_TIER` in `src/core/rule-metadata.ts`).
  Line-pattern rules (secrets, Docker, workflows, test hygiene) send the flagged file.
  Project-fact rules — god files, import cycles, dependency advisories, missing tests, mixed
  conventions — are judged from the finding itself and batched into content-less calls: a
  1,500-line file is big whether or not the model reads it. Cross-file rules (agentic,
  taint) are `neighborhood` tier: see the next point. Unknown rules default to the safe,
  expensive tier.
- **Cross-file evidence, chosen deterministically.** The thing that makes an agentic or taint
  finding benign often lives in another module — the executor that gates every destructive
  tool, the validator whose body rejects shell metacharacters, the assertion helper that calls
  `expect()`. For `neighborhood`-tier findings PRISM walks the import graph (no model in the
  loop) and hands the judge the related files: modules the flagged file imports whose imported
  names are used near the flagged line, and modules importing the flagged file that mention a
  token from it (the tool name, the exported function). Bounded (4 files, 12 KB each, 30 KB
  total), TS/JS only (tsconfig aliases resolved), and silent when nothing qualifies. On the
  AI-triage benchmark this moved cross-file false positives caught from 1/3 to 3/3 with no
  real issue excused. A cached verdict misses when a related file changes, not only the
  flagged one.
- **N-model vote.** A single model makes confident judgment errors (and re-checking with the
  same model shares its blind spots). `--ai-vote model-a,model-b,model-c` makes every
  false-positive verdict face a panel: the FP survives only if the panel is **unanimous** —
  any skeptic's dissent blocks the excusal (the N-voter generalization of the single
  adversarial re-check). A blocked FP becomes `real` (strict majority) or `uncertain`
  (anything less — surfaced for the human). The tally is appended to the reasoning
  (`[panel: 1 real · 2 fp · 0 uncertain]`). A voter that errors abstains as `uncertain`.
  Only false-positive verdicts pay the panel cost.
- **Remediation guide.** Every finding the triage confirms as `real` gets a concrete fix
  proposal — what to change, where, with a short snippet when it helps — plus an honest effort
  estimate (`low`/`medium`/`high`). Rendered inline under each finding (`🔧 fix`) and included
  in JSON as `aiRemediation`. Only confirmed-real findings pay the extra call; disable with
  `--no-ai-remediate`.
- **Executive summary.** After triage, one more call writes a short prose assessment of the
  project (overall health, what's urgent), focused on the confirmed-real findings. Rendered at
  the top of the report (`🧠 AI Assessment`) and included in JSON as `aiSummary`. Disable with
  `--no-ai-summary`.
- Verdicts appear inline under each finding, plus a summary line
  (`AI triage: N real · M false positives · K uncertain`), and are included in JSON output
  under `aiTriage`.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
prism analyze . --ai
```

### `triage` — re-run AI triage on a saved report

```
prism analyze <path> -o json -f report.json     # scan once
prism triage report.json                          # re-triage cheaply, as often as you like
prism triage report.json --ai-model openai/gpt-4o-mini   # compare models without re-scanning
```

Decouples the (cheap, fast) static scan from the (paid) LLM passes. Loads a saved JSON report,
re-reads the project's files from its recorded `projectPath`, and runs triage + remediation +
summary again — without re-scanning. Ideal for iterating on the AI layer or comparing models on
the same report. Takes the same `--ai-*` flags as `analyze --ai`; requires the provider's API key.

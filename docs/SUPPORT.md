# Support matrix and roadmap

## Language & platform support

PRISM inspects some ecosystems deeply and others only at the metadata level. The score reflects
**what PRISM understands** — a high score on an unsupported stack means "nothing wrong in what
was inspected", not "deep audit passed":

| Area | Support |
|---|---|
| TypeScript / JavaScript | **Full** — all ten analyzers, import graph, dead-file and cycle detection, taint analysis (with semgrep) |
| Python | Partial — dependencies (`requirements.txt` pinning, OSV.dev advisories), basic structure, decorative/skipped tests, taint analysis (with semgrep), and the agentic checks in their Python shapes: `os.system`/`subprocess … shell=True` with f-strings (`AGT-001`), env secrets and external content in f-string/`.format()` prompts (`AGT-002`/`AGT-004`), destructive tools without `requires_confirmation` (`AGT-003`), `except` handlers that fail open (`AGT-006`). No import graph or dead-file analysis for Python yet |
| Rust / Go / PHP / Ruby | Dependencies — known-vulnerability check of `Cargo.lock`, `go.mod`, `composer.lock`, `Gemfile.lock` via OSV.dev |
| Docker / Compose | Full — Dockerfile and docker-compose checks |
| GitHub Actions | Full — workflow risk analysis cross-checked against the repo (other CI systems: not yet) |
| Secrets / entropy | Language-agnostic — any text file |
| Monorepos | Partial — analyzed as one tree; per-package scoring not yet separated |
| Dynamic imports | Limited — `import()` with non-literal arguments is not resolved in the graph |
| Generated / vendored code | Excluded by the file-context classifier |
| Other languages (Rust, Java, Go…) | Metadata and structure only — no language-aware analysis |

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| **Fase 1** — Static analysis CLI | **Done** | 7 analyzers, weighted scoring, JSON/CLI output, CI exit codes |
| **Fase 2** — LLM triage | **Done** | `--ai`: triage + adversarial re-check + N-model vote, remediation guide, executive summary, standalone `triage` |
| **Fase 3** — Reports & outputs | **Done** | Self-contained HTML, JUnit XML, SARIF 2.1.0 |
| **Fase 4** — Dashboard + multi-input | **Done** | Local dashboard, git URL input, `.zip` input |
| **Fase 5** — Agent-ready | **Done (v1.0.0)** | Exit-code contract, `diff`, `finding get`, `agent install`, quality/new-code gates |
| **Fase 6** — Persistent config | **Done** | `prism.config.json` + `prism init` wizard, justified suppressions with reasons and expiry |
| **Fase 7** — Quality flywheel | **Done** | Public rule catalog (sync-tested), reproducible FP benchmark in CI, agentic checks AGT-003..006 |
| **Fase 8** — Workflow Intelligence | **Done (v1.2.0)** | GitHub Actions analyzer (`WFL-*`): pwn requests, script injection, dead triggers, fail-open gates — cross-checked against the real repo |
| **Fase 9** — Security depth | **Done (v1.4.0)** | Curated semgrep taint pack (`SG-*`: SQLi/XSS/SSRF/traversal/deserialization), multi-ecosystem SCA via OSV.dev (`DEP-OSV-*`), CWE/OWASP Top 10 mapping with SARIF tags |
| **Fase 10** — AI layer: cheap, measured, with sight | **Done (v1.6.0)** | Context tiers per rule, verdict cache (resume for free), import-graph neighborhood for cross-file evidence, AI-triage benchmark that measures the judge |
| **Next** | Planned | Python parity for the agentic checks (`subprocess`/f-string shell, f-string prompts, `except` fail-open); risk chains (findings that connect into one attack path, verified in the graph); more CI systems (GitLab CI); finding lifecycle / quality profiles |

---

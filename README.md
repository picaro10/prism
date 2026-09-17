# PRISM

[![CI](https://github.com/picaro10/prism/actions/workflows/ci.yml/badge.svg)](https://github.com/picaro10/prism/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@latenciatech/prism)](https://www.npmjs.com/package/@latenciatech/prism)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%E2%89%A522-brightgreen)

**The auditor for AI-written code, its agents, and the pipelines that ship it.**
*Deterministic rules that ship with their own false-positive traps, and an AI judge that reads the code.*

Code written by agents gets deployed by pipelines nobody reads. PRISM scans a codebase for the
risks that era actually produces — leaked secrets, shell injection inside agent tools, prompt
injection, destructive tools with no confirmation, CI workflows a fork can hijack, containers
with the Docker socket mounted — and then, optionally, has a model read every flagged line
*and the files it imports* before calling it real. It only asserts what it can show you.

```sh
npm install -g @latenciatech/prism
prism analyze .            # static, offline, no key
prism analyze . --ai       # + adversarial AI triage (ANTHROPIC_API_KEY or OPENROUTER_API_KEY)
```

## What it looks like

A four-file demo: a Stripe key in source, an agent tool that shells out, a destructive tool
with no gate, a privileged container. Real output, real model:

```
  Overall Score
  █████████████████████████████████░░░░░░░  8.2/10

  security       █████████████████░░░  8.5/10 (2 findings)
  docker         ██████████████░░░░░░  7/10 (4 findings)
  agentic        █████████████████░░░  8.5/10 (2 findings)

  🔴 CRITICAL (2)
    SEC-STRIPE-SK Stripe Secret Key detected → src/pay.ts:1
      ✓ real (92%) — A live-prefixed Stripe secret key (sk_live_) is hardcoded and exported from source.
    DOC-020 Container running in privileged mode → docker-compose.yml:4
      ✓ real (97%) — privileged: true is explicitly set, granting the container full host access.
  🟠 HIGH (1)
    AGT-001 Shell command built with interpolation (agent command-injection risk) → src/tools.ts:9
      ✓ real (97%) — execSync interpolates cmd directly into a shell string with no escaping or validation.
      💡 Use execFile/execFileSync with an argument array (no shell), or strictly validate the argument.
  🟡 MEDIUM (2)
    AGT-003 Destructive agent tool with no confirmation gate → src/tools.ts:4
      ✓ real (85%) — The delete_order tool performs a destructive action and its definition has no
        confirmation, approval, or dangerous-operation marker, so an agent could invoke it autonomously.
  ℹ️  INFO (1)
    SEC-SEMGREP-MISSING Semgrep not installed — taint analysis skipped

  AI triage: 8 real · 0 false positives · 0 uncertain
```

Every finding has a stable id, a file and line, a fix, and — with `--ai` — a verdict that cites the
code. JSON, HTML, SARIF and JUnit outputs, exit codes for CI, and a `diff` command for regression
gates are all in [docs/USAGE.md](docs/USAGE.md).

## How it earns trust

- **Every rule ships with the false positives it once produced.** A [benchmark](docs/USAGE.md#false-positive-benchmark)
  of 28 cases — 14 planted issues, 14 traps that were real mistakes on real projects — fails CI if
  a rule regresses in either direction.
- **The AI judge is measured, not trusted.** A [second benchmark](docs/USAGE.md#ai-triage-benchmark)
  (17 cases: genuine issues it must not excuse, false positives it should catch, cross-file ones
  whose evidence lives in another module) hard-fails only when a real issue is excused. Last live
  run: 17/17. Seventeen is a signal, not a statistic — the corpus grows with every field mistake.
- **Unknown is never clean.** No semgrep, no network, an unreadable directory, a capped scan: each
  shows up as a finding or a summary note, never as a silent pass. Categories with nothing to
  analyze are N/A, not 10/10.
- **It runs on itself**, on every push, on Linux, macOS and Windows, and a [SECURITY.md](SECURITY.md)
  says how to report the day it gets something wrong.

## What it checks

| Category | Weight | In one line |
|---|---|---|
| **Security** | 2.0× | Secrets, committed `.env`, entropy; taint dataflow (SQLi/XSS/SSRF/traversal/deserialization) via a curated [semgrep](https://semgrep.dev) pack, when installed |
| **Agentic** | 1.5× | Shell injection in tools, secrets and external content in prompts, destructive tools without confirmation, public MCP binds, fail-open gates — JS/TS and Python |
| **Workflow** | 1.0× | GitHub Actions: pwn requests, script injection, unpinned actions, permissions, triggers on branches that don't exist, fail-open gates |
| **Docker** | 1.0× | Root, `:latest`, no healthcheck, privileged, hardcoded credentials, ports on all interfaces per service, the Docker socket mounted |
| **Dependencies** | 1.5× | Lockfile, wildcards, `npm audit`, OSV.dev for Python/Rust/Go/PHP/Ruby lockfiles |
| **Tests** | 1.5× | Decorative tests, disconnected tests, skipped accumulation, snapshot overuse, ratio |
| **Structure** | 1.0× | God files, import cycles, dead files, layout hygiene |
| **Consistency** | 0.8× | Mixed naming, mixed natural languages, mixed indentation |

Security rules map to **CWE / OWASP Top 10** and SARIF feeds GitHub Code Scanning. The full
catalog — every id, severity and its known traps — is in [docs/rules/](docs/rules/README.md), and
a test fails CI if a rule ships undocumented.

## What it is, and is not

**It is** about a hundred curated, deterministic checks plus an optional adversarial LLM layer
that reads the flagged code and the modules it imports. **It is not** a replacement for semgrep,
CodeQL or Snyk: deep dataflow is a wrapped semgrep pack, and the depth is theirs. PRISM's own
ground is the agentic and workflow rules, the cross-checks against the real repository, the
integrated score, and the judge.

**Status:** 1.x, one maintainer, field-tested on real agent codebases and CI pipelines. The
report schema and the config file can still change between minor versions — the
[CHANGELOG](CHANGELOG.md) lists every change. Python is partial and most other languages are
metadata only; read the [support matrix](docs/SUPPORT.md) before trusting a score on a stack
PRISM only partially understands.

## Documentation

- [Usage](docs/USAGE.md) — every command and flag, `prism.config.json`, suppressions, scoring, development
- [AI triage](docs/AI-TRIAGE.md) — the adversarial judge, context tiers, the verdict cache, cross-file evidence
- [Rule catalog](docs/rules/README.md) — all rules with severities and false-positive notes
- [Support matrix & roadmap](docs/SUPPORT.md) — what is inspected deeply, what only at the metadata level
- [Architecture](docs/ARCHITECTURE.md) — the pipeline, the trust boundaries, the scoring doctrine
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

[MIT](LICENSE) — © 2026 LatenciaTech (Spain).

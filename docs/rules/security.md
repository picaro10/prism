# Security rules (`SEC-*`) — weight 2.0×

Hardcoded credentials and committed secrets. Findings in files the context classifier marks as
fixture/template/documentation/generated/vendor are skipped entirely; findings in test files are
stepped down one severity.

## File-level rules

| ID | Severity | What it detects |
|---|---|---|
| `SEC-ENV-COMMITTED` | critical | A real `.env` file tracked in the project (not an `.env.example`). |
| `SEC-GITIGNORE-ENV` | high | `.env` exists but is not covered by `.gitignore`. |
| `SEC-ENTROPY` | high/medium¹ | A high-Shannon-entropy string that reads like a real secret. |

¹ `SEC-ENTROPY` severity adjusts with context (test files step down).

## Pattern rules

| ID | Severity | What it detects |
|---|---|---|
| `SEC-AWS-KEY` | critical | AWS Access Key ID (`AKIA…` prefix). |
| `SEC-GH-PAT` | critical | GitHub personal access token (`ghp_…`). |
| `SEC-GH-OAUTH` | critical | GitHub OAuth token (`gho_…`). |
| `SEC-API-KEY` | high | Generic hardcoded API key assignment. |
| `SEC-PRIVATE-KEY` | critical | Inline private key material (`-----BEGIN … PRIVATE KEY`). |
| `SEC-DB-URL` | critical | Database connection string with embedded credentials. |
| `SEC-JWT` | high | Hardcoded JWT. |
| `SEC-TELEGRAM` | critical | Telegram bot token. |
| `SEC-STRIPE-SK` | critical | Stripe secret key (`sk_live_…`). |
| `SEC-STRIPE-PK` | medium | Stripe live publishable key (`pk_live_…`). |
| `SEC-OPENAI` | critical | OpenAI API key (`sk-…`). |
| `SEC-ANTHROPIC` | critical | Anthropic API key (`sk-ant-…`). |
| `SEC-PASSWORD` | high | Hardcoded password assignment. |
| `SEC-ENV-VALUE` | medium | A value that looks like it belongs in `.env`, hardcoded in source. |

## False-positive notes (field-tested)

These distinctions came from real audits, not theory:

- **`SEC-DB-URL` and placeholder credentials.** Connection strings whose *password* is a
  placeholder (`user:password@`, `root:root@`) in generators/templates are not flagged as
  critical — but a real-looking password (`aether:S3cr3t!@`) still fires.
- **`SEC-ENV-VALUE` and readable identifiers.** A lowercase snake/kebab value like
  `'orion_dashboard_token'` is a storage *key name*, not a secret; low-entropy readable values
  don't fire. A mixed-case random token still does.
- **`SEC-AWS-SECRET` was removed entirely** (any 40-char base64 matched too much). Only the
  `AKIA`-prefixed key ID rule remains.
- **Docker secret mount paths** (`/run/secrets/…`) in compose `environment` blocks are not
  credentials.

## Suppression

Prefer fixing (rotate the credential, move it to the environment). Suppress only for provably
fake material the classifier can't infer, and say so:

```json
{ "rule": "SEC-JWT", "file": "tests/fixtures/**", "reason": "Fake token used to test the detector" }
```

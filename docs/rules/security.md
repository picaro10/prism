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

## Taint rules (`SG-*`, via semgrep)

Real dataflow analysis — user input traced to a dangerous sink — powered by [semgrep](https://semgrep.dev)
running PRISM's curated rule pack (shipped with PRISM, no registry fetch, no metrics). **Optional:**
when semgrep is not on PATH the category degrades to an info notice (`SEC-SEMGREP-MISSING`) with no
penalty — taint depth is an upgrade, never a requirement. Install with `pipx install semgrep`.

Each rule carries CWE/OWASP metadata, and the AI triage layer (`--ai`) adversarially re-checks these
findings like any others — that pass is what kills the false positives taint analysis is famous for.

| ID | Severity | Lang | CWE | What it detects |
|---|---|---|---|---|
| `SG-SQLI-TAINTED-QUERY` | critical | JS/TS | CWE-89 | Request data string-built into `db.query`/`execute`/`raw`. |
| `SG-XSS-TAINTED-RESPONSE` | high | JS/TS | CWE-79 | Request data written into `res.send`/`res.write` unsanitized. |
| `SG-DOM-XSS-INNERHTML` | high | JS/TS | CWE-79 | URL-controlled data assigned to `innerHTML`/`outerHTML`/`document.write`. |
| `SG-SSRF-TAINTED-URL` | high | JS/TS | CWE-918 | Request data used as `fetch`/`axios`/`http.get` URL. |
| `SG-PATH-TRAVERSAL-FS` | critical | JS/TS | CWE-22 | Request data in a filesystem path (`readFile`, `createReadStream`, …). |
| `SG-COMMAND-INJECTION-EXEC` | critical | JS/TS | CWE-78 | Request data in `exec`/`execSync` shell commands. |
| `SG-CODE-INJECTION-EVAL` | critical | JS/TS | CWE-95 | Request data reaching `eval`/`new Function`/`vm.runInNewContext`. |
| `SG-SQLI-TAINTED-EXECUTE-PY` | critical | Python | CWE-89 | Flask/Django request data formatted into `cursor.execute`. |
| `SG-COMMAND-INJECTION-PY` | critical | Python | CWE-78 | Request data in `os.system`/`subprocess … shell=True`. |
| `SG-SSRF-TAINTED-URL-PY` | high | Python | CWE-918 | Request data used as `requests`/`urlopen` URL. |
| `SG-PATH-TRAVERSAL-OPEN-PY` | critical | Python | CWE-22 | Request data flowing into `open()` (sanitized by `secure_filename`/`basename`). |
| `SG-PICKLE-LOAD-UNTRUSTED-PY` | critical | Python | CWE-502 | Request data reaching `pickle`/`marshal` deserialization. |
| `SG-YAML-UNSAFE-LOAD-PY` | high | Python | CWE-502 | `yaml.load` without `SafeLoader`. |

Notices (no dataflow finding, they report the engine's own state): `SEC-SEMGREP-MISSING` (info, not
installed), `SEC-SEMGREP-ERROR` (low, installed but the scan failed — unknown ≠ clean),
`SEC-SEMGREP-TRUNCATED` (info, >200 findings capped).

Context rules apply as everywhere else: fixture/template/vendor/generated findings are skipped,
test-file findings step down one severity.

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

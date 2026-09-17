# CWE / OWASP mapping

Every **security-relevant** PRISM rule maps to a [CWE](https://cwe.mitre.org) identifier and an
[OWASP Top 10 (2021)](https://owasp.org/Top10/) category. The mapping lives in
`src/core/rule-metadata.ts` and feeds the SARIF output: rules gain
`external/cwe/…` and `external/owasp/…` tags plus a `security-severity`
property, so GitHub Code Scanning ranks and groups PRISM alerts like any other
security tool's.

Quality rules (structure, consistency, test hygiene, CI ergonomics such as
missing timeouts or caching) deliberately have **no** CWE — stamping one on a
naming-convention rule would be metadata theater. A test keeps this table, the
metadata module, and the semgrep rule pack in sync.

| Rule | CWE | OWASP Top 10 (2021) |
|---|---|---|
| `SEC-ENV-COMMITTED` | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | A05:2021 — Security Misconfiguration |
| `SEC-GITIGNORE-ENV` | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | A05:2021 — Security Misconfiguration |
| `SEC-ENTROPY` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-AWS-KEY` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-GH-PAT` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-GH-OAUTH` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-API-KEY` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-PRIVATE-KEY` | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | A02:2021 — Cryptographic Failures |
| `SEC-DB-URL` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-JWT` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-TELEGRAM` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-STRIPE-SK` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-STRIPE-PK` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-OPENAI` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-ANTHROPIC` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-PASSWORD` | [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | A07:2021 — Identification and Authentication Failures |
| `SEC-ENV-VALUE` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `SG-SQLI-TAINTED-QUERY` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | A03:2021 — Injection |
| `SG-XSS-TAINTED-RESPONSE` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | A03:2021 — Injection |
| `SG-DOM-XSS-INNERHTML` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | A03:2021 — Injection |
| `SG-SSRF-TAINTED-URL` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | A10:2021 — Server-Side Request Forgery |
| `SG-PATH-TRAVERSAL-FS` | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | A01:2021 — Broken Access Control |
| `SG-COMMAND-INJECTION-EXEC` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | A03:2021 — Injection |
| `SG-CODE-INJECTION-EVAL` | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | A03:2021 — Injection |
| `SG-SQLI-TAINTED-EXECUTE-PY` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | A03:2021 — Injection |
| `SG-COMMAND-INJECTION-PY` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | A03:2021 — Injection |
| `SG-SSRF-TAINTED-URL-PY` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | A10:2021 — Server-Side Request Forgery |
| `SG-PATH-TRAVERSAL-OPEN-PY` | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | A01:2021 — Broken Access Control |
| `SG-PICKLE-LOAD-UNTRUSTED-PY` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | A08:2021 — Software and Data Integrity Failures |
| `SG-YAML-UNSAFE-LOAD-PY` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | A08:2021 — Software and Data Integrity Failures |
| `AGT-001` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | A03:2021 — Injection |
| `AGT-002` | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | A07:2021 — Identification and Authentication Failures |
| `AGT-003` | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | A01:2021 — Broken Access Control |
| `AGT-004` | [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | A03:2021 — Injection |
| `AGT-005` | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | A07:2021 — Identification and Authentication Failures |
| `AGT-006` | [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | A04:2021 — Insecure Design |
| `WFL-001` | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | A08:2021 — Software and Data Integrity Failures |
| `WFL-002` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | A03:2021 — Injection |
| `WFL-003` | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | A08:2021 — Software and Data Integrity Failures |
| `WFL-004` | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | A05:2021 — Security Misconfiguration |
| `WFL-005` | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | A05:2021 — Security Misconfiguration |
| `WFL-009` | [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | A04:2021 — Insecure Design |
| `WFL-011` | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | A08:2021 — Software and Data Integrity Failures |
| `DOC-001` | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | A05:2021 — Security Misconfiguration |
| `DOC-010` | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | A05:2021 — Security Misconfiguration |
| `DOC-020` | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | A05:2021 — Security Misconfiguration |
| `DOC-021` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | A07:2021 — Identification and Authentication Failures |
| `DOC-024` | [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) | A05:2021 — Security Misconfiguration |
| `DOC-025` | [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | A05:2021 — Security Misconfiguration |
| `DEP-001` | [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | A08:2021 — Software and Data Integrity Failures |
| `DEP-002` | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | A08:2021 — Software and Data Integrity Failures |
| `DEP-AUDIT-CRITICAL` | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | A06:2021 — Vulnerable and Outdated Components |
| `DEP-AUDIT-HIGH` | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | A06:2021 — Vulnerable and Outdated Components |
| `DEP-OSV-CRITICAL` | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | A06:2021 — Vulnerable and Outdated Components |
| `DEP-OSV-HIGH` | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | A06:2021 — Vulnerable and Outdated Components |
| `DEP-OSV-LOWER` | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | A06:2021 — Vulnerable and Outdated Components |

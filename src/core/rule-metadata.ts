// ============================================================
// PRISM — CWE / OWASP metadata for the rule catalog
//
// Curated mapping for every SECURITY-RELEVANT rule. Quality rules
// (structure, consistency, test hygiene, CI ergonomics) are deliberately
// absent — stamping a CWE on a naming-convention rule would be metadata
// theater, and credibility is the primary design constraint. SG-* entries
// mirror the metadata embedded in the semgrep rule pack (a test enforces
// the sync). Consumed by the SARIF reporter (GitHub Code Scanning tags +
// alert ranking) and the docs catalog.
// ============================================================

export interface RuleSecurityMetadata {
  /** CWE identifier, e.g. "CWE-89". */
  cwe: string;
  /** OWASP Top 10 2021 code, e.g. "A03:2021". */
  owasp: string;
}

export const RULE_METADATA: Record<string, RuleSecurityMetadata> = {
  // ---------- Security: committed env files ----------
  'SEC-ENV-COMMITTED': { cwe: 'CWE-312', owasp: 'A05:2021' },
  'SEC-GITIGNORE-ENV': { cwe: 'CWE-312', owasp: 'A05:2021' },

  // ---------- Security: hardcoded credentials ----------
  'SEC-ENTROPY': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-AWS-KEY': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-GH-PAT': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-GH-OAUTH': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-API-KEY': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-PRIVATE-KEY': { cwe: 'CWE-321', owasp: 'A02:2021' },
  'SEC-DB-URL': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-JWT': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-TELEGRAM': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-STRIPE-SK': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-STRIPE-PK': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-OPENAI': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-ANTHROPIC': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'SEC-PASSWORD': { cwe: 'CWE-259', owasp: 'A07:2021' },
  'SEC-ENV-VALUE': { cwe: 'CWE-798', owasp: 'A07:2021' },

  // ---------- Security: semgrep taint rules (mirrors the rule pack) ----------
  'SG-SQLI-TAINTED-QUERY': { cwe: 'CWE-89', owasp: 'A03:2021' },
  'SG-XSS-TAINTED-RESPONSE': { cwe: 'CWE-79', owasp: 'A03:2021' },
  'SG-DOM-XSS-INNERHTML': { cwe: 'CWE-79', owasp: 'A03:2021' },
  'SG-SSRF-TAINTED-URL': { cwe: 'CWE-918', owasp: 'A10:2021' },
  'SG-PATH-TRAVERSAL-FS': { cwe: 'CWE-22', owasp: 'A01:2021' },
  'SG-COMMAND-INJECTION-EXEC': { cwe: 'CWE-78', owasp: 'A03:2021' },
  'SG-CODE-INJECTION-EVAL': { cwe: 'CWE-95', owasp: 'A03:2021' },
  'SG-SQLI-TAINTED-EXECUTE-PY': { cwe: 'CWE-89', owasp: 'A03:2021' },
  'SG-COMMAND-INJECTION-PY': { cwe: 'CWE-78', owasp: 'A03:2021' },
  'SG-SSRF-TAINTED-URL-PY': { cwe: 'CWE-918', owasp: 'A10:2021' },
  'SG-PATH-TRAVERSAL-OPEN-PY': { cwe: 'CWE-22', owasp: 'A01:2021' },
  'SG-PICKLE-LOAD-UNTRUSTED-PY': { cwe: 'CWE-502', owasp: 'A08:2021' },
  'SG-YAML-UNSAFE-LOAD-PY': { cwe: 'CWE-502', owasp: 'A08:2021' },

  // ---------- Agentic ----------
  'AGT-001': { cwe: 'CWE-78', owasp: 'A03:2021' },
  'AGT-002': { cwe: 'CWE-522', owasp: 'A07:2021' },
  'AGT-003': { cwe: 'CWE-862', owasp: 'A01:2021' },
  'AGT-004': { cwe: 'CWE-74', owasp: 'A03:2021' },
  'AGT-005': { cwe: 'CWE-306', owasp: 'A07:2021' },
  'AGT-006': { cwe: 'CWE-636', owasp: 'A04:2021' },

  // ---------- Workflow (GitHub Actions) ----------
  'WFL-001': { cwe: 'CWE-829', owasp: 'A08:2021' },
  'WFL-002': { cwe: 'CWE-78', owasp: 'A03:2021' },
  'WFL-003': { cwe: 'CWE-829', owasp: 'A08:2021' },
  'WFL-004': { cwe: 'CWE-250', owasp: 'A05:2021' },
  'WFL-005': { cwe: 'CWE-250', owasp: 'A05:2021' },
  'WFL-009': { cwe: 'CWE-636', owasp: 'A04:2021' },
  'WFL-011': { cwe: 'CWE-829', owasp: 'A08:2021' },

  // ---------- Docker ----------
  'DOC-001': { cwe: 'CWE-200', owasp: 'A05:2021' },
  'DOC-010': { cwe: 'CWE-250', owasp: 'A05:2021' },
  'DOC-020': { cwe: 'CWE-250', owasp: 'A05:2021' },
  'DOC-021': { cwe: 'CWE-798', owasp: 'A07:2021' },
  'DOC-024': { cwe: 'CWE-1327', owasp: 'A05:2021' },
  'DOC-025': { cwe: 'CWE-668', owasp: 'A05:2021' },

  // ---------- Dependencies (known-vulnerability signals) ----------
  'DEP-001': { cwe: 'CWE-494', owasp: 'A08:2021' },
  'DEP-002': { cwe: 'CWE-829', owasp: 'A08:2021' },
  'DEP-AUDIT-CRITICAL': { cwe: 'CWE-1395', owasp: 'A06:2021' },
  'DEP-AUDIT-HIGH': { cwe: 'CWE-1395', owasp: 'A06:2021' },
  'DEP-OSV-CRITICAL': { cwe: 'CWE-1395', owasp: 'A06:2021' },
  'DEP-OSV-HIGH': { cwe: 'CWE-1395', owasp: 'A06:2021' },
  'DEP-OSV-LOWER': { cwe: 'CWE-1395', owasp: 'A06:2021' },
};

/**
 * Metadata for a rule id, falling back to the CWE/OWASP a finding carries in
 * its own meta (semgrep findings embed them, and future engines may too).
 * OWASP long form ("A03:2021 - Injection") is normalized to the code.
 */
export function ruleMetadataFor(
  ruleId: string,
  findingMeta: Record<string, unknown> | undefined,
): RuleSecurityMetadata | undefined {
  const fromCatalog = RULE_METADATA[ruleId];
  if (fromCatalog) return fromCatalog;

  const cwe = findingMeta?.cwe;
  const owasp = findingMeta?.owasp;
  if (typeof cwe !== 'string' || !/^CWE-\d+$/.test(cwe)) return undefined;
  const owaspCode = typeof owasp === 'string' ? /^(A\d{2}:\d{4})/.exec(owasp)?.[1] : undefined;
  return owaspCode ? { cwe, owasp: owaspCode } : undefined;
}

// ============================================================
// Context tier — how much code the AI triage needs to judge a rule
//
// The triage layer used to send every finding with its whole file (up to
// 60k chars). For half the catalog that is pure token spend: a god file is
// big whether or not the model reads it, an OSV advisory applies whether or
// not the model reads the lockfile, "no tests" has no file at all. The tier
// says what evidence can actually flip the verdict:
//
// - `none`: the evidence is a fact computed over the project — a count, the
//   import graph, an external advisory database, a missing file. Reading the
//   flagged file cannot change the call, so the finding is batched with
//   other no-code findings and judged from its description and metadata.
// - `file`: the evidence is a pattern in a line, and the verdict flips on
//   what that line really is (a Docker mount path vs a password, a fixture
//   vs source). The file is read. This is the default — an unknown rule gets
//   the safe, expensive behavior, never the cheap one.
// - `neighborhood`: the verdict depends on code OUTSIDE the file — the
//   sanitizer, the auth gate, the policy layer that a line-level rule cannot
//   see (the AGT-003 case on orion: every destructive tool was "ungated" in
//   its own file because the gate lived in a Policy DSL elsewhere). The
//   judge additionally gets the related files the import graph points at
//   (see src/ai/neighborhood.ts); with no usable neighbor it behaves as `file`.
//
// Remediation deliberately ignores tiers: proposing how to split a god file
// or which line of package.json to bump genuinely needs the content.
// ============================================================

export type ContextTier = 'none' | 'file' | 'neighborhood';

export const CONTEXT_TIER: Record<string, ContextTier> = {
  // ---------- Facts over the project: no code can change the verdict ----------
  'DEP-001': 'none', // no lockfile
  'DEP-002': 'none', // wildcard versions — the finding names the dep
  'DEP-003': 'none', // dependency count
  'DEP-004': 'none', // engines field absent
  'DEP-005': 'none', // test script absent
  'DEP-PY-001': 'none', // unpinned requirements — the finding names them
  'DEP-PARSE-ERR': 'none',
  'DEP-AUDIT-CRITICAL': 'none', // external advisory database
  'DEP-AUDIT-HIGH': 'none',
  'DEP-AUDIT-LOWER': 'none',
  'DEP-AUDIT-SKIP': 'none',
  'DEP-OSV-CRITICAL': 'none',
  'DEP-OSV-HIGH': 'none',
  'DEP-OSV-LOWER': 'none',
  'DEP-OSV-UNKNOWN': 'none',
  'DEP-OSV-SKIP': 'none',
  'DEP-OSV-INCOMPLETE': 'none',
  'STR-001': 'none', // README / .gitignore / layout / nesting / naming / linter / tsconfig / empty dirs
  'STR-002': 'none',
  'STR-003': 'none',
  'STR-004': 'none',
  'STR-005': 'none',
  'STR-006': 'none',
  'STR-007': 'none',
  'STR-008': 'none',
  'STR-009': 'none',
  'STR-010': 'none',
  'STR-011': 'none', // god file — the LOC count is the evidence
  'STR-012': 'none', // import cycle — the graph is the evidence
  'CON-001': 'none', // mixed naming conventions (aggregate)
  'CON-002': 'none', // mixed natural languages (aggregate)
  'CON-003': 'none', // inconsistent indentation (aggregate)
  'TST-001': 'none', // no tests
  'TST-002': 'none', // test ratio
  'TST-003': 'none', // no test framework config
  'SEC-SEMGREP-MISSING': 'none', // engine-state notices
  'SEC-SEMGREP-ERROR': 'none',
  'SEC-SEMGREP-INCOMPLETE': 'none',
  'SEC-SEMGREP-TRUNCATED': 'none',

  // ---------- Cross-file: the gate or sanitizer may live elsewhere ----------
  'AGT-001': 'neighborhood', // shell built from a value defined upstream
  'AGT-003': 'neighborhood', // destructive tool gated by an external policy layer
  'AGT-004': 'neighborhood', // external content sanitized before the prompt builder
  'AGT-006': 'neighborhood', // fail-open catch around a gate defined elsewhere
  'SG-SQLI-TAINTED-QUERY': 'neighborhood', // taint: source and sink cross files
  'SG-XSS-TAINTED-RESPONSE': 'neighborhood',
  'SG-DOM-XSS-INNERHTML': 'neighborhood',
  'SG-SSRF-TAINTED-URL': 'neighborhood',
  'SG-PATH-TRAVERSAL-FS': 'neighborhood',
  'SG-COMMAND-INJECTION-EXEC': 'neighborhood',
  'SG-CODE-INJECTION-EVAL': 'neighborhood',
  'SG-SQLI-TAINTED-EXECUTE-PY': 'neighborhood',
  'SG-COMMAND-INJECTION-PY': 'neighborhood',
  'SG-SSRF-TAINTED-URL-PY': 'neighborhood',
  'SG-PATH-TRAVERSAL-OPEN-PY': 'neighborhood',
  'SG-PICKLE-LOAD-UNTRUSTED-PY': 'neighborhood',
  'SG-YAML-UNSAFE-LOAD-PY': 'neighborhood',

  // Everything else (SEC-* secrets, DOC-*, WFL-*, TST-01x, STR-013, AGT-002/005)
  // is a line pattern judged against its own file — the `file` default.
};

/** Context tier for a rule id; unknown rules get the safe default (`file`). */
export function contextTierFor(ruleId: string): ContextTier {
  return CONTEXT_TIER[ruleId] ?? 'file';
}

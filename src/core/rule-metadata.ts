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

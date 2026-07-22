import ignore from 'ignore';
import type { AnalyzerResult, Severity, SuppressedFinding, Suppression } from './types.js';

/**
 * Standard per-severity penalty refunded to a category's score when one of its
 * findings is suppressed. Analyzers score with their own ad-hoc penalties, so
 * this is an approximation by design (it matches the secrets analyzer exactly);
 * the alternative — re-running every analyzer with the finding masked — would
 * couple suppression to each analyzer's internals.
 */
const SUPPRESSION_REFUND: Record<Severity, number> = {
  critical: 1.5,
  high: 1.0,
  medium: 0.5,
  low: 0.2,
  info: 0,
};

export interface SuppressionOutcome {
  /** Analyzer results with suppressed findings removed and scores refunded. */
  results: AnalyzerResult[];
  /** What was silenced, and why — kept for report transparency. */
  suppressed: SuppressedFinding[];
  /** Expired or stale (matched-nothing) suppressions the human should see. */
  warnings: string[];
}

/** A suppression is expired when its `expires` date is strictly before today (UTC). */
function isExpired(s: Suppression, now: Date): boolean {
  if (!s.expires) return false;
  return new Date(`${s.expires}T23:59:59Z`).getTime() < now.getTime();
}

/**
 * Apply justified suppressions to analyzer results, before scoring aggregation,
 * gates, fingerprints, and AI triage. Matching is by rule id (case-insensitive)
 * plus an optional gitignore-syntax file pattern. Expired entries are ignored
 * with a warning; entries that match nothing produce a stale warning so config
 * files don't accumulate dead exceptions.
 */
export function applySuppressions(
  results: AnalyzerResult[],
  suppressions: Suppression[],
  now: Date = new Date(),
): SuppressionOutcome {
  if (suppressions.length === 0) return { results, suppressed: [], warnings: [] };

  const warnings: string[] = [];
  const active: { s: Suppression; matcher?: ReturnType<typeof ignore>; hits: number }[] = [];
  for (const s of suppressions) {
    if (isExpired(s, now)) {
      warnings.push(
        `Suppression for ${s.rule}${s.file ? ` (${s.file})` : ''} expired on ${s.expires} — the finding is reported again.`,
      );
      continue;
    }
    active.push({ s, matcher: s.file ? ignore().add(s.file) : undefined, hits: 0 });
  }

  const suppressed: SuppressedFinding[] = [];
  const nextResults = results.map((result) => {
    let refund = 0;
    const kept = result.findings.filter((finding) => {
      const match = active.find((a) => {
        if (a.s.rule.toUpperCase() !== finding.id.toUpperCase()) return false;
        if (!a.matcher) return true;
        return finding.file ? a.matcher.ignores(finding.file) : false;
      });
      if (!match) return true;
      match.hits += 1;
      suppressed.push({ finding, reason: match.s.reason });
      refund += SUPPRESSION_REFUND[finding.severity];
      return false;
    });
    if (kept.length === result.findings.length) return result;
    const score = Math.min(10, Math.round((result.score + refund) * 10) / 10);
    return { ...result, findings: kept, score };
  });

  for (const a of active) {
    if (a.hits === 0) {
      warnings.push(
        `Suppression for ${a.s.rule}${a.s.file ? ` (${a.s.file})` : ''} matched no findings — it may be stale and removable.`,
      );
    }
  }

  return { results: nextResults, suppressed, warnings };
}

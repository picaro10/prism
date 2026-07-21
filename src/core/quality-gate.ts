import type { AuditReport, Severity } from './types.js';

/** Severity ordering for threshold comparisons (higher = worse). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface QualityGateConfig {
  /** Fail when the overall score is below this. */
  minScore: number;
  /** Fail when any finding is at or above this severity. */
  failOn?: Severity;
  /** Fail when the count of critical findings exceeds this. */
  maxCritical?: number;
  /** Fail when the count of high findings exceeds this. */
  maxHigh?: number;
}

export interface QualityGateResult {
  passed: boolean;
  /** Human-readable reasons the gate failed (empty when passed). */
  reasons: string[];
}

export function countBySeverity(report: AuditReport): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report.findings) counts[f.severity]++;
  return counts;
}

/**
 * Evaluate the quality gate. A gate can fail for several independent reasons: a
 * low overall score, OR a severity threshold, OR a per-severity count cap. The
 * average alone must never be the only door — a single new critical can hide
 * behind good scores elsewhere, so severity gates are checked separately.
 */
export function evaluateQualityGate(report: AuditReport, cfg: QualityGateConfig): QualityGateResult {
  const reasons: string[] = [];
  const counts = countBySeverity(report);

  if (report.overallScore < cfg.minScore) {
    reasons.push(`overall score ${report.overallScore} is below --min-score ${cfg.minScore}`);
  }

  if (cfg.failOn) {
    const threshold = SEVERITY_RANK[cfg.failOn];
    const hits = report.findings.filter((f) => SEVERITY_RANK[f.severity] >= threshold).length;
    if (hits > 0) {
      reasons.push(`${hits} finding(s) at or above severity '${cfg.failOn}' (--fail-on)`);
    }
  }

  if (cfg.maxCritical !== undefined && counts.critical > cfg.maxCritical) {
    reasons.push(`${counts.critical} critical finding(s) exceed --max-critical ${cfg.maxCritical}`);
  }

  if (cfg.maxHigh !== undefined && counts.high > cfg.maxHigh) {
    reasons.push(`${counts.high} high finding(s) exceed --max-high ${cfg.maxHigh}`);
  }

  return { passed: reasons.length === 0, reasons };
}

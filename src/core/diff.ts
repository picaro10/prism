import type { AuditReport, Finding } from './types.js';
import { findingKey } from '../ai/types.js';

/** The delta between two audit reports of (presumably) the same project. */
export interface ReportDiff {
  /** Findings present in `current` but not in `baseline` — regressions. */
  added: Finding[];
  /** Findings present in `baseline` but not in `current` — resolved. */
  removed: Finding[];
  baselineScore: number;
  currentScore: number;
  /** currentScore − baselineScore, rounded to 1 decimal. */
  scoreDelta: number;
}

/**
 * Diff two saved reports by findingKey. A finding whose key is in `current` but
 * not in `baseline` is "added" (a regression); one only in `baseline` is
 * "removed" (fixed). Keys are stable across runs, so this is deterministic.
 */
export function diffReports(baseline: AuditReport, current: AuditReport): ReportDiff {
  const baseKeys = new Set(baseline.findings.map(findingKey));
  const currKeys = new Set(current.findings.map(findingKey));
  return {
    added: current.findings.filter((f) => !baseKeys.has(findingKey(f))),
    removed: baseline.findings.filter((f) => !currKeys.has(findingKey(f))),
    baselineScore: baseline.overallScore,
    currentScore: current.overallScore,
    scoreDelta: Math.round((current.overallScore - baseline.overallScore) * 10) / 10,
  };
}

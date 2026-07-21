import type { AuditReport, Finding } from './types.js';

export interface NewCodeDiff {
  /** Findings present now whose fingerprint is not in the baseline — new. */
  newFindings: Finding[];
  /** Findings in the baseline whose fingerprint is gone now — fixed. */
  fixedFindings: Finding[];
  /** Findings that existed in the baseline and still do. */
  existingCount: number;
}

/** Identity key for diffing: prefer the stable fingerprint, fall back to id+file+line. */
function key(f: Finding): string {
  return f.fingerprint ?? `${f.id}|${f.file ?? ''}|${f.line ?? ''}`;
}

/**
 * Compare a baseline report to the current one by fingerprint. A finding is
 * "new" only if its fingerprint isn't in the baseline — so old debt doesn't
 * gate, but nothing new is allowed to slip in. This is the SonarQube-style
 * "clean as you code" model: legacy code can carry debt; new code must not add.
 */
export function diffByFingerprint(baseline: AuditReport, current: AuditReport): NewCodeDiff {
  const baseKeys = new Set(baseline.findings.map(key));
  const currKeys = new Set(current.findings.map(key));
  const newFindings = current.findings.filter((f) => !baseKeys.has(key(f)));
  const fixedFindings = baseline.findings.filter((f) => !currKeys.has(key(f)));
  return {
    newFindings,
    fixedFindings,
    existingCount: current.findings.length - newFindings.length,
  };
}

/**
 * Build a report view containing only the given findings — so the existing
 * quality gate can be evaluated against just the new code.
 */
export function reportOfFindings(current: AuditReport, findings: Finding[]): AuditReport {
  return { ...current, findings };
}

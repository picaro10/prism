import { describe, it, expect } from 'vitest';
import { diffByFingerprint, reportOfFindings } from '../../src/core/new-code-gate.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(fingerprint: string, p: Partial<Finding> = {}): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', fingerprint, ...p };
}
function report(findings: Finding[], overallScore = 8): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '',
    durationMs: 0,
    overallScore,
    categories: [],
    findings,
    projectMeta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 0,
      totalFiles: 0,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
    prismVersion: '1.0.0',
  };
}

describe('diffByFingerprint', () => {
  it('separates new, fixed, and existing by fingerprint', () => {
    const baseline = report([finding('aaa'), finding('bbb')]);
    const current = report([finding('aaa'), finding('ccc')]); // bbb fixed, ccc new, aaa kept
    const d = diffByFingerprint(baseline, current);
    expect(d.newFindings.map((f) => f.fingerprint)).toEqual(['ccc']);
    expect(d.fixedFindings.map((f) => f.fingerprint)).toEqual(['bbb']);
    expect(d.existingCount).toBe(1);
  });

  it('does not flag a moved finding as new (same fingerprint, different line)', () => {
    const baseline = report([finding('aaa', { line: 5 })]);
    const current = report([finding('aaa', { line: 40 })]); // same code moved down
    const d = diffByFingerprint(baseline, current);
    expect(d.newFindings).toHaveLength(0);
    expect(d.fixedFindings).toHaveLength(0);
    expect(d.existingCount).toBe(1);
  });

  it('falls back to id|file|line when a fingerprint is missing', () => {
    const baseline = report([{ ...finding('', { id: 'A', file: 'a.ts', line: 1 }), fingerprint: undefined }]);
    const current = report([{ ...finding('', { id: 'A', file: 'a.ts', line: 1 }), fingerprint: undefined }]);
    expect(diffByFingerprint(baseline, current).newFindings).toHaveLength(0);
  });
});

describe('reportOfFindings', () => {
  it('keeps report metadata but swaps the findings (for gating new code)', () => {
    const full = report([finding('a'), finding('b')], 9.1);
    const sub = reportOfFindings(full, [finding('b')]);
    expect(sub.overallScore).toBe(9.1); // score is still the whole project's
    expect(sub.findings).toHaveLength(1);
    expect(sub.projectName).toBe('demo');
  });
});

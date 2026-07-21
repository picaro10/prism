import { describe, it, expect } from 'vitest';
import { diffReports } from '../../src/core/diff.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X-001', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
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
    prismVersion: '1.9.0',
  };
}

describe('diffReports', () => {
  it('reports added (regressions) and removed (fixed) findings by key', () => {
    const kept = finding({ id: 'A', file: 'src/a.ts', line: 1 });
    const baseline = report([kept, finding({ id: 'GONE', file: 'src/b.ts', line: 2 })], 9);
    const current = report([kept, finding({ id: 'NEW', file: 'src/c.ts', line: 3 })], 7);

    const d = diffReports(baseline, current);
    expect(d.added.map((f) => f.id)).toEqual(['NEW']);
    expect(d.removed.map((f) => f.id)).toEqual(['GONE']);
    expect(d.baselineScore).toBe(9);
    expect(d.currentScore).toBe(7);
    expect(d.scoreDelta).toBe(-2);
  });

  it('reports no change when the findings are identical', () => {
    const fs = [finding({ id: 'A', file: 'src/a.ts', line: 1 })];
    const d = diffReports(report(fs, 8), report(fs, 8));
    expect(d.added).toHaveLength(0);
    expect(d.removed).toHaveLength(0);
    expect(d.scoreDelta).toBe(0);
  });

  it('distinguishes same-id findings on different lines', () => {
    const baseline = report([finding({ id: 'DUP', file: 'src/a.ts', line: 1 })]);
    const current = report([finding({ id: 'DUP', file: 'src/a.ts', line: 9 })]);
    const d = diffReports(baseline, current);
    expect(d.added).toHaveLength(1); // line 9 is new
    expect(d.removed).toHaveLength(1); // line 1 is gone
  });
});

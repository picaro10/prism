import { describe, it, expect } from 'vitest';
import { evaluateQualityGate, countBySeverity } from '../../src/core/quality-gate.js';
import type { AuditReport, Finding, Severity } from '../../src/core/types.js';

function finding(severity: Severity, id = 'X'): Finding {
  return { id, category: 'security', severity, title: 't', description: 'd' };
}
function report(findings: Finding[], overallScore = 9): AuditReport {
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

describe('countBySeverity', () => {
  it('tallies findings per severity', () => {
    const c = countBySeverity(report([finding('critical'), finding('critical'), finding('high'), finding('low')]));
    expect(c).toMatchObject({ critical: 2, high: 1, low: 1, medium: 0, info: 0 });
  });
});

describe('evaluateQualityGate', () => {
  it('passes a clean high-scoring report', () => {
    const g = evaluateQualityGate(report([finding('low')], 9.5), { minScore: 8.5, failOn: 'critical', maxHigh: 0 });
    expect(g.passed).toBe(true);
    expect(g.reasons).toEqual([]);
  });

  it('fails on a low score', () => {
    const g = evaluateQualityGate(report([], 5), { minScore: 8 });
    expect(g.passed).toBe(false);
    expect(g.reasons[0]).toMatch(/below --min-score/);
  });

  it('--fail-on critical catches a critical hidden behind a high average', () => {
    // 9.2 average but one critical — the average alone would let it through.
    const g = evaluateQualityGate(report([finding('critical')], 9.2), { minScore: 8, failOn: 'critical' });
    expect(g.passed).toBe(false);
    expect(g.reasons.some((r) => r.includes("severity 'critical'"))).toBe(true);
  });

  it('--fail-on high also catches criticals (severity is a floor)', () => {
    const g = evaluateQualityGate(report([finding('critical')], 9), { minScore: 0, failOn: 'high' });
    expect(g.passed).toBe(false);
  });

  it('--max-high enforces a per-severity cap', () => {
    const twoHigh = report([finding('high', 'A'), finding('high', 'B')], 9);
    expect(evaluateQualityGate(twoHigh, { minScore: 0, maxHigh: 0 }).passed).toBe(false);
    expect(evaluateQualityGate(twoHigh, { minScore: 0, maxHigh: 2 }).passed).toBe(true);
  });

  it('--max-critical enforces a per-severity cap', () => {
    const oneCrit = report([finding('critical')], 9);
    expect(evaluateQualityGate(oneCrit, { minScore: 0, maxCritical: 0 }).passed).toBe(false);
    expect(evaluateQualityGate(oneCrit, { minScore: 0, maxCritical: 1 }).passed).toBe(true);
  });

  it('collects every failing reason at once', () => {
    const g = evaluateQualityGate(report([finding('critical'), finding('high')], 5), {
      minScore: 8,
      failOn: 'critical',
      maxHigh: 0,
    });
    expect(g.passed).toBe(false);
    expect(g.reasons.length).toBeGreaterThanOrEqual(3); // score + fail-on + max-high
  });
});

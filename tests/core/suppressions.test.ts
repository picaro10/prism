import { describe, it, expect } from 'vitest';
import { applySuppressions } from '../../src/core/suppressions.js';
import type { AnalyzerResult, Finding, Severity, Suppression } from '../../src/core/types.js';

function finding(id: string, severity: Severity, file?: string): Finding {
  return { id, category: 'security', severity, title: id, description: 'd', file };
}
function result(findings: Finding[], score = 5): AnalyzerResult {
  return { category: 'security', score, findings, summary: 's' };
}
const NOW = new Date('2026-07-22T00:00:00Z');

describe('applySuppressions', () => {
  it('removes a finding matched by rule and records it with the reason', () => {
    const suppressions: Suppression[] = [{ rule: 'SEC-001', reason: 'fake credential for the detector test' }];
    const r = applySuppressions(
      [result([finding('SEC-001', 'high', 'a.ts'), finding('SEC-002', 'high', 'b.ts')])],
      suppressions,
      NOW,
    );
    expect(r.results[0].findings.map((f) => f.id)).toEqual(['SEC-002']);
    expect(r.suppressed).toHaveLength(1);
    expect(r.suppressed[0].finding.id).toBe('SEC-001');
    expect(r.suppressed[0].reason).toBe('fake credential for the detector test');
  });

  it('narrows by file pattern with gitignore syntax', () => {
    const suppressions: Suppression[] = [{ rule: 'SEC-001', file: 'tests/fixtures/**', reason: 'fixtures' }];
    const r = applySuppressions(
      [result([finding('SEC-001', 'high', 'tests/fixtures/fake.ts'), finding('SEC-001', 'high', 'src/real.ts')])],
      suppressions,
      NOW,
    );
    expect(r.results[0].findings.map((f) => f.file)).toEqual(['src/real.ts']);
    expect(r.suppressed).toHaveLength(1);
  });

  it('does not match a file-scoped suppression against a finding without a file', () => {
    const suppressions: Suppression[] = [{ rule: 'STR-001', file: 'src/**', reason: 'r' }];
    const r = applySuppressions([result([finding('STR-001', 'low')])], suppressions, NOW);
    expect(r.results[0].findings).toHaveLength(1);
    expect(r.suppressed).toHaveLength(0);
  });

  it('matches rule ids case-insensitively', () => {
    const r = applySuppressions(
      [result([finding('SEC-001', 'high', 'a.ts')])],
      [{ rule: 'sec-001', reason: 'r' }],
      NOW,
    );
    expect(r.suppressed).toHaveLength(1);
  });

  it('refunds the standard penalty per suppressed severity, capped at 10', () => {
    const findings = [finding('SEC-001', 'critical', 'a.ts'), finding('SEC-002', 'high', 'b.ts')];
    const r = applySuppressions(
      [result(findings, 5)],
      [
        { rule: 'SEC-001', reason: 'r1' },
        { rule: 'SEC-002', reason: 'r2' },
      ],
      NOW,
    );
    // 5 + 1.5 (critical) + 1.0 (high) = 7.5
    expect(r.results[0].score).toBe(7.5);

    const capped = applySuppressions(
      [result([finding('SEC-001', 'critical', 'a.ts')], 9.5)],
      [{ rule: 'SEC-001', reason: 'r' }],
      NOW,
    );
    expect(capped.results[0].score).toBe(10);
  });

  it('ignores an expired suppression and warns, keeping the finding', () => {
    const suppressions: Suppression[] = [{ rule: 'SEC-001', reason: 'temporary', expires: '2026-01-01' }];
    const r = applySuppressions([result([finding('SEC-001', 'high', 'a.ts')])], suppressions, NOW);
    expect(r.results[0].findings).toHaveLength(1);
    expect(r.suppressed).toHaveLength(0);
    expect(r.warnings.some((w) => /expired/i.test(w) && w.includes('SEC-001'))).toBe(true);
  });

  it('applies a suppression that expires in the future', () => {
    const suppressions: Suppression[] = [{ rule: 'SEC-001', reason: 'until rotation', expires: '2027-01-01' }];
    const r = applySuppressions([result([finding('SEC-001', 'high', 'a.ts')])], suppressions, NOW);
    expect(r.suppressed).toHaveLength(1);
    expect(r.warnings).toHaveLength(0);
  });

  it('warns about a suppression that matched nothing (stale)', () => {
    const r = applySuppressions(
      [result([finding('SEC-002', 'high', 'a.ts')])],
      [{ rule: 'SEC-001', reason: 'r' }],
      NOW,
    );
    expect(r.warnings.some((w) => /matched no findings/i.test(w) && w.includes('SEC-001'))).toBe(true);
  });

  it('leaves results untouched when there are no suppressions', () => {
    const input = [result([finding('SEC-001', 'high', 'a.ts')], 5)];
    const r = applySuppressions(input, [], NOW);
    expect(r.results[0].findings).toHaveLength(1);
    expect(r.results[0].score).toBe(5);
    expect(r.suppressed).toHaveLength(0);
    expect(r.warnings).toHaveLength(0);
  });
});

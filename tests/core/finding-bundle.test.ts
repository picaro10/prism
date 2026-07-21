import { describe, it, expect } from 'vitest';
import { buildFindingBundle, findByKey, extractSnippet } from '../../src/core/finding-bundle.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}
function report(p: Partial<AuditReport> = {}): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '2026-07-21T00:00:00.000Z',
    durationMs: 0,
    overallScore: 6,
    categories: [],
    findings: [finding({ id: 'SEC-1', file: 'src/a.ts', line: 5 })],
    projectMeta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 0,
      totalFiles: 0,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
    prismVersion: '1.12.0',
    ...p,
  };
}

describe('extractSnippet', () => {
  it('slices ±context lines, clamped to file bounds', () => {
    const content = ['l1', 'l2', 'l3', 'l4', 'l5'].join('\n');
    expect(extractSnippet(content, 3, 1)).toEqual({ startLine: 2, endLine: 4, code: 'l2\nl3\nl4' });
    expect(extractSnippet(content, 1, 2)).toEqual({ startLine: 1, endLine: 3, code: 'l1\nl2\nl3' });
    expect(extractSnippet(content, 5, 2)).toEqual({ startLine: 3, endLine: 5, code: 'l3\nl4\nl5' });
  });
});

describe('findByKey', () => {
  it('finds a finding by exact key and tolerates a trimmed trailing pipe', () => {
    const r = report({ findings: [finding({ id: 'STR-011', file: 'src/big.ts' })] });
    expect(findByKey(r, 'STR-011|src/big.ts|')?.id).toBe('STR-011');
    expect(findByKey(r, 'STR-011|src/big.ts')?.id).toBe('STR-011'); // model dropped the trailing pipe
    expect(findByKey(r, 'NOPE|x|1')).toBeNull();
  });
});

describe('buildFindingBundle', () => {
  it('assembles a self-contained bundle with snippet, verdict and fix', () => {
    const r = report({
      aiTriage: {
        verdicts: [{ findingKey: 'SEC-1|src/a.ts|5', classification: 'real', confidence: 0.9, reasoning: 'r' }],
        summary: { real: 1, falsePositive: 0, uncertain: 0 },
      },
      aiRemediation: [{ findingKey: 'SEC-1|src/a.ts|5', fix: 'do X', effort: 'low' }],
    });
    const content = ['a', 'b', 'c', 'd', 'e', 'f', 'g'].join('\n');
    const b = buildFindingBundle(r, 'SEC-1|src/a.ts|5', content, 1);
    expect(b?.scan.project).toBe('demo');
    expect(b?.finding.id).toBe('SEC-1');
    expect(b?.location).toEqual({ file: 'src/a.ts', line: 5 });
    expect(b?.snippet).toEqual({ startLine: 4, endLine: 6, code: 'd\ne\nf' });
    expect(b?.verdict?.classification).toBe('real');
    expect(b?.remediation?.fix).toBe('do X');
  });

  it('returns a null snippet when the file is unavailable, without failing', () => {
    const b = buildFindingBundle(report(), 'SEC-1|src/a.ts|5', null);
    expect(b?.finding.id).toBe('SEC-1');
    expect(b?.snippet).toBeNull();
  });

  it('has null location and snippet for a project-level finding', () => {
    const r = report({ findings: [finding({ id: 'TST-001' })] });
    const b = buildFindingBundle(r, 'TST-001||', null);
    expect(b?.location).toBeNull();
    expect(b?.snippet).toBeNull();
    expect(b?.verdict).toBeNull();
  });

  it('returns null for an unknown key', () => {
    expect(buildFindingBundle(report(), 'GHOST|x|1', null)).toBeNull();
  });
});

import { describe, it, expect } from 'vitest';
import { parseReport, parseReportDetailed } from '../../src/core/report-schema.js';

const validFinding = {
  id: 'SEC-001',
  category: 'security',
  severity: 'high',
  title: 'x',
  description: 'd',
  file: 'src/a.ts',
  line: 3,
};

const validReport = {
  projectName: 'demo',
  projectPath: '/tmp/demo',
  overallScore: 7.5,
  categories: [{ category: 'security', score: 7.5, findings: [validFinding], summary: 's' }],
  findings: [validFinding],
  projectMeta: {
    stack: { primary: 'typescript', secondary: [] },
    totalLoc: 0,
    totalFiles: 12,
    hasGit: true,
    hasDocker: false,
    hasCi: true,
    frameworks: [],
  },
};

describe('parseReport', () => {
  it('accepts a well-formed report', () => {
    expect(parseReport(validReport)).not.toBeNull();
  });

  it('accepts a minimal 1.0-era report (no prismVersion/fingerprints/applicable)', () => {
    expect(parseReport({ ...validReport, prismVersion: undefined })).not.toBeNull();
  });

  it('tolerates unknown extra keys (forward compatibility)', () => {
    expect(parseReport({ ...validReport, aiTriage: { verdicts: [], summary: {} }, futureField: 1 })).not.toBeNull();
  });

  it('rejects non-objects and junk', () => {
    expect(parseReport(null)).toBeNull();
    expect(parseReport('str')).toBeNull();
    expect(parseReport({})).toBeNull();
  });

  it('rejects a finding without a severity (used to 500 in the HTML renderer)', () => {
    const broken = { ...validReport, findings: [{ ...validFinding, severity: undefined }] };
    expect(parseReport(broken)).toBeNull();
  });

  it('rejects an invalid severity value', () => {
    const broken = { ...validReport, findings: [{ ...validFinding, severity: 'catastrophic' }] };
    expect(parseReport(broken)).toBeNull();
  });

  it('rejects a category without a findings array', () => {
    const broken = { ...validReport, categories: [{ category: 'security', score: 5, summary: 's' }] };
    expect(parseReport(broken)).toBeNull();
  });

  it('rejects a missing projectPath (triage would have nothing to confine reads to)', () => {
    const { projectPath: _omitted, ...rest } = validReport;
    expect(parseReport(rest)).toBeNull();
  });

  it('rejects a report without projectMeta (HTML/CLI renderers dereference it unconditionally)', () => {
    const { projectMeta: _omitted, ...rest } = validReport;
    expect(parseReport(rest)).toBeNull();
  });

  it('rejects a projectMeta missing the fields the renderers touch', () => {
    const broken = { ...validReport, projectMeta: { stack: { primary: 'ts' } } };
    expect(parseReport(broken)).toBeNull();
  });

  it('rejects aiTriage verdicts without a findingKey (renderers index by it)', () => {
    const broken = { ...validReport, aiTriage: { verdicts: [{ classification: 'real' }], summary: {} } };
    expect(parseReport(broken)).toBeNull();
  });

  it('rejects aiRemediation entries without fix text', () => {
    const broken = { ...validReport, aiRemediation: [{ findingKey: 'SEC-001|src/a.ts|3' }] };
    expect(parseReport(broken)).toBeNull();
  });

  it('accepts valid aiTriage, aiRemediation, and suppressed sections', () => {
    const full = {
      ...validReport,
      aiTriage: {
        verdicts: [{ findingKey: 'SEC-001|src/a.ts|3', classification: 'real', confidence: 0.9, reasoning: 'r' }],
        summary: { real: 1, falsePositive: 0, uncertain: 0 },
      },
      aiRemediation: [{ findingKey: 'SEC-001|src/a.ts|3', fix: 'do x', effort: 'low' }],
      suppressed: [{ finding: validFinding, reason: 'accepted risk' }],
      suppressionWarnings: ['stale entry'],
    };
    expect(parseReport(full)).not.toBeNull();
  });
});

describe('parseReportDetailed', () => {
  it('returns the report on success', () => {
    const r = parseReportDetailed(validReport);
    expect('report' in r).toBe(true);
  });

  it('returns human-readable reasons on failure', () => {
    const r = parseReportDetailed({ projectName: 'x' });
    if (!('errors' in r)) throw new Error('expected errors');
    expect(r.errors.length).toBeGreaterThan(0);
    expect(r.errors.some((e) => e.includes('projectPath') || e.includes('overallScore'))).toBe(true);
  });
});

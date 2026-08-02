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

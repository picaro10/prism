import { describe, it, expect } from 'vitest';
import { formatSarifReport } from '../../src/reporters/sarif.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X-001', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}
function report(findings: Finding[]): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '',
    durationMs: 0,
    overallScore: 7,
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

describe('formatSarifReport', () => {
  it('produces a valid SARIF 2.1.0 document', () => {
    const doc = JSON.parse(
      formatSarifReport(report([finding({ id: 'SEC-1', file: 'src/a.ts', line: 5, severity: 'critical' })])),
    );
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs[0].tool.driver.name).toBe('PRISM');
    expect(doc.runs[0].tool.driver.version).toBe('1.0.0');
    const result = doc.runs[0].results[0];
    expect(result.ruleId).toBe('SEC-1');
    expect(result.level).toBe('error'); // critical → error
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('src/a.ts');
    expect(result.locations[0].physicalLocation.region.startLine).toBe(5);
  });

  it('maps severities to the three SARIF levels', () => {
    const doc = JSON.parse(
      formatSarifReport(
        report([
          finding({ id: 'A', severity: 'critical', file: 'a.ts', line: 1 }),
          finding({ id: 'B', severity: 'medium', file: 'b.ts', line: 1 }),
          finding({ id: 'C', severity: 'low', file: 'c.ts', line: 1 }),
        ]),
      ),
    );
    const levels = Object.fromEntries(
      doc.runs[0].results.map((r: { ruleId: string; level: string }) => [r.ruleId, r.level]),
    );
    expect(levels).toEqual({ A: 'error', B: 'warning', C: 'note' });
  });

  it('deduplicates rules (one per finding id) but keeps every result', () => {
    const doc = JSON.parse(
      formatSarifReport(
        report([finding({ id: 'DUP', file: 'a.ts', line: 1 }), finding({ id: 'DUP', file: 'b.ts', line: 2 })]),
      ),
    );
    expect(doc.runs[0].tool.driver.rules).toHaveLength(1); // one rule 'DUP'
    expect(doc.runs[0].results).toHaveLength(2); // two results
  });

  it('omits locations for project-level findings (no file)', () => {
    const doc = JSON.parse(formatSarifReport(report([finding({ id: 'TST-001', file: undefined })])));
    expect(doc.runs[0].results[0].locations).toBeUndefined();
  });

  it('carries security-severity for GitHub alert ranking', () => {
    const doc = JSON.parse(formatSarifReport(report([finding({ id: 'SEC-1', severity: 'critical' })])));
    expect(doc.runs[0].tool.driver.rules[0].properties['security-severity']).toBe('9.5');
  });
});

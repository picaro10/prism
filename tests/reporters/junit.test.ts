import { describe, it, expect } from 'vitest';
import { formatJunitReport, escapeXml } from '../../src/reporters/junit.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X-001', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}
function report(p: Partial<AuditReport> = {}): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '',
    durationMs: 0,
    overallScore: 7,
    categories: [
      {
        category: 'security',
        score: 5,
        maxScore: 10,
        findings: [finding({ id: 'SEC-1', file: 'a.ts', line: 3 })],
        summary: '',
      },
      { category: 'docker', score: 10, maxScore: 10, findings: [], summary: '' },
    ],
    findings: [finding({ id: 'SEC-1', file: 'a.ts', line: 3 })],
    projectMeta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 0,
      totalFiles: 0,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
    prismVersion: '1.11.0',
    ...p,
  };
}

describe('escapeXml', () => {
  it('escapes the five XML-significant characters', () => {
    expect(escapeXml(`<a b="c" d='e' & f>`)).toBe('&lt;a b=&quot;c&quot; d=&apos;e&apos; &amp; f&gt;');
  });
});

describe('formatJunitReport', () => {
  it('emits one testsuite per category and one failing testcase per finding', () => {
    const xml = formatJunitReport(report());
    expect(xml).toMatch(/^<\?xml version="1\.0"/);
    expect(xml).toContain('<testsuites name="PRISM demo" tests="1" failures="1">');
    expect(xml).toContain('<testsuite name="security" tests="1" failures="1">');
    expect(xml).toContain('classname="prism.security"');
    expect(xml).toContain('SEC-1');
    // clean category → empty suite, no testcase
    expect(xml).toContain('<testsuite name="docker" tests="0" failures="0"></testsuite>');
  });

  it('escapes hostile finding content (no XML injection)', () => {
    const xml = formatJunitReport(
      report({
        findings: [finding({ title: '</failure><script>x</script>', description: 'a & b < c' })],
        categories: [
          {
            category: 'security',
            score: 0,
            maxScore: 10,
            findings: [finding({ title: '</failure><script>x</script>', description: 'a & b < c' })],
            summary: '',
          },
        ],
      }),
    );
    expect(xml).not.toContain('<script>x</script>');
    expect(xml).toContain('&lt;/failure&gt;');
    expect(xml).toContain('a &amp; b &lt; c');
  });
});

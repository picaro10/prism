import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { formatHtmlReport, writeHtmlReport, escapeHtml } from '../../src/reporters/html.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X-001', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}

function report(p: Partial<AuditReport> = {}): AuditReport {
  return {
    projectName: 'demo-app',
    projectPath: '/demo',
    startedAt: '2026-06-11T10:00:00.000Z',
    completedAt: '2026-06-11T10:00:01.000Z',
    durationMs: 1000,
    overallScore: 7.5,
    categories: [
      { category: 'security', score: 9.1, maxScore: 10, findings: [], summary: 'sec ok' },
      { category: 'tests', score: 4.2, maxScore: 10, findings: [finding({})], summary: 'low ratio' },
    ],
    findings: [],
    projectMeta: {
      stack: { primary: 'typescript', secondary: ['python'] },
      totalLoc: 1000,
      totalFiles: 42,
      hasGit: true,
      hasDocker: false,
      hasCi: true,
      packageManager: 'npm',
      frameworks: ['Express'],
    },
    prismVersion: '1.7.0',
    ...p,
  };
}

describe('escapeHtml', () => {
  it('escapes the five HTML-significant characters', () => {
    expect(escapeHtml(`<img src="x" onerror='a&b'>`)).toBe('&lt;img src=&quot;x&quot; onerror=&#39;a&amp;b&#39;&gt;');
  });
});

describe('formatHtmlReport', () => {
  it('renders a self-contained document with project, score, and categories', () => {
    const html = formatHtmlReport(report());
    expect(html).toMatch(/^<!doctype html>/);
    expect(html).toContain('demo-app');
    expect(html).toContain('7.5/10');
    expect(html).toContain('security');
    expect(html).toContain('Express');
    expect(html).not.toMatch(/<script\b/); // no JS, no external assets
    expect(html).not.toMatch(/\bsrc=|href=/); // nothing fetched from outside
  });

  it('escapes hostile content from findings', () => {
    const hostile = finding({
      title: '<script>alert(1)</script>',
      description: 'value is "<b>x</b>"',
      file: 'src/<evil>.ts',
    });
    const html = formatHtmlReport(report({ findings: [hostile] }));
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('src/&lt;evil&gt;.ts');
  });

  it('coerces numeric fields so a crafted JSON cannot inject via a numeric slot', () => {
    // A tampered report file (loaded by the dashboard) with a string where a
    // number belongs must not reach the HTML unescaped.
    const evilScore = '<script>alert(1)</script>' as unknown as number;
    const html = formatHtmlReport(
      report({
        overallScore: evilScore,
        durationMs: '"><img src=x onerror=alert(1)>' as unknown as number,
        findings: [finding({ file: 'src/a.ts', line: '<script>x</script>' as unknown as number })],
      }),
    );
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).not.toContain('onerror=');
    expect(html).not.toContain('<script>x</script>');
  });

  it('groups findings by severity in order', () => {
    const html = formatHtmlReport(
      report({ findings: [finding({ id: 'L', severity: 'low' }), finding({ id: 'C', severity: 'critical' })] }),
    );
    expect(html.indexOf('Critical (1)')).toBeGreaterThan(-1);
    expect(html.indexOf('Critical (1)')).toBeLessThan(html.indexOf('Low (1)'));
  });

  it('renders AI verdicts, fixes, summary and the triage tally when present', () => {
    const f = finding({ id: 'SEC-001', file: 'src/a.ts', line: 3 });
    const html = formatHtmlReport(
      report({
        findings: [f],
        aiSummary: 'Overall the project is healthy.',
        aiTriage: {
          verdicts: [
            {
              findingKey: 'SEC-001|src/a.ts|3',
              classification: 'real',
              confidence: 0.9,
              reasoning: 'hardcoded token [panel: 2 real · 1 fp · 0 uncertain]',
            },
          ],
          summary: { real: 1, falsePositive: 0, uncertain: 0 },
        },
        aiRemediation: [{ findingKey: 'SEC-001|src/a.ts|3', fix: 'move it to .env', effort: 'low' }],
      }),
    );
    expect(html).toContain('AI Assessment');
    expect(html).toContain('Overall the project is healthy.');
    expect(html).toContain('✓ real (90%)');
    expect(html).toContain('[panel: 2 real · 1 fp · 0 uncertain]');
    expect(html).toContain('move it to .env');
    expect(html).toContain('low effort');
    expect(html).toContain('1 real · 0 false positives · 0 uncertain');
    expect(html).toContain('1/1 confirmed-real findings got a fix proposal');
  });

  it('omits AI sections entirely when the report has no AI data', () => {
    const html = formatHtmlReport(report({ findings: [finding({})] }));
    expect(html).not.toContain('AI Assessment');
    expect(html).not.toContain('AI triage:');
    expect(html).not.toContain('🔧');
  });

  it('celebrates a clean project', () => {
    const html = formatHtmlReport(report());
    expect(html).toContain('No issues found');
  });
});

describe('writeHtmlReport', () => {
  let dir: string;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('creates missing parent directories', async () => {
    dir = await mkdtemp(join(tmpdir(), 'prism-html-'));
    const out = join(dir, 'nested', 'report.html');
    await writeHtmlReport(report(), out);
    const saved = await readFile(out, 'utf-8');
    expect(saved).toContain('demo-app');
  });
});

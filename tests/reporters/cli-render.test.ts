import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderCliReport } from '../../src/reporters/cli.js';
import type { AuditReport } from '../../src/core/types.js';

function baseReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/tmp/demo',
    startedAt: '2026-08-02T10:00:00Z',
    completedAt: '2026-08-02T10:00:01Z',
    durationMs: 1000,
    overallScore: 7.4,
    categories: [
      { category: 'security', score: 6.5, maxScore: 10, findings: [], summary: 'sec summary' },
      {
        category: 'docker',
        score: 10,
        maxScore: 10,
        findings: [],
        summary: 'No Docker configuration found (N/A — not scored)',
        applicable: false,
      },
    ],
    findings: [
      {
        id: 'SEC-001',
        category: 'security',
        severity: 'high',
        title: 'Hardcoded credential',
        description: 'd',
        file: 'src/a.ts',
        line: 4,
      },
    ],
    projectMeta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 0,
      totalFiles: 3,
      hasGit: true,
      hasDocker: false,
      hasCi: true,
      packageManager: 'npm',
      frameworks: ['Vitest'],
    },
    prismVersion: '1.2.1',
    ...overrides,
  };
}

let lines: string[];

beforeEach(() => {
  lines = [];
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.join(' '));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

const output = () => lines.join('\n');

describe('renderCliReport', () => {
  it('renders header, overall score and category breakdown', () => {
    renderCliReport(baseReport());
    expect(output()).toContain('PRISM Audit Report');
    expect(output()).toContain('7.4/10');
    expect(output()).toContain('security');
  });

  it('renders non-applicable categories as N/A, never as a scored bar', () => {
    renderCliReport(baseReport());
    expect(output()).toContain('N/A');
    expect(output()).toContain('(nothing to analyze)');
    // the docker row must NOT show 10/10
    const dockerLine = lines.find((l) => l.includes('docker'));
    expect(dockerLine).toBeDefined();
    expect(dockerLine).not.toContain('10/10');
  });

  it('lists findings grouped by severity with file locations', () => {
    renderCliReport(baseReport());
    expect(output()).toContain('HIGH');
    expect(output()).toContain('SEC-001');
    expect(output()).toContain('src/a.ts:4');
  });

  it('celebrates a clean report', () => {
    renderCliReport(baseReport({ findings: [] }));
    expect(output()).toContain('No issues found');
  });

  it('surfaces a category coverage gap under the score bar (not just in JSON)', () => {
    renderCliReport(
      baseReport({
        categories: [
          {
            category: 'security',
            score: 10,
            maxScore: 10,
            findings: [],
            summary: '3 files scanned for secrets · 2 unreadable (not scanned) · No secrets detected',
          },
        ],
      }),
    );
    expect(output()).toContain('2 unreadable (not scanned)');
  });

  it('shows suppressed findings with their reasons', () => {
    renderCliReport(
      baseReport({
        suppressed: [
          {
            finding: { id: 'AGT-001', category: 'agentic', severity: 'high', title: 't', description: 'd' },
            reason: 'accepted risk',
          },
        ],
      }),
    );
    expect(output()).toContain('suppressed by config');
    expect(output()).toContain('accepted risk');
  });

  it('renders AI triage tallies when present', () => {
    renderCliReport(
      baseReport({
        aiTriage: {
          model: 'm',
          verdicts: [],
          summary: { real: 2, falsePositive: 1, uncertain: 0 },
        } as AuditReport['aiTriage'],
      }),
    );
    expect(output()).toContain('AI triage:');
    expect(output()).toContain('2 real');
  });
});

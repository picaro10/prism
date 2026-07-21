import { describe, it, expect } from 'vitest';
import { buildSummaryDigest, runSummary } from '../../src/ai/summarize.js';
import { findingKey } from '../../src/ai/types.js';
import type { LLMClient, TriageUnit, Verdict, ProjectContext } from '../../src/ai/types.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}

function report(findings: Finding[], verdicts?: Verdict[]): AuditReport {
  return {
    projectName: 'demo-proj',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '',
    durationMs: 0,
    overallScore: 6.5,
    categories: [{ category: 'security', score: 8, maxScore: 10, findings: [], summary: 'sec clean' }],
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
    prismVersion: '1.2.0',
    aiTriage: verdicts
      ? {
          verdicts,
          summary: {
            real: verdicts.filter((v) => v.classification === 'real').length,
            falsePositive: verdicts.filter((v) => v.classification === 'false-positive').length,
            uncertain: verdicts.filter((v) => v.classification === 'uncertain').length,
          },
        }
      : undefined,
  };
}

describe('buildSummaryDigest', () => {
  it('includes project name, overall score and category scores', () => {
    const d = buildSummaryDigest(report([]));
    expect(d).toMatch(/demo-proj/);
    expect(d).toMatch(/6\.5\/10/);
    expect(d).toMatch(/security: 8\/10 — sec clean/);
  });

  it('lists real findings but excludes confirmed false positives', () => {
    const real = finding({ id: 'SEC-REAL', file: 'src/a.ts', title: 'Real issue' });
    const fp = finding({ id: 'SEC-FP', file: 'src/b.ts', title: 'Not an issue' });
    const verdicts: Verdict[] = [
      { findingKey: findingKey(real), classification: 'real', confidence: 0.9, reasoning: 'r' },
      { findingKey: findingKey(fp), classification: 'false-positive', confidence: 0.9, reasoning: 'fp' },
    ];
    const d = buildSummaryDigest(report([real, fp], verdicts));
    expect(d).toMatch(/SEC-REAL/);
    expect(d).toMatch(/\[real\]/);
    expect(d).not.toMatch(/SEC-FP/); // confirmed FP excluded
    expect(d).toMatch(/AI triage: 1 real · 1 false positives · 0 uncertain/);
  });

  it('includes all findings when there was no triage', () => {
    const d = buildSummaryDigest(report([finding({ id: 'A' }), finding({ id: 'B' })]));
    expect(d).toMatch(/\bA\b/);
    expect(d).toMatch(/\bB\b/);
  });
});

class FakeSummaryClient implements LLMClient {
  receivedDigest = '';
  async triage(_u: TriageUnit, _c: ProjectContext): Promise<Verdict[]> {
    return [];
  }
  async verify(_u: TriageUnit, _c: ProjectContext): Promise<Verdict[]> {
    return [];
  }
  async summarize(digest: string, _c: ProjectContext): Promise<string> {
    this.receivedDigest = digest;
    return 'The project is in solid shape; the one real issue is X.';
  }
  async remediate(_u: TriageUnit, _c: ProjectContext): Promise<never[]> {
    return [];
  }
}

describe('runSummary', () => {
  it('returns the model prose and feeds it the report digest', async () => {
    const real = finding({ id: 'SEC-REAL', title: 'Real issue' });
    const client = new FakeSummaryClient();
    const text = await runSummary(report([real]), client);
    expect(text).toMatch(/solid shape/);
    expect(client.receivedDigest).toMatch(/demo-proj/);
    expect(client.receivedDigest).toMatch(/SEC-REAL/);
  });
});

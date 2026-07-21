import { describe, it, expect } from 'vitest';
import { applyAiTriage } from '../../src/ai/run.js';
import { findingKey } from '../../src/ai/types.js';
import type { LLMClient, TriageUnit, Verdict, Remediation, ProjectContext } from '../../src/ai/types.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function report(findings: Finding[]): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '',
    durationMs: 0,
    overallScore: 7,
    categories: [{ category: 'security', score: 8, maxScore: 10, findings: [], summary: 's' }],
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
    prismVersion: '1.3.0',
  };
}

const finding: Finding = {
  id: 'A',
  category: 'security',
  severity: 'high',
  title: 't',
  description: 'd',
  file: 'src/a.ts',
};
const reader = async (p: string) => `// ${p}`;

class Fake implements LLMClient {
  summarizeCalls = 0;
  remediateCalls = 0;
  constructor(private opts: { triageThrows?: boolean } = {}) {}
  async triage(unit: TriageUnit, _c: ProjectContext): Promise<Verdict[]> {
    if (this.opts.triageThrows) throw new Error('boom');
    return unit.findings.map((f) => ({
      findingKey: findingKey(f),
      classification: 'real',
      confidence: 0.9,
      reasoning: 'r',
    }));
  }
  async verify(unit: TriageUnit, _c: ProjectContext): Promise<Verdict[]> {
    return unit.findings.map((f) => ({
      findingKey: findingKey(f),
      classification: 'real',
      confidence: 0.9,
      reasoning: 'r',
    }));
  }
  async summarize(_d: string, _c: ProjectContext): Promise<string> {
    this.summarizeCalls++;
    return 'assessment prose';
  }
  async remediate(unit: TriageUnit, _c: ProjectContext): Promise<Remediation[]> {
    this.remediateCalls++;
    return unit.findings.map((f) => ({ findingKey: findingKey(f), fix: `fix ${f.id}`, effort: 'low' as const }));
  }
}

describe('applyAiTriage', () => {
  it('attaches triage verdicts, remediation fixes, and an executive summary', async () => {
    const r = report([finding]);
    await applyAiTriage(r, reader, {}, undefined, new Fake());
    expect(r.aiTriage?.verdicts).toHaveLength(1);
    expect(r.aiTriage?.summary.real).toBe(1);
    expect(r.aiRemediation).toHaveLength(1);
    expect(r.aiRemediation?.[0].fix).toBe('fix A');
    expect(r.aiSummary).toBe('assessment prose');
  });

  it('skips remediation when aiRemediate is false', async () => {
    const r = report([finding]);
    const fake = new Fake();
    await applyAiTriage(r, reader, { aiRemediate: false }, undefined, fake);
    expect(r.aiTriage).toBeDefined();
    expect(r.aiRemediation).toBeUndefined();
    expect(fake.remediateCalls).toBe(0);
    expect(r.aiSummary).toBe('assessment prose'); // summary still runs
  });

  it('skips the summary when aiSummary is false', async () => {
    const r = report([finding]);
    const fake = new Fake();
    await applyAiTriage(r, reader, { aiSummary: false }, undefined, fake);
    expect(r.aiTriage).toBeDefined();
    expect(r.aiSummary).toBeUndefined();
    expect(fake.summarizeCalls).toBe(0);
  });

  it('swallows failures so the static report survives', async () => {
    const r = report([finding]);
    const messages: string[] = [];
    await applyAiTriage(r, reader, {}, (m) => messages.push(m), new Fake({ triageThrows: true }));
    expect(r.aiTriage).toBeUndefined();
    expect(r.aiRemediation).toBeUndefined();
    expect(r.aiSummary).toBeUndefined();
    expect(messages.some((m) => m.startsWith('AI triage failed'))).toBe(true);
  });
});

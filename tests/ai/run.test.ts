import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

  describe('verdict cache wiring', () => {
    const withCacheDir = async (fn: () => Promise<void>) => {
      const prev = process.env.PRISM_CACHE_DIR;
      process.env.PRISM_CACHE_DIR = mkdtempSync(join(tmpdir(), 'prism-run-cache-'));
      try {
        await fn();
      } finally {
        // biome-ignore lint/performance/noDelete: unsetting an env var needs delete — assigning undefined stores the string "undefined"
        if (prev === undefined) delete process.env.PRISM_CACHE_DIR;
        else process.env.PRISM_CACHE_DIR = prev;
      }
    };

    it('reuses verdicts and fixes across runs when a cacheRoot is given', () =>
      withCacheDir(async () => {
        const root = mkdtempSync(join(tmpdir(), 'prism-run-root-'));
        const r1 = report([finding]);
        await applyAiTriage(r1, reader, {}, undefined, new Fake(), root);
        expect(r1.aiTriage?.summary.cached).toBe(0);

        const r2 = report([finding]);
        const second = new Fake();
        const messages: string[] = [];
        await applyAiTriage(r2, reader, {}, (m) => messages.push(m), second, root);
        expect(r2.aiTriage?.summary.cached).toBe(1);
        expect(second.remediateCalls).toBe(0);
        expect(r2.aiRemediation).toHaveLength(1);
        expect(messages).toContain('AI triage complete (1 from cache)');
      }));

    it('does not cache without a cacheRoot, with aiCache=false, or on a dry run', () =>
      withCacheDir(async () => {
        const root = mkdtempSync(join(tmpdir(), 'prism-run-root-'));
        const r1 = report([finding]);
        await applyAiTriage(r1, reader, {}, undefined, new Fake());
        expect(r1.aiTriage?.summary.cached).toBeUndefined();

        const r2 = report([finding]);
        await applyAiTriage(r2, reader, { aiCache: false }, undefined, new Fake(), root);
        expect(r2.aiTriage?.summary.cached).toBeUndefined();

        const r3 = report([finding]);
        await applyAiTriage(r3, reader, { aiDryRun: true }, undefined, new Fake(), root);
        expect(r3.aiTriage?.summary.cached).toBeUndefined();
      }));
  });
});

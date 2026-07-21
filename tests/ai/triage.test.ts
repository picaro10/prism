import { describe, it, expect } from 'vitest';
import { runTriage } from '../../src/ai/triage.js';
import { findingKey } from '../../src/ai/types.js';
import type { LLMClient, TriageUnit, Verdict, ProjectContext } from '../../src/ai/types.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}

function report(findings: Finding[]): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '',
    durationMs: 0,
    overallScore: 7,
    categories: [{ category: 'security', score: 8, maxScore: 10, findings: [], summary: 'sec ok' }],
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

class FakeClient implements LLMClient {
  units: TriageUnit[] = [];
  contexts: ProjectContext[] = [];
  verifyUnits: TriageUnit[] = [];
  // verifyFn defaults to fn, so verify confirms whatever triage said.
  constructor(
    private fn: (u: TriageUnit) => Verdict[],
    private verifyFn: (u: TriageUnit) => Verdict[] = fn,
  ) {}
  async triage(unit: TriageUnit, ctx: ProjectContext): Promise<Verdict[]> {
    this.units.push(unit);
    this.contexts.push(ctx);
    return this.fn(unit);
  }
  async verify(unit: TriageUnit, _ctx: ProjectContext): Promise<Verdict[]> {
    this.verifyUnits.push(unit);
    return this.verifyFn(unit);
  }
  async summarize(_digest: string, _ctx: ProjectContext): Promise<string> {
    return 'summary';
  }
  async remediate(_unit: TriageUnit, _ctx: ProjectContext): Promise<never[]> {
    return [];
  }
}

const reader = async (p: string) => `// content of ${p}`;

describe('runTriage', () => {
  it('groups findings by file (one call per file + one for project-level)', async () => {
    const findings = [
      finding({ id: 'A', file: 'src/a.ts', line: 1 }),
      finding({ id: 'B', file: 'src/a.ts', line: 2 }),
      finding({ id: 'C', file: 'src/b.ts', line: 1 }),
      finding({ id: 'D' }),
    ];
    const client = new FakeClient((u) =>
      u.findings.map((f) => ({ findingKey: findingKey(f), classification: 'real', confidence: 0.9, reasoning: 'r' })),
    );
    await runTriage(report(findings), reader, client);
    expect(client.units).toHaveLength(3);
    const aUnit = client.units.find((u) => u.file === 'src/a.ts')!;
    expect(aUnit.findings).toHaveLength(2);
    expect(aUnit.content).toBe('// content of src/a.ts');
    const projUnit = client.units.find((u) => u.file === null)!;
    expect(projUnit.findings).toHaveLength(1);
    expect(projUnit.content).toBe('');
  });

  it('flattens verdicts and computes summary counts', async () => {
    const findings = [
      finding({ id: 'A', file: 'src/a.ts' }),
      finding({ id: 'B', file: 'src/b.ts' }),
      finding({ id: 'C', file: 'src/c.ts' }),
    ];
    const verdictByFile: Record<string, Verdict['classification']> = {
      'src/a.ts': 'real',
      'src/b.ts': 'false-positive',
      'src/c.ts': 'uncertain',
    };
    const client = new FakeClient((u) =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: verdictByFile[u.file!],
        confidence: 0.8,
        reasoning: 'r',
      })),
    );
    const result = await runTriage(report(findings), reader, client);
    expect(result.summary).toEqual({ real: 1, falsePositive: 1, uncertain: 1 });
    expect(result.verdicts).toHaveLength(3);
  });

  it('synthesizes an uncertain verdict for a finding the model did not return', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' }), finding({ id: 'B', file: 'src/a.ts' })];
    const client = new FakeClient((u) => [
      { findingKey: findingKey(u.findings[0]), classification: 'real', confidence: 0.9, reasoning: 'r' },
      { findingKey: 'BOGUS|x|1', classification: 'real', confidence: 0.5, reasoning: 'noise' },
    ]);
    const result = await runTriage(report(findings), reader, client);
    expect(result.verdicts).toHaveLength(2);
    const second = result.verdicts.find((v) => v.findingKey === findingKey(findings[1]))!;
    expect(second.classification).toBe('uncertain');
    expect(second.confidence).toBe(0);
    expect(result.verdicts.find((v) => v.findingKey === 'BOGUS|x|1')).toBeUndefined();
  });

  it('aligns a verdict whose echoed key lost its trailing pipes', async () => {
    // STR-011-style finding without a line — its key ends in '|', which
    // models routinely trim when echoing back.
    const findings = [finding({ id: 'STR-011', file: 'src/big.py' })];
    const client = new FakeClient(() => [
      { findingKey: 'STR-011|src/big.py', classification: 'real', confidence: 0.9, reasoning: 'r' },
    ]);
    const result = await runTriage(report(findings), reader, client);
    expect(result.verdicts[0].classification).toBe('real'); // not a synthesized uncertain
    expect(result.verdicts[0].findingKey).toBe('STR-011|src/big.py|'); // canonical key restored
  });

  it('triages a file even when reading it fails', async () => {
    const findings = [finding({ id: 'A', file: 'src/missing.ts' })];
    const failReader = async () => {
      throw new Error('ENOENT');
    };
    const client = new FakeClient((u) =>
      u.findings.map((f) => ({ findingKey: findingKey(f), classification: 'real', confidence: 1, reasoning: 'r' })),
    );
    const result = await runTriage(report(findings), failReader, client);
    expect(client.units[0].content).toBe('');
    expect(result.verdicts).toHaveLength(1);
  });

  it('keeps a false-positive only when the verify pass confirms it', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const fp = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'false-positive',
        confidence: 0.9,
        reasoning: 'fp',
      }));
    // verify also says FP → confirmed
    const client = new FakeClient(fp, fp);
    const result = await runTriage(report(findings), reader, client);
    expect(result.verdicts[0].classification).toBe('false-positive');
    expect(client.verifyUnits).toHaveLength(1); // verify ran on the FP
  });

  it('downgrades a false-positive the verify pass does not confirm', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const firstFP = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'false-positive',
        confidence: 0.9,
        reasoning: 'lenient fp',
      }));
    // skeptical verify says it is actually real (caught the bad FP)
    const verifyReal = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'real',
        confidence: 0.8,
        reasoning: 'concrete evidence: real',
      }));
    const client = new FakeClient(firstFP, verifyReal);
    const result = await runTriage(report(findings), reader, client);
    expect(result.verdicts[0].classification).toBe('real');
    expect(result.summary).toEqual({ real: 1, falsePositive: 0, uncertain: 0 });
  });

  it('does not run the verify pass when verify is disabled', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const fp = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'false-positive',
        confidence: 0.9,
        reasoning: 'fp',
      }));
    const client = new FakeClient(fp);
    const result = await runTriage(report(findings), reader, client, { verify: false });
    expect(result.verdicts[0].classification).toBe('false-positive');
    expect(client.verifyUnits).toHaveLength(0);
  });

  it('lets a verifier panel out-vote a false positive (majority real wins)', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const fp = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'false-positive',
        confidence: 1,
        reasoning: 'looks fine',
      }));
    const real = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'real',
        confidence: 0.8,
        reasoning: 'still an issue',
      }));
    const client = new FakeClient(fp, fp); // triage says FP; this client also votes FP
    const voterReal1 = new FakeClient(real, real);
    const voterReal2 = new FakeClient(real, real);
    const result = await runTriage(report(findings), reader, client, {
      verifiers: [client, voterReal1, voterReal2],
    });
    expect(result.verdicts[0].classification).toBe('real');
    expect(result.verdicts[0].reasoning).toMatch(/\[panel: 2 real · 1 fp · 0 uncertain\]/);
    expect(result.summary).toEqual({ real: 1, falsePositive: 0, uncertain: 0 });
  });

  it('confirms a false positive when the panel is unanimous', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const fp = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'false-positive',
        confidence: 0.9,
        reasoning: 'benign',
      }));
    const client = new FakeClient(fp, fp);
    const result = await runTriage(report(findings), reader, client, {
      verifiers: [client, new FakeClient(fp, fp), new FakeClient(fp, fp)],
    });
    expect(result.verdicts[0].classification).toBe('false-positive');
  });

  it('a voter that throws abstains as uncertain instead of killing the triage', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const fp = (u: TriageUnit): Verdict[] =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'false-positive',
        confidence: 1,
        reasoning: 'fp',
      }));
    const boom = () => {
      throw new Error('rate limited');
    };
    const client = new FakeClient(fp, fp);
    // panel: 1 fp + 2 crashed voters (abstain as uncertain) → fp has no majority → uncertain
    const result = await runTriage(report(findings), reader, client, {
      verifiers: [client, new FakeClient(fp, boom), new FakeClient(fp, boom)],
    });
    expect(result.verdicts[0].classification).toBe('uncertain');
    expect(result.summary.uncertain).toBe(1);
  });

  it('does not run the verify pass when there are no false-positives', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const client = new FakeClient((u) =>
      u.findings.map((f) => ({ findingKey: findingKey(f), classification: 'real', confidence: 1, reasoning: 'r' })),
    );
    await runTriage(report(findings), reader, client);
    expect(client.verifyUnits).toHaveLength(0);
  });

  it('gives distinct verdicts to findings that would share a key (no collapse)', async () => {
    // Two DEP-002 on package.json with no line — same base key. The model judges
    // one real and one FP; without instance disambiguation both would collapse.
    const findings = [
      finding({ id: 'DEP-002', file: 'package.json', title: 'lodash wildcard' }),
      finding({ id: 'DEP-002', file: 'package.json', title: 'express wildcard' }),
    ];
    const client = new FakeClient((u) =>
      u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: f.title.includes('lodash') ? ('real' as const) : ('false-positive' as const),
        confidence: 0.9,
        reasoning: 'r',
      })),
    );
    const result = await runTriage(report(findings), reader, client, { verify: false });
    const byKey = new Map(result.verdicts.map((v) => [v.findingKey, v]));
    expect(result.verdicts).toHaveLength(2);
    expect(byKey.get('DEP-002|package.json|')?.classification).toBe('real');
    expect(byKey.get('DEP-002|package.json|#1')?.classification).toBe('false-positive');
  });

  it('survives a triage call that throws for one group (others keep their verdicts)', async () => {
    const findings = [
      finding({ id: 'A', file: 'src/a.ts', line: 1 }),
      finding({ id: 'B', file: 'src/bad.ts', line: 1 }),
    ];
    // The client throws only for src/bad.ts; src/a.ts must still get a verdict.
    const client = new FakeClient((u) => {
      if (u.file === 'src/bad.ts') throw new Error('rate limit');
      return u.findings.map((f) => ({
        findingKey: findingKey(f),
        classification: 'real' as const,
        confidence: 0.9,
        reasoning: 'r',
      }));
    });
    const result = await runTriage(report(findings), reader, client, { verify: false });
    const byKey = new Map(result.verdicts.map((v) => [v.findingKey, v]));
    expect(byKey.get(findingKey(findings[0]))?.classification).toBe('real');
    expect(byKey.get(findingKey(findings[1]))?.classification).toBe('uncertain');
    expect(result.verdicts).toHaveLength(2);
  });
});

import { describe, it, expect } from 'vitest';
import { runTriage, MAX_BATCH_FINDINGS } from '../../src/ai/triage.js';
import { findingKey } from '../../src/ai/types.js';
import type { LLMClient, TriageUnit, Verdict, ProjectContext } from '../../src/ai/types.js';
import type { AuditReport, Finding } from '../../src/core/types.js';
import { VerdictCache } from '../../src/ai/cache.js';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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

/** A reader that records which files were actually read. */
function trackingReader() {
  const read: string[] = [];
  const fn = async (p: string) => {
    read.push(p);
    return `// content of ${p}`;
  };
  return { fn, read };
}

const realVerdicts = (u: TriageUnit): Verdict[] =>
  u.findings.map((f) => ({ findingKey: findingKey(f), classification: 'real', confidence: 0.9, reasoning: 'r' }));

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

  describe('context tiers', () => {
    it('batches "none"-tier findings without reading their files, even when they name one', async () => {
      const findings = [
        finding({ id: 'STR-011', category: 'structure', file: 'src/big.ts' }),
        finding({ id: 'DEP-OSV-HIGH', category: 'dependencies', file: 'requirements.txt' }),
        finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 3 }),
      ];
      const client = new FakeClient(realVerdicts);
      const r = trackingReader();
      const result = await runTriage(report(findings), r.fn, client);

      expect(client.units).toHaveLength(2);
      const fileUnit = client.units.find((u) => u.file === 'src/a.ts')!;
      expect(fileUnit.findings.map((f) => f.id)).toEqual(['SEC-AWS-KEY']);
      expect(fileUnit.content).toBe('// content of src/a.ts');
      const batch = client.units.find((u) => u.file === null)!;
      expect(batch.findings.map((f) => f.id).sort()).toEqual(['DEP-OSV-HIGH', 'STR-011']);
      expect(batch.content).toBe('');
      // The god file and the lockfile were never read — that is the token saving.
      expect(r.read).toEqual(['src/a.ts']);
      // Every finding still gets a verdict.
      expect(result.verdicts).toHaveLength(3);
    });

    it('splits one file across tiers: the code-judged finding gets the content, the fact-judged one is batched', async () => {
      const findings = [
        finding({ id: 'STR-011', category: 'structure', file: 'src/a.ts' }),
        finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 3 }),
      ];
      const client = new FakeClient(realVerdicts);
      await runTriage(report(findings), reader, client);
      const fileUnit = client.units.find((u) => u.file === 'src/a.ts')!;
      expect(fileUnit.findings.map((f) => f.id)).toEqual(['SEC-AWS-KEY']);
      const batch = client.units.find((u) => u.file === null)!;
      expect(batch.findings.map((f) => f.id)).toEqual(['STR-011']);
    });

    it('chunks the no-code batch so one giant advisory list never becomes one giant call', async () => {
      const findings = Array.from({ length: MAX_BATCH_FINDINGS * 2 + 1 }, (_, i) =>
        finding({ id: 'DEP-OSV-LOWER', category: 'dependencies', file: 'poetry.lock', title: `adv ${i}` }),
      );
      const client = new FakeClient(realVerdicts);
      const result = await runTriage(report(findings), reader, client);
      expect(client.units).toHaveLength(3);
      for (const u of client.units) {
        expect(u.file).toBeNull();
        expect(u.findings.length).toBeLessThanOrEqual(MAX_BATCH_FINDINGS);
      }
      expect(result.verdicts).toHaveLength(findings.length);
    });

    it('project-level findings (no file) share the batch with none-tier findings', async () => {
      const findings = [
        finding({ id: 'TST-001', category: 'tests' }),
        finding({ id: 'STR-011', category: 'structure', file: 'src/big.ts' }),
      ];
      const client = new FakeClient(realVerdicts);
      await runTriage(report(findings), reader, client);
      expect(client.units).toHaveLength(1);
      expect(client.units[0].file).toBeNull();
      expect(client.units[0].findings).toHaveLength(2);
    });

    it('the verify pass on a batched finding carries no content either', async () => {
      const findings = [finding({ id: 'DEP-002', category: 'dependencies', file: 'package.json' })];
      const client = new FakeClient((u) =>
        u.findings.map((f) => ({
          findingKey: findingKey(f),
          classification: 'false-positive',
          confidence: 0.8,
          reasoning: 'r',
        })),
      );
      await runTriage(report(findings), reader, client);
      expect(client.verifyUnits).toHaveLength(1);
      expect(client.verifyUnits[0].file).toBeNull();
      expect(client.verifyUnits[0].content).toBe('');
    });

    it('neighborhood tier reads the file like "file" tier until the neighborhood builder lands', async () => {
      const findings = [finding({ id: 'AGT-001', category: 'agentic', file: 'src/tool.ts', line: 9 })];
      const client = new FakeClient(realVerdicts);
      const r = trackingReader();
      await runTriage(report(findings), r.fn, client);
      expect(client.units).toHaveLength(1);
      expect(client.units[0].file).toBe('src/tool.ts');
      expect(client.units[0].content).toBe('// content of src/tool.ts');
      expect(r.read).toEqual(['src/tool.ts']);
    });
  });

  describe('verdict cache', () => {
    const freshCache = () => new VerdictCache(join(mkdtempSync(join(tmpdir(), 'prism-triage-cache-')), 'v.json'));

    it('reuses a final verdict for unchanged content and skips the call (and counts it)', async () => {
      const cache = freshCache();
      const findings = [finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 })];
      const c1 = new FakeClient(realVerdicts);
      const r1 = await runTriage(report(findings), reader, c1, { cache });
      expect(c1.units).toHaveLength(1);
      expect(r1.summary.cached).toBe(0);

      const c2 = new FakeClient(realVerdicts);
      const r2 = await runTriage(report(findings), reader, c2, { cache });
      expect(c2.units).toHaveLength(0); // no call at all
      expect(r2.summary).toEqual({ real: 1, falsePositive: 0, uncertain: 0, cached: 1 });
      expect(r2.verdicts[0].reasoning).toMatch(/\[cached\]$/);
    });

    it('misses when the file content changed', async () => {
      const cache = freshCache();
      const findings = [finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 })];
      await runTriage(report(findings), reader, new FakeClient(realVerdicts), { cache });
      const c2 = new FakeClient(realVerdicts);
      await runTriage(report(findings), async (p) => `// edited ${p}`, c2, { cache });
      expect(c2.units).toHaveLength(1);
    });

    it('misses when the judge (client id) differs', async () => {
      const cache = freshCache();
      const findings = [finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 })];
      const a = new FakeClient(realVerdicts);
      (a as unknown as { id: string }).id = 'fake:a';
      await runTriage(report(findings), reader, a, { cache });
      const b = new FakeClient(realVerdicts);
      (b as unknown as { id: string }).id = 'fake:b';
      await runTriage(report(findings), reader, b, { cache });
      expect(b.units).toHaveLength(1);
    });

    it('stores a false-positive only AFTER the verify pass, as the final verdict', async () => {
      const cache = freshCache();
      const findings = [finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 })];
      const fp = (u: TriageUnit): Verdict[] =>
        u.findings.map((f) => ({
          findingKey: findingKey(f),
          classification: 'false-positive',
          confidence: 0.8,
          reasoning: 'fp',
        }));
      // First pass says FP, the skeptical pass says real → final is real, and that is what gets cached.
      const c1 = new FakeClient(fp, realVerdicts);
      const r1 = await runTriage(report(findings), reader, c1, { cache });
      expect(r1.verdicts[0].classification).toBe('real');
      const c2 = new FakeClient(fp, realVerdicts);
      const r2 = await runTriage(report(findings), reader, c2, { cache });
      expect(c2.units).toHaveLength(0);
      expect(c2.verifyUnits).toHaveLength(0);
      expect(r2.verdicts[0].classification).toBe('real');
    });

    it('does not cache a verdict synthesized from a failed call or a skipped finding', async () => {
      const cache = freshCache();
      const findings = [
        finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 }),
        finding({ id: 'SEC-GH-PAT', file: 'src/b.ts', line: 1 }),
      ];
      // a.ts: the call throws; b.ts: the model answers nothing.
      const flaky = new FakeClient((u) => {
        if (u.file === 'src/a.ts') throw new Error('500');
        return [];
      });
      const r1 = await runTriage(report(findings), reader, flaky, { cache });
      expect(r1.verdicts.every((v) => v.classification === 'uncertain')).toBe(true);
      const c2 = new FakeClient(realVerdicts);
      await runTriage(report(findings), reader, c2, { cache });
      expect(c2.units).toHaveLength(2); // both judged again
    });

    it('does not freeze a panel decision reached with an abstaining (errored) voter', async () => {
      const cache = freshCache();
      const findings = [finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 })];
      const fp = (u: TriageUnit): Verdict[] =>
        u.findings.map((f) => ({
          findingKey: findingKey(f),
          classification: 'false-positive',
          confidence: 0.8,
          reasoning: 'fp',
        }));
      const dead: LLMClient = {
        triage: async () => [],
        verify: async () => {
          throw new Error('down');
        },
        summarize: async () => '',
        remediate: async () => [],
      };
      const c1 = new FakeClient(fp, fp);
      const r1 = await runTriage(report(findings), reader, c1, { cache, verifiers: [c1, dead] });
      expect(r1.verdicts[0].classification).toBe('uncertain'); // not unanimous
      const c2 = new FakeClient(fp, fp);
      await runTriage(report(findings), reader, c2, { cache, verifiers: [c2, dead] });
      expect(c2.units).toHaveLength(1); // judged again, not served from cache
    });

    it('a false-positive stored under --no-ai-verify is NOT reused by a run that verifies', async () => {
      const cache = freshCache();
      const findings = [finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 })];
      const fp = (u: TriageUnit): Verdict[] =>
        u.findings.map((f) => ({
          findingKey: findingKey(f),
          classification: 'false-positive',
          confidence: 0.8,
          reasoning: 'fp',
        }));
      const lenient = new FakeClient(fp, realVerdicts);
      const r1 = await runTriage(report(findings), reader, lenient, { cache, verify: false });
      expect(r1.verdicts[0].classification).toBe('false-positive'); // unverified, by request
      // Same judge, now WITH the skeptical pass: the unverified FP must not shortcut it.
      const skeptical = new FakeClient(fp, realVerdicts);
      const r2 = await runTriage(report(findings), reader, skeptical, { cache, verify: true });
      expect(skeptical.units).toHaveLength(1);
      expect(skeptical.verifyUnits).toHaveLength(1);
      expect(r2.verdicts[0].classification).toBe('real');
    });

    it('a run served entirely from cache is not "failed for every group"', async () => {
      const cache = freshCache();
      const findings = [finding({ id: 'SEC-AWS-KEY', file: 'src/a.ts', line: 1 })];
      await runTriage(report(findings), reader, new FakeClient(realVerdicts), { cache });
      const broken = new FakeClient(() => {
        throw new Error('no network');
      });
      await expect(runTriage(report(findings), reader, broken, { cache })).resolves.toBeDefined();
    });

    it('without a cache option the summary has no cached count (pre-cache shape)', async () => {
      const r = await runTriage(
        report([finding({ id: 'A', file: 'src/a.ts', line: 1 })]),
        reader,
        new FakeClient(realVerdicts),
      );
      expect(r.summary).toEqual({ real: 1, falsePositive: 0, uncertain: 0 });
    });
  });

  describe('neighborhood', () => {
    const files = {
      'src/validate.ts':
        'export function assertSafeRef(r: string) { if (!/^[\\w./-]+$/.test(r)) throw new Error("bad"); }\n',
      'src/git.ts':
        'import { assertSafeRef } from "./validate.js";\nexport const f = (r: string) => { assertSafeRef(r); return execSync(`git log ${r}`); };\n',
    } as Record<string, string>;
    const read = async (p: string) => {
      if (!(p in files)) throw new Error('ENOENT');
      return files[p];
    };

    it('attaches related files to a neighborhood-tier unit when the inventory is given', async () => {
      const client = new FakeClient(realVerdicts);
      await runTriage(report([finding({ id: 'AGT-001', file: 'src/git.ts', line: 2 })]), read, client, {
        files: Object.keys(files),
      });
      expect(client.units).toHaveLength(1);
      expect(client.units[0].neighbors?.map((n) => n.file)).toEqual(['src/validate.ts']);
    });

    it('attaches nothing without the inventory, or for a file-tier finding', async () => {
      const c1 = new FakeClient(realVerdicts);
      await runTriage(report([finding({ id: 'AGT-001', file: 'src/git.ts', line: 2 })]), read, c1);
      expect(c1.units[0].neighbors).toBeUndefined();
      const c2 = new FakeClient(realVerdicts);
      await runTriage(report([finding({ id: 'SEC-AWS-KEY', file: 'src/git.ts', line: 2 })]), read, c2, {
        files: Object.keys(files),
      });
      expect(c2.units[0].neighbors).toBeUndefined();
    });

    it('the verify pass sees the same related files', async () => {
      const fp = (u: TriageUnit): Verdict[] =>
        u.findings.map((f) => ({
          findingKey: findingKey(f),
          classification: 'false-positive',
          confidence: 0.8,
          reasoning: 'fp',
        }));
      const client = new FakeClient(fp, fp);
      await runTriage(report([finding({ id: 'AGT-001', file: 'src/git.ts', line: 2 })]), read, client, {
        files: Object.keys(files),
      });
      expect(client.verifyUnits[0].neighbors?.map((n) => n.file)).toEqual(['src/validate.ts']);
    });

    it('a cached verdict misses when a related file changes', async () => {
      const cache = new VerdictCache(join(mkdtempSync(join(tmpdir(), 'prism-nb-cache-')), 'v.json'));
      const findings = [finding({ id: 'AGT-001', file: 'src/git.ts', line: 2 })];
      await runTriage(report(findings), read, new FakeClient(realVerdicts), { cache, files: Object.keys(files) });
      const edited = {
        ...files,
        'src/validate.ts': 'export function assertSafeRef(r: string) { return r; } // weakened\n',
      };
      const readEdited = async (p: string) => edited[p];
      const c2 = new FakeClient(realVerdicts);
      await runTriage(report(findings), readEdited, c2, { cache, files: Object.keys(files) });
      expect(c2.units).toHaveLength(1); // judged again: the evidence changed even though git.ts did not
    });
  });
});

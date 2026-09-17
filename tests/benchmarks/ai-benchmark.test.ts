import { describe, it, expect } from 'vitest';
import { AI_CASES } from '../../benchmarks/ai/cases.js';
import { scoreVerdict, summarize, runAiCase, CountingClient, type AiCaseResult } from '../../benchmarks/ai/lib.js';
import { findingKey } from '../../src/ai/types.js';
import type { LLMClient, TriageUnit, ProjectContext, Verdict, Classification } from '../../src/ai/types.js';

/** A judge that always answers the same classification. */
function constantJudge(c: Classification): LLMClient {
  const answer = async (u: TriageUnit): Promise<Verdict[]> =>
    u.findings.map((f) => ({
      findingKey: findingKey(f),
      classification: c,
      confidence: 0.9,
      reasoning: `always ${c}`,
    }));
  return { triage: answer, verify: answer, summarize: async () => '', remediate: async () => [] };
}

describe('scoreVerdict — the outcome matrix', () => {
  it('agreement is a hit in both directions', () => {
    expect(scoreVerdict('real', 'real')).toBe('hit');
    expect(scoreVerdict('false-positive', 'false-positive')).toBe('hit');
  });
  it('uncertain escalates to the human, never counts as wrong', () => {
    expect(scoreVerdict('real', 'uncertain')).toBe('escalated');
    expect(scoreVerdict('false-positive', 'uncertain')).toBe('escalated');
  });
  it('a real issue called false-positive is the one hidden-risk outcome', () => {
    expect(scoreVerdict('real', 'false-positive')).toBe('excused-real');
  });
  it('a false positive kept as real is noise, not hidden risk', () => {
    expect(scoreVerdict('false-positive', 'real')).toBe('noise-kept');
  });
});

describe('summarize — the gate', () => {
  const r = (p: Partial<AiCaseResult>): AiCaseResult => ({
    name: 'x',
    expected: 'real',
    crossFile: false,
    calls: 1,
    contentBytes: 10,
    ms: 1,
    ...p,
  });

  it('passes when nothing real was excused and nothing is broken, whatever the FP catch rate', () => {
    const s = summarize([
      r({ outcome: 'hit', got: 'real' }),
      r({ expected: 'false-positive', outcome: 'noise-kept', got: 'real' }),
      r({ expected: 'false-positive', outcome: 'escalated', got: 'uncertain' }),
    ]);
    expect(s.ok).toBe(true);
    expect(s.realHitRate).toBe(1);
    expect(s.fpCatchRate).toBe(0);
  });

  it('fails on a single excused real', () => {
    const s = summarize([r({ outcome: 'hit', got: 'real' }), r({ outcome: 'excused-real', got: 'false-positive' })]);
    expect(s.ok).toBe(false);
    expect(s.excusedReal).toBe(1);
  });

  it('fails on a broken case — an unjudged case must never read as green', () => {
    const s = summarize([r({ outcome: 'hit', got: 'real' }), r({ broken: 'static layer did not emit' })]);
    expect(s.ok).toBe(false);
    expect(s.broken).toBe(1);
  });

  it('reports cross-file FPs as their own rate, separate from same-file FPs', () => {
    const s = summarize([
      r({ expected: 'false-positive', outcome: 'hit', got: 'false-positive' }),
      r({ expected: 'false-positive', crossFile: true, outcome: 'noise-kept', got: 'real' }),
    ]);
    expect(s.fpCatchRate).toBe(1);
    expect(s.crossFileCatchRate).toBe(0);
  });
});

describe('CountingClient', () => {
  it('counts triage and verify calls and the content bytes they carry', async () => {
    const c = new CountingClient(constantJudge('real'));
    const unit: TriageUnit = { file: 'a.ts', content: 'abcdef', findings: [] };
    const ctx = {} as ProjectContext;
    await c.triage(unit, ctx);
    await c.verify(unit, ctx);
    expect(c.calls).toBe(2);
    expect(c.contentBytes).toBe(12);
  });
});

describe('the AI corpus itself (offline health — no model needed)', () => {
  it('every case has a unique name and a rubric', () => {
    const names = AI_CASES.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
    for (const c of AI_CASES) expect(c.why.length, c.name).toBeGreaterThan(20);
  });

  it('the static layer emits every target finding — a case whose target vanished is a broken corpus', async () => {
    const judge = constantJudge('uncertain');
    const broken: string[] = [];
    for (const c of AI_CASES) {
      const r = await runAiCase(c, { client: judge });
      if (r.broken) broken.push(`${c.name}: ${r.broken}`);
    }
    expect(broken).toEqual([]);
  }, 120_000);

  it('a case is reported broken (not silently skipped) when its target is not emitted', async () => {
    const r = await runAiCase(
      {
        name: 'broken-on-purpose',
        categories: ['security'],
        files: { 'package.json': '{}', 'src/a.ts': 'export const x = 1;\n' },
        target: { file: 'src/a.ts', id: 'SEC-AWS-KEY' },
        expect: 'real',
        why: 'nothing here — the static layer must not find anything',
      },
      { client: constantJudge('real') },
    );
    expect(r.broken).toMatch(/did not emit SEC-AWS-KEY/);
  });

  it('a judge that always says real confirms every real case and hides nothing (dry-run baseline)', async () => {
    const results: AiCaseResult[] = [];
    for (const c of AI_CASES.filter((c) => c.expect === 'real').slice(0, 2)) {
      results.push(await runAiCase(c, { client: constantJudge('real') }));
    }
    const s = summarize(results);
    expect(s.ok).toBe(true);
    expect(s.realHitRate).toBe(1);
  }, 60_000);
});

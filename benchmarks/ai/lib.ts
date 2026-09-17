/**
 * AI-triage benchmark — the testable core. The CLI entry (run-ai-benchmark.ts)
 * builds a client and prints; everything that decides pass/fail lives here so
 * the corpus and the scoring are covered by the offline test suite even
 * though the judge itself needs a live model.
 */

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runAudit } from '../../src/core/engine.js';
import { runTriage } from '../../src/ai/triage.js';
import { findingKey } from '../../src/ai/types.js';
import type {
  LLMClient,
  TriageUnit,
  ProjectContext,
  Verdict,
  Remediation,
  Classification,
} from '../../src/ai/types.js';
import type { AnalysisCategory } from '../../src/core/types.js';
import { confinedReader } from '../../src/utils/safe-read.js';
import type { AiBenchCase, ExpectedVerdict } from './cases.js';

/**
 * What a verdict means against the expected one.
 * - hit:           the judge agreed.
 * - escalated:     the judge said `uncertain` — the human looks; not wrong, not a win.
 * - excused-real:  expected real, judge said false-positive — the one outcome that
 *                  HIDES risk. The benchmark hard-fails on any of these.
 * - noise-kept:    expected false-positive, judge said real — costs a human a look.
 */
export type Outcome = 'hit' | 'escalated' | 'excused-real' | 'noise-kept';

export function scoreVerdict(expected: ExpectedVerdict, got: Classification): Outcome {
  if (got === expected) return 'hit';
  if (got === 'uncertain') return 'escalated';
  return expected === 'real' ? 'excused-real' : 'noise-kept';
}

export interface AiCaseResult {
  name: string;
  expected: ExpectedVerdict;
  crossFile: boolean;
  /** Set when the case could not be judged at all — the corpus or the client is broken. */
  broken?: string;
  got?: Classification;
  outcome?: Outcome;
  reasoning?: string;
  calls: number;
  contentBytes: number;
  ms: number;
}

/** Wraps a client to count calls and the file content bytes sent (the cost the tiers cut). */
export class CountingClient implements LLMClient {
  calls = 0;
  contentBytes = 0;
  constructor(private inner: LLMClient) {}
  triage(unit: TriageUnit, ctx: ProjectContext): Promise<Verdict[]> {
    this.calls++;
    this.contentBytes += unit.content.length;
    return this.inner.triage(unit, ctx);
  }
  verify(unit: TriageUnit, ctx: ProjectContext): Promise<Verdict[]> {
    this.calls++;
    this.contentBytes += unit.content.length;
    return this.inner.verify(unit, ctx);
  }
  summarize(digest: string, ctx: ProjectContext): Promise<string> {
    return this.inner.summarize(digest, ctx);
  }
  remediate(unit: TriageUnit, ctx: ProjectContext): Promise<Remediation[]> {
    return this.inner.remediate(unit, ctx);
  }
}

export interface RunOptions {
  client: LLMClient;
  verifiers?: LLMClient[];
}

/**
 * Materialize one case, run the static engine, isolate the target finding and
 * put it in front of the judge. Only the target is triaged: the benchmark
 * measures the verdict on THAT finding, and sending the static noise of a
 * three-file fixture would only add cost.
 */
export async function runAiCase(c: AiBenchCase, opts: RunOptions): Promise<AiCaseResult> {
  const dir = mkdtempSync(join(tmpdir(), 'prism-ai-bench-'));
  const counting = new CountingClient(opts.client);
  const base: AiCaseResult = {
    name: c.name,
    expected: c.expect,
    crossFile: Boolean(c.crossFile),
    calls: 0,
    contentBytes: 0,
    ms: 0,
  };
  const started = performance.now();
  try {
    for (const [rel, content] of Object.entries(c.files)) {
      mkdirSync(join(dir, dirname(rel)), { recursive: true });
      writeFileSync(join(dir, rel), content);
    }
    const report = await runAudit({ targetPath: dir, analyzers: c.categories as AnalysisCategory[] });
    const target = report.findings.find((f) => f.file === c.target.file && f.id === c.target.id);
    if (!target) {
      const seen = report.findings.map((f) => `${f.id}@${f.file ?? '-'}`).join(', ') || 'none';
      return { ...base, broken: `static layer did not emit ${c.target.id} on ${c.target.file} (saw: ${seen})` };
    }
    report.findings = [target];

    const verifiers = opts.verifiers?.map((v) => new CountingClient(v));
    const triage = await runTriage(report, confinedReader(dir), counting, { verify: true, verifiers });
    const verdict = triage.verdicts.find((v) => v.findingKey === findingKey(target));
    const calls = counting.calls + (verifiers?.reduce((n, v) => n + v.calls, 0) ?? 0);
    const contentBytes = counting.contentBytes + (verifiers?.reduce((n, v) => n + v.contentBytes, 0) ?? 0);
    if (!verdict) return { ...base, calls, contentBytes, broken: 'triage returned no verdict for the target' };
    return {
      ...base,
      got: verdict.classification,
      outcome: scoreVerdict(c.expect, verdict.classification),
      reasoning: verdict.reasoning,
      calls,
      contentBytes,
      ms: Math.round(performance.now() - started),
    };
  } catch (err) {
    return { ...base, broken: `triage failed: ${err instanceof Error ? err.message : String(err)}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface AiBenchSummary {
  cases: number;
  broken: number;
  hit: number;
  escalated: number;
  noiseKept: number;
  excusedReal: number;
  /** Hits among expected-real cases / expected-real cases (excluding broken). */
  realHitRate: number;
  /** Hits among same-file expected-FP cases / those cases (excluding broken). */
  fpCatchRate: number;
  /** Hits among cross-file expected-FP cases — the neighborhood baseline. */
  crossFileCatchRate: number;
  calls: number;
  contentBytes: number;
  ms: number;
  /** The gate: any excused-real or broken case fails the run. */
  ok: boolean;
}

export function summarize(results: AiCaseResult[]): AiBenchSummary {
  const judged = results.filter((r) => !r.broken);
  const count = (o: Outcome) => judged.filter((r) => r.outcome === o).length;
  const rate = (subset: AiCaseResult[]) =>
    subset.length === 0 ? 1 : subset.filter((r) => r.outcome === 'hit').length / subset.length;
  const reals = judged.filter((r) => r.expected === 'real');
  const fps = judged.filter((r) => r.expected === 'false-positive' && !r.crossFile);
  const xfps = judged.filter((r) => r.expected === 'false-positive' && r.crossFile);
  const broken = results.length - judged.length;
  const excusedReal = count('excused-real');
  return {
    cases: results.length,
    broken,
    hit: count('hit'),
    escalated: count('escalated'),
    noiseKept: count('noise-kept'),
    excusedReal,
    realHitRate: rate(reals),
    fpCatchRate: rate(fps),
    crossFileCatchRate: rate(xfps),
    calls: results.reduce((n, r) => n + r.calls, 0),
    contentBytes: results.reduce((n, r) => n + r.contentBytes, 0),
    ms: results.reduce((n, r) => n + r.ms, 0),
    ok: excusedReal === 0 && broken === 0,
  };
}

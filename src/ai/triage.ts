import type { AuditReport, FileReader } from '../core/types.js';
import type { LLMClient, TriageResult, TriageUnit, Verdict, ProjectContext, Finding } from './types.js';
import { findingKey, buildKeyMatcher, assignFindingInstances } from './types.js';
import { tallyVerdicts } from './vote.js';
import { mapWithConcurrency } from '../utils/concurrency.js';
import { contextTierFor } from '../core/rule-metadata.js';
import { cacheKey, judgeId, type VerdictCache } from './cache.js';

const DEFAULT_CONCURRENCY = 5;

/**
 * Max findings per no-code batch. Bounds one call's size the way
 * MAX_CONTENT_CHARS bounds a file call — 300 OSV advisories must not become
 * one 300-item prompt the model answers with a truncated array.
 */
export const MAX_BATCH_FINDINGS = 25;

export interface TriageOptions {
  /** Adversarially re-check false-positive verdicts before trusting them (default true). */
  verify?: boolean;
  /** Max concurrent LLM calls (default 5). */
  concurrency?: number;
  /**
   * Verification panel: when set, every false-positive verdict is re-checked
   * by ALL of these clients and merged by majority vote (see tallyVerdicts).
   * Defaults to the triage client alone — the single-verifier behavior.
   */
  verifiers?: LLMClient[];
  /**
   * Verdict cache (see ./cache.ts). When set, findings whose final verdict is
   * already known for this judge + prompt + content are not sent again, and
   * every fresh final verdict is stored. Unset = every finding is judged.
   */
  cache?: VerdictCache;
}

export function buildProjectContext(report: AuditReport): ProjectContext {
  return {
    projectName: report.projectName,
    stack: report.projectMeta.stack.primary,
    overallScore: report.overallScore,
    categorySummaries: report.categories.map((c) => `${c.category}: ${c.score}/10 — ${c.summary}`),
  };
}

/** Group findings by file; null-file findings form one project-level group. */
export function groupFindingsByFile(findings: Finding[]): Array<[string | null, Finding[]]> {
  const byFile = new Map<string | null, Finding[]>();
  for (const f of findings) {
    const key = f.file ?? null;
    const group = byFile.get(key);
    if (group) group.push(f);
    else byFile.set(key, [f]);
  }
  return [...byFile.entries()];
}

/**
 * Triage units by context tier (see CONTEXT_TIER in core/rule-metadata):
 * findings whose rule needs the code are grouped by file, exactly as before;
 * findings whose rule is judged from a project-level fact — plus findings
 * with no file at all — are batched into content-less units in chunks of
 * MAX_BATCH_FINDINGS. A file that carries both kinds is split: the secret on
 * line 3 gets the file, the god-file finding on the same path does not.
 * `neighborhood` behaves as `file` until the neighborhood builder lands.
 */
export function groupFindingsForTriage(findings: Finding[]): Array<[string | null, Finding[]]> {
  const needsCode = findings.filter((f) => f.file && contextTierFor(f.id) !== 'none');
  const noCode = findings.filter((f) => !f.file || contextTierFor(f.id) === 'none');

  const units = groupFindingsByFile(needsCode).filter(([file]) => file !== null);
  for (let i = 0; i < noCode.length; i += MAX_BATCH_FINDINGS) {
    units.push([null, noCode.slice(i, i + MAX_BATCH_FINDINGS)]);
  }
  return units;
}

/**
 * Align a unit's returned verdicts to the findings we sent: keep only known
 * keys (tolerating trimmed trailing pipes), synthesize an `uncertain` verdict
 * for any finding the model skipped.
 */
function alignVerdicts(findings: Finding[], returned: Verdict[]): Verdict[] {
  return alignVerdictsDetailed(findings, returned).verdicts;
}

/**
 * alignVerdicts plus the set of finding keys the model ACTUALLY answered.
 * A synthesized `uncertain` (skipped finding, failed call) is not a judgment
 * and must never be cached as one.
 */
function alignVerdictsDetailed(
  findings: Finding[],
  returned: Verdict[],
): { verdicts: Verdict[]; answered: Set<string> } {
  const matchKey = buildKeyMatcher(findings);
  const byKey = new Map<string, Verdict>();
  for (const v of returned) {
    const canonical = matchKey(v.findingKey);
    if (canonical) byKey.set(canonical, { ...v, findingKey: canonical });
  }
  const answered = new Set<string>();
  const verdicts = findings.map((f) => {
    const key = findingKey(f);
    const v = byKey.get(key);
    if (v) {
      answered.add(key);
      return v;
    }
    return { findingKey: key, classification: 'uncertain' as const, confidence: 0, reasoning: 'no verdict returned' };
  });
  return { verdicts, answered };
}

const CLASSIFICATIONS = new Set(['real', 'false-positive', 'uncertain']);

/** A cached value is trusted only if it still looks like a verdict (the file is the operator's, but it can rot). */
function asVerdict(value: unknown, key: string): Verdict | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const v = value as Partial<Verdict>;
  if (!CLASSIFICATIONS.has(String(v.classification)) || typeof v.reasoning !== 'string') return undefined;
  return {
    findingKey: key,
    classification: v.classification as Verdict['classification'],
    confidence: typeof v.confidence === 'number' ? v.confidence : 0,
    reasoning: `${v.reasoning} [cached]`,
  };
}

export async function runTriage(
  report: AuditReport,
  readFile: FileReader,
  client: LLMClient,
  options: TriageOptions = {},
): Promise<TriageResult> {
  const ctx = buildProjectContext(report);
  const verifyEnabled = options.verify !== false; // default on
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;

  // Disambiguate findings that would otherwise share a key, so their verdicts
  // and fixes don't collapse onto each other downstream. Mutates in place so
  // the same instance indices flow to remediation, summary, and the reporters.
  assignFindingInstances(report.findings);

  const groups = groupFindingsForTriage(report.findings);

  const cache = options.cache;
  const verifiers = options.verifiers?.length ? options.verifiers : [client];
  const judge = judgeId(
    client.id,
    verifiers.map((v) => v.id),
  );
  const keyOf = (f: Finding, content: string) => cacheKey({ kind: 'triage', judge, content, finding: f });
  let cachedCount = 0;

  // First pass: read each file (when the tier needs it), reuse every verdict
  // the cache already holds for this judge + content, and triage the rest
  // with bounded concurrency.
  let attemptedGroups = 0;
  let failedGroups = 0;
  const firstPass = await mapWithConcurrency(groups, concurrency, async ([file, findings]) => {
    let content = '';
    if (file) {
      try {
        content = await readFile(file);
      } catch {
        content = '';
      }
    }
    const unit: TriageUnit = { file, content, findings };

    const cached: Verdict[] = [];
    const pending: Finding[] = [];
    const keys = new Map<string, string>(); // findingKey → cache key
    for (const f of findings) {
      const fk = findingKey(f);
      if (cache) {
        const ck = keyOf(f, content);
        keys.set(fk, ck);
        const hit = asVerdict(cache.get(ck), fk);
        if (hit) {
          cached.push(hit);
          continue;
        }
      }
      pending.push(f);
    }
    cachedCount += cached.length;
    if (pending.length === 0) return { unit, verdicts: cached, answered: new Set<string>(), keys };

    attemptedGroups++;
    try {
      const returned = await client.triage({ file, content, findings: pending }, ctx);
      const { verdicts: fresh, answered } = alignVerdictsDetailed(pending, returned);
      // real / uncertain are final now (only false-positives face the verify pass).
      if (cache) {
        for (const v of fresh) {
          if (answered.has(v.findingKey) && v.classification !== 'false-positive') {
            cache.put(keys.get(v.findingKey) as string, v);
          }
        }
      }
      return { unit, verdicts: [...cached, ...fresh], answered, keys };
    } catch {
      // A failed triage call for one group (rate limit, 500, timeout) must not
      // kill the whole pass and discard every already-computed verdict. Synthesize
      // `uncertain` for this group; the rest survive. Mirrors the verify pass.
      failedGroups++;
      return { unit, verdicts: [...cached, ...alignVerdicts(pending, [])], answered: new Set<string>(), keys };
    }
  });

  // If EVERY attempted group failed (no key, no network, invalid provider),
  // triage didn't really run — throw so the caller drops the AI overlay
  // entirely rather than attaching a report of meaningless "uncertain"
  // verdicts. Groups served entirely from cache are not attempts.
  if (attemptedGroups > 0 && failedGroups === attemptedGroups) {
    throw new Error('AI triage failed for every file group');
  }

  let verdicts: Verdict[] = firstPass.flatMap((p) => p.verdicts);

  // Second pass: adversarially re-check every finding the first pass called a
  // false-positive. An FP survives only if the skeptical re-check also confirms
  // it; otherwise we trust the skeptical verdict (real/uncertain). Catches a
  // lenient or hallucinated FP from the first pass. Cached FPs were stored
  // AFTER their own verify pass, so only fresh ones are re-checked.
  if (verifyEnabled) {
    const verdictByKey = new Map(verdicts.map((v) => [v.findingKey, v]));
    const fpGroups = firstPass
      .map((p) => ({
        unit: p.unit,
        keys: p.keys,
        findings: p.unit.findings.filter(
          (f) => p.answered.has(findingKey(f)) && verdictByKey.get(findingKey(f))?.classification === 'false-positive',
        ),
      }))
      .filter((g) => g.findings.length > 0);

    if (fpGroups.length > 0) {
      const verifyResults = await mapWithConcurrency(fpGroups, concurrency, async (g) => {
        const unit: TriageUnit = { file: g.unit.file, content: g.unit.content, findings: g.findings };
        let voterFailed = false;
        const perVoter = await Promise.all(
          verifiers.map(async (voter) => {
            try {
              return alignVerdicts(g.findings, await voter.verify(unit, ctx));
            } catch {
              // A failed voter abstains: alignVerdicts on [] synthesizes
              // `uncertain` for every finding, so the rest of the panel
              // still decides instead of the whole triage dying.
              voterFailed = true;
              return alignVerdicts(g.findings, []);
            }
          }),
        );
        const tallied = tallyVerdicts(perVoter);
        // A panel decision reached with an abstaining (errored) voter is not
        // frozen: the next run gets to ask again.
        if (cache && !voterFailed) {
          for (const v of tallied) cache.put(g.keys.get(v.findingKey) as string, v);
        }
        return tallied;
      });

      const verifyByKey = new Map<string, Verdict>();
      for (const arr of verifyResults) for (const v of arr) verifyByKey.set(v.findingKey, v);

      verdicts = verdicts.map((v) => {
        if (v.classification !== 'false-positive' || v.reasoning.endsWith('[cached]')) return v;
        const vr = verifyByKey.get(v.findingKey);
        if (!vr) {
          return { ...v, classification: 'uncertain', reasoning: `${v.reasoning} (unverified)` };
        }
        return vr; // confirmed FP, or downgraded to real/uncertain by the skeptical pass
      });
    }
  } else if (cache) {
    // No verify pass: the first-pass FP IS the final verdict — store it.
    for (const p of firstPass) {
      for (const v of p.verdicts) {
        if (p.answered.has(v.findingKey) && v.classification === 'false-positive') {
          cache.put(p.keys.get(v.findingKey) as string, v);
        }
      }
    }
  }

  const summary = {
    real: verdicts.filter((v) => v.classification === 'real').length,
    falsePositive: verdicts.filter((v) => v.classification === 'false-positive').length,
    uncertain: verdicts.filter((v) => v.classification === 'uncertain').length,
    ...(cache ? { cached: cachedCount } : {}),
  };

  return { verdicts, summary };
}

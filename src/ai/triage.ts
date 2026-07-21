import type { AuditReport, FileReader } from '../core/types.js';
import type { LLMClient, TriageResult, TriageUnit, Verdict, ProjectContext, Finding } from './types.js';
import { findingKey, buildKeyMatcher, assignFindingInstances } from './types.js';
import { tallyVerdicts } from './vote.js';
import { mapWithConcurrency } from '../utils/concurrency.js';

const DEFAULT_CONCURRENCY = 5;

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
 * Align a unit's returned verdicts to the findings we sent: keep only known
 * keys (tolerating trimmed trailing pipes), synthesize an `uncertain` verdict
 * for any finding the model skipped.
 */
function alignVerdicts(findings: Finding[], returned: Verdict[]): Verdict[] {
  const matchKey = buildKeyMatcher(findings);
  const byKey = new Map<string, Verdict>();
  for (const v of returned) {
    const canonical = matchKey(v.findingKey);
    if (canonical) byKey.set(canonical, { ...v, findingKey: canonical });
  }
  return findings.map(
    (f) =>
      byKey.get(findingKey(f)) ?? {
        findingKey: findingKey(f),
        classification: 'uncertain',
        confidence: 0,
        reasoning: 'no verdict returned',
      },
  );
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

  const groups = groupFindingsByFile(report.findings);

  // First pass: read each file and triage its findings, with bounded concurrency.
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
    try {
      const returned = await client.triage(unit, ctx);
      return { unit, verdicts: alignVerdicts(findings, returned) };
    } catch {
      // A failed triage call for one group (rate limit, 500, timeout) must not
      // kill the whole pass and discard every already-computed verdict. Synthesize
      // `uncertain` for this group; the rest survive. Mirrors the verify pass.
      failedGroups++;
      return { unit, verdicts: alignVerdicts(findings, []) };
    }
  });

  // If EVERY group failed (no key, no network, invalid provider), triage didn't
  // really run — throw so the caller drops the AI overlay entirely rather than
  // attaching a report of meaningless "uncertain" verdicts.
  if (groups.length > 0 && failedGroups === groups.length) {
    throw new Error('AI triage failed for every file group');
  }

  let verdicts: Verdict[] = firstPass.flatMap((p) => p.verdicts);

  // Second pass: adversarially re-check every finding the first pass called a
  // false-positive. An FP survives only if the skeptical re-check also confirms
  // it; otherwise we trust the skeptical verdict (real/uncertain). Catches a
  // lenient or hallucinated FP from the first pass.
  if (verifyEnabled) {
    const verdictByKey = new Map(verdicts.map((v) => [v.findingKey, v]));
    const fpGroups = firstPass
      .map((p) => ({
        unit: p.unit,
        findings: p.unit.findings.filter((f) => verdictByKey.get(findingKey(f))?.classification === 'false-positive'),
      }))
      .filter((g) => g.findings.length > 0);

    if (fpGroups.length > 0) {
      const verifiers = options.verifiers?.length ? options.verifiers : [client];
      const verifyResults = await mapWithConcurrency(fpGroups, concurrency, async (g) => {
        const unit: TriageUnit = { file: g.unit.file, content: g.unit.content, findings: g.findings };
        const perVoter = await Promise.all(
          verifiers.map(async (voter) => {
            try {
              return alignVerdicts(g.findings, await voter.verify(unit, ctx));
            } catch {
              // A failed voter abstains: alignVerdicts on [] synthesizes
              // `uncertain` for every finding, so the rest of the panel
              // still decides instead of the whole triage dying.
              return alignVerdicts(g.findings, []);
            }
          }),
        );
        return tallyVerdicts(perVoter);
      });

      const verifyByKey = new Map<string, Verdict>();
      for (const arr of verifyResults) for (const v of arr) verifyByKey.set(v.findingKey, v);

      verdicts = verdicts.map((v) => {
        if (v.classification !== 'false-positive') return v;
        const vr = verifyByKey.get(v.findingKey);
        if (!vr) {
          return { ...v, classification: 'uncertain', reasoning: `${v.reasoning} (unverified)` };
        }
        return vr; // confirmed FP, or downgraded to real/uncertain by the skeptical pass
      });
    }
  }

  const summary = {
    real: verdicts.filter((v) => v.classification === 'real').length,
    falsePositive: verdicts.filter((v) => v.classification === 'false-positive').length,
    uncertain: verdicts.filter((v) => v.classification === 'uncertain').length,
  };

  return { verdicts, summary };
}

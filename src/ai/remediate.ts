import type { AuditReport, FileReader } from '../core/types.js';
import type { LLMClient, TriageUnit, Remediation, Finding } from './types.js';
import { findingKey, buildKeyMatcher } from './types.js';
import { buildProjectContext, groupFindingsByFile } from './triage.js';
import { mapWithConcurrency } from '../utils/concurrency.js';

const DEFAULT_CONCURRENCY = 5;

export interface RemediationOptions {
  /** Max concurrent LLM calls (default 5). */
  concurrency?: number;
}

/**
 * Findings whose final triage verdict is `real` — the only signal worth a fix
 * proposal. Without triage verdicts there is no confirmed signal, so nothing
 * is selected (remediation is a post-triage feature).
 */
export function selectRealFindings(report: AuditReport): Finding[] {
  const verdicts = report.aiTriage?.verdicts;
  if (!verdicts) return [];
  const realKeys = new Set(verdicts.filter((v) => v.classification === 'real').map((v) => v.findingKey));
  return report.findings.filter((f) => realKeys.has(findingKey(f)));
}

/**
 * Propose a concrete fix for each confirmed-real finding. Same per-file
 * grouping as triage (the model reads the actual file once per group). A fix
 * the model skipped is simply absent — we never fabricate a remediation —
 * and fixes for keys we did not send are discarded.
 */
export async function runRemediation(
  report: AuditReport,
  readFile: FileReader,
  client: LLMClient,
  options: RemediationOptions = {},
): Promise<Remediation[]> {
  const targets = selectRealFindings(report);
  if (targets.length === 0) return [];

  const ctx = buildProjectContext(report);
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  const groups = groupFindingsByFile(targets);

  const results = await mapWithConcurrency(groups, concurrency, async ([file, findings]) => {
    let content = '';
    if (file) {
      try {
        content = await readFile(file);
      } catch {
        content = '';
      }
    }
    const unit: TriageUnit = { file, content, findings };
    const returned = await client.remediate(unit, ctx);
    const matchKey = buildKeyMatcher(findings);
    return returned.flatMap((r) => {
      const canonical = matchKey(r.findingKey);
      return canonical ? [{ ...r, findingKey: canonical }] : [];
    });
  });

  // Dedupe by findingKey (first fix wins) in case the model repeats itself.
  const byKey = new Map<string, Remediation>();
  for (const r of results.flat()) {
    if (!byKey.has(r.findingKey)) byKey.set(r.findingKey, r);
  }
  return [...byKey.values()];
}

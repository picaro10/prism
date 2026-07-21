import type { AuditReport } from '../core/types.js';
import type { LLMClient } from './types.js';
import { findingKey } from './types.js';
import { buildProjectContext } from './triage.js';

/** Max findings listed in the digest (bounds token cost). */
const MAX_DIGEST_FINDINGS = 40;

/**
 * Build the text digest the executive-summary call reasons over: scores, the
 * triage tally, and the findings worth weighing (everything not confirmed a
 * false positive). Pure — no I/O.
 */
export function buildSummaryDigest(report: AuditReport): string {
  const verdictByKey = new Map((report.aiTriage?.verdicts ?? []).map((v) => [v.findingKey, v] as const));
  const lines: string[] = [];

  lines.push(`Project: ${report.projectName}`);
  lines.push(`Overall static score: ${report.overallScore}/10`);
  lines.push('Category scores:');
  for (const c of report.categories) lines.push(`  - ${c.category}: ${c.score}/10 — ${c.summary}`);
  lines.push('');

  if (report.aiTriage) {
    const s = report.aiTriage.summary;
    lines.push(`AI triage: ${s.real} real · ${s.falsePositive} false positives · ${s.uncertain} uncertain.`);
    lines.push('');
  }

  // Findings worth narrating: everything not CONFIRMED a false positive.
  const worth = report.findings.filter((f) => verdictByKey.get(findingKey(f))?.classification !== 'false-positive');
  lines.push(`Findings to weigh (${worth.length}, excluding confirmed false positives):`);
  for (const f of worth.slice(0, MAX_DIGEST_FINDINGS)) {
    const v = verdictByKey.get(findingKey(f));
    const tag = v ? ` [${v.classification}]` : '';
    lines.push(`  - ${f.severity.toUpperCase()} ${f.id}${f.file ? ` (${f.file})` : ''}: ${f.title}${tag}`);
  }
  if (worth.length > MAX_DIGEST_FINDINGS) {
    lines.push(`  … and ${worth.length - MAX_DIGEST_FINDINGS} more.`);
  }

  return lines.join('\n');
}

/** Produce the executive-summary prose for a report (consumes triage verdicts if present). */
export async function runSummary(report: AuditReport, client: LLMClient): Promise<string> {
  const ctx = buildProjectContext(report);
  const digest = buildSummaryDigest(report);
  return client.summarize(digest, ctx);
}

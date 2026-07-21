import type { AuditReport, Finding } from './types.js';
import type { Verdict, Remediation } from '../ai/types.js';
import { findingKey, buildKeyMatcher } from '../ai/types.js';

/** A self-contained package of everything needed to act on one finding. */
export interface FindingBundle {
  /** Correlation metadata — ties the bundle to a specific scan. */
  scan: {
    project: string;
    projectPath: string;
    completedAt: string;
    overallScore: number;
    prismVersion: string;
  };
  finding: Finding;
  /** The fix target, or null for a project-level finding. */
  location: { file: string; line?: number } | null;
  /** Code around the flagged line (±context), or null if unavailable. */
  snippet: { startLine: number; endLine: number; code: string } | null;
  /** The AI triage verdict for this finding, if the report has one. */
  verdict: Verdict | null;
  /** The proposed fix, if the report has one. */
  remediation: Remediation | null;
}

/** Find the finding matching `key` (tolerating trimmed trailing pipes), or null. */
export function findByKey(report: AuditReport, key: string): Finding | null {
  const matchKey = buildKeyMatcher(report.findings);
  const canonical = matchKey(key);
  if (!canonical) return null;
  return report.findings.find((f) => findingKey(f) === canonical) ?? null;
}

/** Slice `content` around a 1-based line, ±context lines (clamped to bounds). */
export function extractSnippet(
  content: string,
  line: number,
  context: number,
): { startLine: number; endLine: number; code: string } {
  const lines = content.split('\n');
  const startLine = Math.max(1, line - context);
  const endLine = Math.min(lines.length, line + context);
  return { startLine, endLine, code: lines.slice(startLine - 1, endLine).join('\n') };
}

/**
 * Assemble a self-contained bundle for the finding whose key is `key`. Returns
 * null if no finding matches (tolerating trimmed trailing pipes via the key
 * matcher). `fileContent` is the flagged file's text (or null if unreadable /
 * not applicable); the caller reads it so this stays pure and testable.
 */
export function buildFindingBundle(
  report: AuditReport,
  key: string,
  fileContent: string | null,
  context = 3,
): FindingBundle | null {
  const finding = findByKey(report, key);
  if (!finding) return null;
  const canonical = findingKey(finding);

  const location = finding.file ? { file: finding.file, line: finding.line } : null;
  const snippet = fileContent && finding.line !== undefined ? extractSnippet(fileContent, finding.line, context) : null;
  const verdict = report.aiTriage?.verdicts.find((v) => v.findingKey === canonical) ?? null;
  const remediation = report.aiRemediation?.find((r) => r.findingKey === canonical) ?? null;

  return {
    scan: {
      project: report.projectName,
      projectPath: report.projectPath,
      completedAt: report.completedAt,
      overallScore: report.overallScore,
      prismVersion: report.prismVersion,
    },
    finding,
    location,
    snippet,
    verdict,
    remediation,
  };
}

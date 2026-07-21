import type { Finding, AnalysisCategory } from '../core/types.js';

export type Classification = 'real' | 'false-positive' | 'uncertain';

export interface Verdict {
  /** Stable key linking back to a finding: `${id}|${file ?? ''}|${line ?? ''}`. */
  findingKey: string;
  classification: Classification;
  /** 0.0–1.0 model-reported confidence. */
  confidence: number;
  /** One or two sentences explaining the verdict. */
  reasoning: string;
}

export interface TriageResult {
  verdicts: Verdict[];
  summary: { real: number; falsePositive: number; uncertain: number };
}

export type RemediationEffort = 'low' | 'medium' | 'high';

/** A concrete fix proposal for one confirmed-real finding. */
export interface Remediation {
  /** Stable key linking back to a finding: `${id}|${file ?? ''}|${line ?? ''}`. */
  findingKey: string;
  /** The concrete fix: what to change, where, possibly with a short snippet. */
  fix: string;
  /** Rough effort: low (minutes), medium (an hour or two), high (a refactor). */
  effort: RemediationEffort;
}

/** One triage call's input: a file's content + the findings on it. */
export interface TriageUnit {
  /** File path, or null for project-level findings. */
  file: string | null;
  /** File content ('' for project-level or unreadable). */
  content: string;
  findings: Finding[];
}

export interface ProjectContext {
  projectName: string;
  stack: string;
  overallScore: number;
  /** Per-category one-line summaries (cacheable prefix). */
  categorySummaries: string[];
}

/** Injectable seam. Real impl calls Claude; tests inject a fake. */
export interface LLMClient {
  triage(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]>;
  /**
   * Adversarial re-check of findings a first pass flagged as false-positive.
   * Same shape as triage, but the model must confirm the FP with concrete code
   * evidence or classify the finding otherwise. Used to catch hallucinated FPs.
   */
  verify(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]>;
  /**
   * Write a free-text executive assessment of the project from a pre-built
   * digest (scores + the triaged findings). Returns prose, not structured data.
   */
  summarize(digest: string, projectContext: ProjectContext): Promise<string>;
  /**
   * Propose a concrete fix for each finding in the unit (only findings the
   * triage confirmed as real are sent). Same per-file grouping as triage.
   */
  remediate(unit: TriageUnit, projectContext: ProjectContext): Promise<Remediation[]>;
}

/** Stable identifier for a finding, used to align verdicts back to findings. */
export function findingKey(f: Finding): string {
  const suffix = f.instance ? `#${f.instance}` : '';
  return `${f.id}|${f.file ?? ''}|${f.line ?? ''}${suffix}`;
}

/**
 * Give a stable instance index to findings that would otherwise share a
 * findingKey (same id+file+line — e.g. DEP-002 emitted once per wildcard dep,
 * all on package.json with no line). Without it their verdicts and fixes
 * collapse onto one another via the alignment maps. The first member of a
 * colliding group keeps the bare key (so the common no-collision case is
 * unchanged); the 2nd+ get #1, #2, … Deterministic in the findings' order, and
 * idempotent-by-recompute (it overwrites, so re-running on a saved report is safe).
 */
export function assignFindingInstances(findings: Finding[]): void {
  const counts = new Map<string, number>();
  for (const f of findings) {
    const base = `${f.id}|${f.file ?? ''}|${f.line ?? ''}`;
    const seen = counts.get(base) ?? 0;
    f.instance = seen > 0 ? seen : undefined;
    counts.set(base, seen + 1);
  }
}

/**
 * Build a matcher that maps a key echoed by a model back to the canonical key
 * we sent. Keys for findings without a line (or file) end in `|` — models
 * routinely trim those trailing pipes when echoing, which used to silently
 * drop their verdicts/fixes (seen in production on STR-011 god files).
 */
export function buildKeyMatcher(findings: Finding[]): (returnedKey: string) => string | undefined {
  const canonicalByNormalized = new Map<string, string>();
  for (const f of findings) {
    const key = findingKey(f);
    canonicalByNormalized.set(key, key);
    canonicalByNormalized.set(key.replace(/\|+$/, ''), key);
  }
  return (returnedKey) =>
    canonicalByNormalized.get(returnedKey) ?? canonicalByNormalized.get(returnedKey.replace(/\|+$/, ''));
}

export type { Finding, AnalysisCategory };

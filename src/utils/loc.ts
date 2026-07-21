/**
 * Line-of-code helpers for the structure analyzer's god-file detection.
 * Pure functions — no findings, no I/O. Total-line counting (decision "(a)"):
 * transparent and reproducible, same spirit as the file-level TST-011 rewrite.
 */

import type { Severity } from '../core/types.js';

/** God-file tiers are severities minus 'critical' (a large file is debt, not a vulnerability). */
export type GodFileTier = Exclude<Severity, 'critical'>;

/** Total number of lines in a file's content. An empty string yields 1 (split artifact). */
export function countLoc(content: string): number {
  return content.split('\n').length;
}

/**
 * Classify a file by its line count into a god-file tier, or null if it is
 * at or below 400 lines. Thresholds are strict `>` comparisons; there is no
 * `critical` tier (a large file is debt, not a vulnerability).
 */
export function classifyGodFile(loc: number): GodFileTier | null {
  if (loc > 1500) return 'high';
  if (loc > 900) return 'medium';
  if (loc > 600) return 'low';
  if (loc > 400) return 'info';
  return null;
}

export interface MeasuredFile {
  path: string;
  loc: number;
}

export interface SizeMetrics {
  totalLoc: number;
  fileCount: number;
  median: number;
  largest: MeasuredFile | null;
  /** % of total LOC held by the 5 largest files (0 when there is no code). */
  top5Pct: number;
}

export function computeSizeMetrics(measured: MeasuredFile[]): SizeMetrics {
  if (measured.length === 0) {
    return { totalLoc: 0, fileCount: 0, median: 0, largest: null, top5Pct: 0 };
  }

  const locs = measured.map((m) => m.loc);
  const totalLoc = locs.reduce((sum, n) => sum + n, 0);

  const sortedAsc = [...locs].sort((a, b) => a - b);
  const mid = Math.floor(sortedAsc.length / 2);
  const median = sortedAsc.length % 2 === 0 ? Math.round((sortedAsc[mid - 1] + sortedAsc[mid]) / 2) : sortedAsc[mid];

  const byLocDesc = [...measured].sort((a, b) => b.loc - a.loc);
  const largest = byLocDesc[0];
  const top5Loc = byLocDesc.slice(0, 5).reduce((sum, m) => sum + m.loc, 0);
  const top5Pct = totalLoc === 0 ? 0 : Math.round((top5Loc / totalLoc) * 100);

  return { totalLoc, fileCount: measured.length, median, largest, top5Pct };
}

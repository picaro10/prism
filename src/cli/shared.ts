import { resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import chalk from 'chalk';
import type { AuditReport } from '../core/types.js';

/**
 * Semantic exit codes — a stable contract for CI and coding agents:
 *   0 the audit ran and the score met the threshold
 *   1 the audit ran but the score is below the threshold (findings to fix)
 *   2 usage/config error — bad flag, missing key, unresolvable target (your fault)
 *   3 internal error — the audit threw and could not complete (our fault)
 */
export const EXIT = { OK: 0, FINDINGS: 1, USAGE: 2, INTERNAL: 3 } as const;

export const DEFAULT_MIN_SCORE = 6;
export const CLI_VERSION = '1.4.1';

/** Print a usage error (subsequent lines are detail) and exit 2. */
export function usageError(...messages: string[]): never {
  const [first, ...rest] = messages;
  console.error(chalk.red(`\n  ✗ ${first}`));
  for (const m of rest) console.error(chalk.red(`    ${m}`));
  console.error('');
  process.exit(EXIT.USAGE);
}

/** Parse the --ai-vote value ("model-a,model-b,...") into model IDs. */
export function parseVoteModels(value: string | boolean | undefined): string[] | undefined {
  if (!value || typeof value !== 'string') return undefined;
  const models = value
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean);
  return models.length > 0 ? models : undefined;
}

/**
 * Load a saved report from disk with deep shape validation — exits 2 with the
 * first validation reasons when the file is missing, unparseable, or not a
 * structurally valid PRISM report.
 */
export async function loadReportOrExit(path: string): Promise<AuditReport> {
  const abs = resolve(String(path));
  if (!existsSync(abs)) usageError(`Report not found: ${abs}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(abs, 'utf-8'));
  } catch {
    usageError(`Could not parse ${path} as JSON.`);
  }
  const { parseReportDetailed } = await import('../core/report-schema.js');
  const result = parseReportDetailed(parsed);
  if ('errors' in result) {
    usageError(`${path} is not a valid PRISM report:`, ...result.errors.map((e) => `  · ${e}`));
  }
  return result.report;
}

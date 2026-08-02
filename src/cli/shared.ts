import { resolve, relative, isAbsolute } from 'node:path';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
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
export const CLI_VERSION = '1.5.1';

/** Print a usage error (subsequent lines are detail) and exit 2. */
export function usageError(...messages: string[]): never {
  const [first, ...rest] = messages;
  console.error(chalk.red(`\n  ✗ ${first}`));
  for (const m of rest) console.error(chalk.red(`    ${m}`));
  console.error('');
  process.exit(EXIT.USAGE);
}

/**
 * Import variables from a .env file into process.env — allowlisted keys only.
 * In `cd project && prism analyze .` the cwd .env IS the analyzed (untrusted)
 * project's, so it must never be loaded wholesale into the auditor's process
 * and its subprocesses: only what PRISM itself consumes (AI provider keys,
 * PRISM_* settings), and never overriding the real environment.
 */
export function loadAllowlistedEnv(path: string): void {
  const ENV_ALLOWLIST = /^(ANTHROPIC_API_KEY|OPENROUTER_API_KEY|PRISM_[A-Z0-9_]*)$/;
  try {
    if (!existsSync(path)) return;
    for (const line of readFileSync(path, 'utf-8').split(/\r?\n/)) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (!m || !ENV_ALLOWLIST.test(m[1]) || m[1] in process.env) continue;
      let value = m[2];
      if (
        value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))
      ) {
        // Quoted value: take it verbatim (an inline # inside quotes is data).
        value = value.slice(1, -1);
      } else {
        // Unquoted value: strip an inline comment (` #...`) the way dotenv does,
        // otherwise `KEY=v # note` yields the literal `v # note` and every API
        // call fails with an opaque auth error.
        const hash = value.search(/\s#/);
        if (hash !== -1) value = value.slice(0, hash).trimEnd();
      }
      process.env[m[1]] = value;
    }
  } catch {
    /* unreadable .env — rely on the real environment */
  }
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
 * Decide which directory code may be read from when working with a SAVED
 * report. Reads are already confined to report.projectPath — but the report
 * also CHOOSES that path, so a manipulated report could point the read root
 * anywhere the operator can read. Trust rule: the recorded root is honored
 * only when it resolves to the current working directory or below; anything
 * else must be asserted explicitly by the operator via --root.
 *
 * Returns the resolved root, or a human-readable refusal reason. Symlinks are
 * resolved on both sides so a link inside cwd cannot smuggle the root out.
 */
export function checkReportRoot(recordedPath: string, rootOverride?: string): { root: string } | { reason: string } {
  if (rootOverride !== undefined) {
    const abs = resolve(rootOverride);
    if (!isDirectory(abs)) return { reason: `--root is not a directory: ${abs}` };
    return { root: abs };
  }
  let real: string;
  try {
    real = realpathSync(resolve(recordedPath));
  } catch {
    return { reason: `the project path recorded in the report does not exist: ${recordedPath}` };
  }
  if (!isDirectory(real)) return { reason: `the recorded project path is not a directory: ${real}` };
  const cwd = realpathSync(process.cwd());
  // Containment via relative(): '' means real === cwd; a path starting with '..'
  // or an absolute path means it's outside. Using relative() instead of a
  // `cwd + sep` prefix avoids the `cwd === '/'` edge (prefix '//') that refused
  // every report when the process ran from a filesystem root (docker no WORKDIR).
  const rel = relative(cwd, real);
  if (rel !== '' && (rel.startsWith('..') || isAbsolute(rel))) {
    return { reason: `the report records a project path outside the current directory: ${real}` };
  }
  return { root: real };
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
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

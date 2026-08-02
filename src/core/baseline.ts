import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile, realpath } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import type { AuditReport } from './types.js';
import { runAudit } from './engine.js';
import { safeGitArgs, safeGitEnv } from '../utils/git-safe.js';

const execFileAsync = promisify(execFile);

/**
 * Resolve a baseline into an AuditReport. If `ref` is an existing `.json` file,
 * load it as a saved report. Otherwise treat it as a git ref (e.g. `origin/main`):
 * check it out into a temporary detached worktree, run a static-only audit there,
 * and clean up. The worktree shares the target repo's `.git`, so the ref must
 * exist in it.
 */
export async function resolveBaselineReport(ref: string, targetPath: string): Promise<AuditReport> {
  if (existsSync(ref) && ref.endsWith('.json')) {
    return JSON.parse(await readFile(ref, 'utf-8')) as AuditReport;
  }

  // The worktree checks out the whole repo, but the audit target may be a
  // subdirectory of it — audit the same relative path inside the worktree.
  let subPath = '';
  try {
    const { stdout } = await execFileAsync('git', [...safeGitArgs(), 'rev-parse', '--show-toplevel'], {
      cwd: targetPath,
      env: safeGitEnv(),
    });
    // realpath BOTH sides: on Windows git prints the long forward-slash path
    // while Node may hold an 8.3 short form (RUNNER~1) — relative() between
    // the two mismatched spellings fabricates a bogus subPath and the audit
    // then runs over a directory that does not exist.
    const top = await realpath(stdout.trim());
    subPath = relative(top, await realpath(resolve(targetPath)));
    if (subPath.startsWith('..')) subPath = ''; // outside toplevel — audit the whole worktree
  } catch {
    /* not a git repo — the worktree add below will fail with a clear message */
  }

  const parent = await mkdtemp(join(tmpdir(), 'prism-baseline-'));
  const worktree = join(parent, 'baseline');
  try {
    // SECURITY: `worktree add` performs a CHECKOUT of an untrusted repo →
    // post-checkout hooks + fsmonitor. safeGitArgs() neutralizes both; the
    // `--` terminates option parsing so a ref like `--foo` can't be read as a
    // flag. (Smudge/clean filters from the repo's own .gitattributes are the
    // documented residual; the zip path strips .git to close it for archives.)
    await execFileAsync('git', [...safeGitArgs(), 'worktree', 'add', '--detach', '--quiet', worktree, '--', ref], {
      cwd: targetPath,
      timeout: 60_000,
      env: safeGitEnv(),
    });
  } catch (err) {
    await rm(parent, { recursive: true, force: true });
    const detail = err instanceof Error ? err.message.split('\n')[0] : 'unknown error';
    throw new Error(`Could not resolve baseline '${ref}' (not a .json report or a valid git ref): ${detail}`);
  }

  try {
    // Static-only: the baseline never needs the AI layer.
    return await runAudit({ targetPath: subPath ? join(worktree, subPath) : worktree, ai: false });
  } finally {
    await execFileAsync('git', [...safeGitArgs(), 'worktree', 'remove', '--force', worktree], {
      cwd: targetPath,
      env: safeGitEnv(),
    }).catch(() => {});
    await rm(parent, { recursive: true, force: true }).catch(() => {});
  }
}

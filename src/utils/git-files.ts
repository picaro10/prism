import { execFile } from 'node:child_process';
import { safeGitArgs, safeGitEnv } from './git-safe.js';

/**
 * Relative (POSIX) paths of every file tracked in the git index under
 * rootPath, or null when git is missing or rootPath is not a work tree.
 *
 * Why this exists: the scanner filters its inventory through .gitignore, but
 * ignoring a file does NOT untrack it — a .env committed first and gitignored
 * later stays in the repository while becoming invisible to the inventory.
 * The index is the only source of truth for "is this actually committed".
 *
 * SECURITY: the repo is untrusted. `git ls-files` does not checkout (no hooks,
 * no smudge filters) but it DOES honor `core.fsmonitor` — a repo-config command
 * git spawns as the operator (verified). SAFE_GIT_ARGS/safeGitEnv neutralize
 * that (fsmonitor=false, hooksPath=/dev/null, system+global config ignored).
 * argv-only execFile (no shell); `--no-optional-locks` avoids touching the
 * index of a repo we only want to read.
 */
export function gitTrackedFiles(rootPath: string): Promise<string[] | null> {
  return new Promise((resolve) => {
    execFile(
      'git',
      [...safeGitArgs(), '--no-optional-locks', '-C', rootPath, 'ls-files', '-z'],
      { timeout: 10_000, maxBuffer: 64 * 1024 * 1024, env: safeGitEnv() },
      (err, stdout) => {
        if (err) return resolve(null);
        resolve(stdout.split('\0').filter(Boolean));
      },
    );
  });
}

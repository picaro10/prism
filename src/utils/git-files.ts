import { execFile } from 'node:child_process';

/**
 * Relative (POSIX) paths of every file tracked in the git index under
 * rootPath, or null when git is missing or rootPath is not a work tree.
 *
 * Why this exists: the scanner filters its inventory through .gitignore, but
 * ignoring a file does NOT untrack it — a .env committed first and gitignored
 * later stays in the repository while becoming invisible to the inventory.
 * The index is the only source of truth for "is this actually committed".
 *
 * argv-only execFile (no shell), and `git ls-files` never runs hooks — safe
 * to point at an untrusted repo.
 */
export function gitTrackedFiles(rootPath: string): Promise<string[] | null> {
  return new Promise((resolve) => {
    execFile(
      'git',
      ['-C', rootPath, 'ls-files', '-z'],
      { timeout: 10_000, maxBuffer: 64 * 1024 * 1024 },
      (err, stdout) => {
        if (err) return resolve(null);
        resolve(stdout.split('\0').filter(Boolean));
      },
    );
  });
}

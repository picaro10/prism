import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Local branch names of a repository, read directly from .git (no git binary,
 * no exec): loose refs under .git/refs/heads plus packed refs. Used by the
 * workflow analyzer to cross-check a workflow's branch filters against the
 * branches that actually exist — a check impossible for linters that see the
 * YAML in isolation.
 *
 * Returns [] when the directory is not a git repo or refs can't be read —
 * callers must treat [] as "unknown", never as "no branches".
 */
export function localBranches(rootPath: string): string[] {
  const gitDir = join(rootPath, '.git');
  const branches = new Set<string>();

  const headsDir = join(gitDir, 'refs', 'heads');
  const walk = (dir: string, prefix: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const abs = join(dir, entry);
      try {
        if (statSync(abs).isDirectory()) walk(abs, `${prefix}${entry}/`);
        else branches.add(`${prefix}${entry}`);
      } catch {
        /* unreadable ref — skip */
      }
    }
  };
  walk(headsDir, '');

  const packed = join(gitDir, 'packed-refs');
  if (existsSync(packed)) {
    try {
      for (const line of readFileSync(packed, 'utf-8').split('\n')) {
        const m = line.match(/^[0-9a-f]{40} refs\/heads\/(.+)$/);
        if (m) branches.add(m[1]);
      }
    } catch {
      /* unreadable packed-refs — loose refs may still have answered */
    }
  }

  return [...branches].sort();
}

import { readFileSync, readdirSync, lstatSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/** Depth cap for the refs walk — real ref hierarchies are shallow. */
const MAX_REF_DEPTH = 20;
/** Cap on packed-refs size read into memory (untrusted repo). */
const MAX_PACKED_REFS_BYTES = 5 * 1024 * 1024;

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
  // The repo is untrusted: use lstat (do NOT follow symlinks) and a depth cap
  // so a planted symlink loop (`.git/refs/heads/loop -> ../heads`) can't drive
  // infinite recursion / stack overflow.
  const walk = (dir: string, prefix: string, depth: number): void => {
    if (depth > MAX_REF_DEPTH) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const abs = join(dir, entry);
      try {
        const st = lstatSync(abs);
        if (st.isSymbolicLink()) continue; // never follow a ref symlink
        if (st.isDirectory()) walk(abs, `${prefix}${entry}/`, depth + 1);
        else branches.add(`${prefix}${entry}`);
      } catch {
        /* unreadable ref — skip */
      }
    }
  };
  walk(headsDir, '', 0);

  const packed = join(gitDir, 'packed-refs');
  if (existsSync(packed)) {
    try {
      if (lstatSync(packed).size > MAX_PACKED_REFS_BYTES) throw new Error('packed-refs too large');
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

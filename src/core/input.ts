import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, basename, resolve, sep } from 'node:path';
import AdmZip from 'adm-zip';

const execFileAsync = promisify(execFile);

// Temp dirs created for clones/extractions still in flight. On Ctrl-C (which can
// land mid-clone, before resolveTarget returns a cleanup handle) a signal handler
// removes them synchronously, so an interrupted run never leaves temps behind.
const activeTemps = new Set<string>();
let signalHandlerRegistered = false;
function trackTemp(dir: string): void {
  activeTemps.add(dir);
  if (!signalHandlerRegistered) {
    signalHandlerRegistered = true;
    process.once('SIGINT', () => {
      for (const d of activeTemps) {
        try {
          rmSync(d, { recursive: true, force: true });
        } catch {
          /* best effort */
        }
      }
      process.exit(130); // 128 + SIGINT
    });
  }
}
function untrackTemp(dir: string): void {
  activeTemps.delete(dir);
}

/** What a target string resolved to: a local path plus how to dispose of it. */
export interface ResolvedTarget {
  /** Absolute local path ready to be scanned. */
  path: string;
  /** 'local' | 'git' | 'zip' — how the target was obtained. */
  source: 'local' | 'git' | 'zip';
  /** Removes any temporary copy (no-op for local paths). */
  cleanup: () => Promise<void>;
}

/**
 * True for strings that are unambiguously git URLs, never local paths:
 * http(s)/ssh URLs, scp-style git@host:..., or anything ending in .git.
 * Plain `user/repo` shorthand is NOT accepted — it collides with local dirs.
 */
export function isGitUrl(target: string): boolean {
  if (target.startsWith('-')) return false; // a leading '-' is a CLI flag, never a URL
  return /^(https?|ssh|git):\/\//.test(target) || /^git@[^/]+:/.test(target) || target.endsWith('.git');
}

/**
 * Reject git targets that would let `git clone` execute arbitrary commands.
 * Two real RCE vectors: argument injection (a target starting with '-' that
 * git reads as a flag, e.g. `--upload-pack=...`) and remote-helper transports
 * (`ext::<cmd>`, and any `scheme::address` form — `ext::` runs shell commands
 * by design). Everything else (http/https/ssh/git/file URLs, scp-style
 * git@host:path, local .git paths) is a plain repository reference and safe.
 */
export function assertSafeGitUrl(url: string): void {
  if (url.startsWith('-')) {
    throw new Error(`Refusing to clone unsafe target (looks like a CLI flag): ${url}`);
  }
  if (/^[a-z][a-z0-9+.-]*::/i.test(url)) {
    throw new Error(`Refusing to clone unsafe git transport (remote helpers can run commands): ${url}`);
  }
}

/** Repo name from a git URL: trailing path segment minus .git. */
export function repoNameFromUrl(url: string): string {
  const tail = url.replace(/\/+$/, '').split(/[/:]/).pop();
  const name = (tail ?? 'repo').replace(/\.git$/, '');
  return name || 'repo';
}

/**
 * Shallow-clone a git URL into a fresh temp directory named after the repo
 * (so the derived project name is the repo name, not a mkdtemp suffix).
 */
export async function cloneRepo(url: string): Promise<ResolvedTarget> {
  assertSafeGitUrl(url);
  const parent = await mkdtemp(join(tmpdir(), 'prism-clone-'));
  trackTemp(parent);
  const dest = join(parent, repoNameFromUrl(url));
  try {
    // `--` terminates option parsing so a URL can never be read as a flag.
    await execFileAsync('git', ['clone', '--depth', '1', '--quiet', '--', url, dest], {
      timeout: 120_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, // fail instead of prompting for credentials
    });
  } catch (err) {
    untrackTemp(parent);
    await rm(parent, { recursive: true, force: true });
    const detail = err instanceof Error ? err.message.split('\n')[0] : 'unknown error';
    throw new Error(`Could not clone ${url}: ${detail}`);
  }
  return {
    path: dest,
    source: 'git',
    cleanup: () => {
      untrackTemp(parent);
      return rm(parent, { recursive: true, force: true });
    },
  };
}

/**
 * Extract a .zip into a fresh temp directory named after the archive.
 * Entries that would escape the destination (zip-slip: '../', absolute
 * paths) are rejected outright — an archive is untrusted input.
 */
export async function extractZip(zipPath: string): Promise<ResolvedTarget> {
  const parent = await mkdtemp(join(tmpdir(), 'prism-zip-'));
  trackTemp(parent);
  const dest = join(parent, basename(zipPath).replace(/\.zip$/i, '') || 'archive');
  await mkdir(dest, { recursive: true });

  try {
    const zip = new AdmZip(zipPath);
    for (const entry of zip.getEntries()) {
      const target = resolve(dest, entry.entryName);
      if (target !== dest && !target.startsWith(dest + sep)) {
        throw new Error(`unsafe entry path: ${entry.entryName}`);
      }
    }
    zip.extractAllTo(dest, true);
  } catch (err) {
    untrackTemp(parent);
    await rm(parent, { recursive: true, force: true });
    const detail = err instanceof Error ? err.message : 'unknown error';
    throw new Error(`Could not extract ${zipPath}: ${detail}`);
  }
  return {
    path: dest,
    source: 'zip',
    cleanup: () => {
      untrackTemp(parent);
      return rm(parent, { recursive: true, force: true });
    },
  };
}

/**
 * Resolve an analyze target — git URL, .zip archive, or local path — to a
 * local directory. The caller must invoke cleanup() when done (a no-op for
 * local paths).
 */
export async function resolveTarget(target: string): Promise<ResolvedTarget> {
  if (isGitUrl(target)) return cloneRepo(target);
  if (/\.zip$/i.test(target)) return extractZip(resolve(target));
  return { path: resolve(target), source: 'local', cleanup: async () => {} };
}

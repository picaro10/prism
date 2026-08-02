import { readFile, writeFile, mkdir, lstat } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';

const PKG = '@latenciatech/prism';
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Cache path in a PER-USER subdirectory of the (world-writable) tmpdir. A fixed
 * shared path let any local user pre-create it as a symlink and have PRISM
 * overwrite the link target, or poison the file so a crafted `latest` string
 * (with terminal escapes) got printed. The per-user dir + a symlink check on
 * write + version-shape validation on read close that.
 */
function cacheDir(): string {
  let uid = 'shared';
  try {
    const u = userInfo().uid;
    if (typeof u === 'number' && u >= 0) uid = String(u);
  } catch {
    /* windows / no uid — fall back to a named dir */
  }
  return join(tmpdir(), `prism-cache-${uid}`);
}
const CACHE_FILE = join(cacheDir(), 'update-check.json');
const VERSION_RE = /^v?\d+(\.\d+){0,3}(-[0-9A-Za-z.-]+)?$/;

/** Parse a dotted version into numeric components (missing parts → 0). */
export function parseVersion(v: string): number[] {
  return v
    .trim()
    .replace(/^v/, '')
    .split('.')
    .map((n) => Number.parseInt(n, 10) || 0);
}

/** True when `latest` is strictly greater than `current` (semver-ish, numeric). */
export function isNewer(current: string, latest: string): boolean {
  const a = parseVersion(current);
  const b = parseVersion(latest);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (y > x) return true;
    if (y < x) return false;
  }
  return false;
}

/** Whether enough time has passed since the last check (default 24h). */
export function shouldCheck(lastCheckMs: number | undefined, now: number, intervalMs = DAY_MS): boolean {
  if (!lastCheckMs) return true;
  return now - lastCheckMs >= intervalMs;
}

export interface UpdateCheckDeps {
  now: number;
  env: NodeJS.ProcessEnv;
  fetchLatest: () => Promise<string | null>;
  readCache: () => Promise<{ lastCheck?: number; latest?: string } | null>;
  writeCache: (data: { lastCheck: number; latest: string }) => Promise<void>;
}

export interface UpdateInfo {
  current: string;
  latest: string;
  hasUpdate: boolean;
}

/**
 * Return update info if a newer version exists, else null. Rate-limited to once
 * per interval via a cache file; opts out on PRISM_NO_UPDATE_CHECK. Fully
 * error-safe — any failure (offline, bad cache) yields null. Sends only the
 * package name to the registry (a plain GET), never any user data.
 */
export async function checkForUpdate(current: string, deps: UpdateCheckDeps): Promise<UpdateInfo | null> {
  try {
    if (deps.env.PRISM_NO_UPDATE_CHECK) return null;
    const cache = await deps.readCache().catch(() => null);
    if (!shouldCheck(cache?.lastCheck, deps.now)) {
      // Use the cached latest without hitting the network.
      if (cache?.latest && isNewer(current, cache.latest)) {
        return { current, latest: cache.latest, hasUpdate: true };
      }
      return null;
    }
    const latest = await deps.fetchLatest();
    if (!latest) return null;
    await deps.writeCache({ lastCheck: deps.now, latest }).catch(() => {});
    return isNewer(current, latest) ? { current, latest, hasUpdate: true } : null;
  } catch {
    return null;
  }
}

/** Fetch the latest published version from the npm registry, with a short timeout. */
export async function fetchLatestFromNpm(): Promise<string | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1500);
    const res = await fetch(`https://registry.npmjs.org/${PKG}/latest`, {
      signal: ctrl.signal,
      headers: { accept: 'application/json' },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const body = (await res.json()) as { version?: string };
    return typeof body.version === 'string' ? body.version : null;
  } catch {
    return null;
  }
}

export const defaultDeps = (): UpdateCheckDeps => ({
  now: Date.now(),
  env: process.env,
  fetchLatest: fetchLatestFromNpm,
  readCache: async () => {
    const parsed = JSON.parse(await readFile(CACHE_FILE, 'utf-8'));
    // Poisoned-cache guard: only trust a well-formed version string.
    if (parsed && typeof parsed.latest === 'string' && !VERSION_RE.test(parsed.latest)) {
      return { lastCheck: parsed.lastCheck };
    }
    return parsed;
  },
  writeCache: async (data) => {
    await mkdir(cacheDir(), { recursive: true, mode: 0o700 });
    // Never follow a symlink another user may have planted at the cache path.
    const st = await lstat(CACHE_FILE).catch(() => null);
    if (st?.isSymbolicLink()) return;
    await writeFile(CACHE_FILE, JSON.stringify(data), 'utf-8');
  },
});

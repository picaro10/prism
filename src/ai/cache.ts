import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { Finding } from '../core/types.js';
import {
  buildRemediationSystemPrompt,
  buildSystemPrompt,
  buildUserContent,
  buildVerificationSystemPrompt,
} from './prompt.js';
import type { TriageUnit } from './types.js';

/**
 * Verdict cache — the AI layer's memory between runs.
 *
 * A verdict is a function of what the model was asked: the prompts, the
 * model (and panel), the finding, and the exact content it read. If none of
 * that changed, asking again buys nothing and costs tokens. So every FINAL
 * verdict and fix is stored under a key that hashes all of it, and a later
 * run — the next CI push, a re-triage of a saved report, or the same run
 * resumed after a Ctrl-C — skips the calls whose answer it already has.
 *
 * What the key deliberately includes: the prompt texts (edit a prompt → every
 * entry misses), the client id (model, provider, panel composition), the
 * finding's identity (rule, file, title, description) and a hash of the
 * content sent with it. What it deliberately excludes: the project context
 * block (score, category summaries — they drift every run and steer the
 * verdict only marginally) and the line NUMBER (the content hash already
 * pins the code).
 *
 * What is never cached: a verdict synthesized because a call failed or the
 * model skipped a finding, or a panel result where a voter abstained on an
 * error. A transient failure must not be frozen as a judgment.
 *
 * Where it lives: the OPERATOR's cache directory, never inside the audited
 * project — a hostile repo cannot plant entries, and PRISM leaves no files in
 * the tree it audits. `PRISM_CACHE_DIR` overrides; otherwise
 * `$XDG_CACHE_HOME/prism`, `%LOCALAPPDATA%\prism\cache` on Windows, or
 * `~/.cache/prism`. One JSON file per project (keyed by its real path).
 *
 * Writes are synchronous and atomic (tmp + rename) after every store, so an
 * interrupted run keeps everything it had already judged. Any I/O failure
 * disables the cache for the run — silently degrading to "no cache", never
 * failing the triage.
 */

const CACHE_FORMAT = 1;
/** Entries kept per project file; the oldest-used are evicted beyond this. */
export const MAX_CACHE_ENTRIES = 5000;

interface Entry {
  value: unknown;
  /** ISO timestamp of the last read or write — eviction order. */
  usedAt: string;
}

interface CacheFile {
  format: number;
  entries: Record<string, Entry>;
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

/**
 * A fixed synthetic unit rendered through buildUserContent: its rendering is
 * part of the fingerprint, so a change to the USER-content format (how the
 * flagged line is quoted, how related files or content-less batches are laid
 * out) invalidates cached verdicts exactly like a system-prompt edit does.
 */
const SAMPLE_UNIT: TriageUnit = {
  file: 'src/sample.ts',
  content: 'const a = 1;\nconst b = secret;\n',
  findings: [
    {
      id: 'SEC-SAMPLE',
      category: 'security',
      severity: 'high',
      title: 'sample',
      description: 'sample',
      file: 'src/sample.ts',
      line: 2,
      meta: { k: 'v' },
    },
  ],
  neighbors: [{ file: 'src/neighbor.ts', content: 'export const secret = 1;\n', reason: 'sample' }],
};
const SAMPLE_BATCH: TriageUnit = {
  file: null,
  content: '',
  findings: [
    {
      id: 'DEP-SAMPLE',
      category: 'dependencies',
      severity: 'low',
      title: 'sample',
      description: 'sample',
      file: 'package.json',
    },
  ],
};

/** Fingerprint of everything the model is told: system prompts + the user-content rendering. */
export function promptFingerprint(kind: 'triage' | 'remediation'): string {
  if (kind === 'remediation') {
    return sha256(`${buildRemediationSystemPrompt()}\n${buildUserContent(SAMPLE_UNIT, 'Findings to fix:')}`);
  }
  return sha256(
    [
      buildSystemPrompt(),
      buildVerificationSystemPrompt(),
      buildUserContent(SAMPLE_UNIT),
      buildUserContent(SAMPLE_BATCH),
    ].join('\n'),
  );
}
const TRIAGE_PROMPT_FINGERPRINT = promptFingerprint('triage');
const REMEDIATION_PROMPT_FINGERPRINT = promptFingerprint('remediation');

export interface KeyParts {
  kind: 'triage' | 'remediation';
  /** Client identity — provider + model (+ panel members for triage). */
  judge: string;
  /** The exact content the model reads with the finding ('' for a content-less batch). */
  content: string;
  finding: Finding;
}

/** Cache key for one finding's verdict or fix. Pure — no I/O. */
export function cacheKey(parts: KeyParts): string {
  const prompt = parts.kind === 'triage' ? TRIAGE_PROMPT_FINGERPRINT : REMEDIATION_PROMPT_FINGERPRINT;
  const f = parts.finding;
  return sha256(
    [parts.kind, prompt, parts.judge, sha256(parts.content), f.id, f.file ?? '', f.title, f.description].join('\0'),
  );
}

/**
 * The judge identity string: client, optional verification panel, and
 * whether the verify pass ran. A false-positive that skipped the skeptical
 * re-check (`--no-ai-verify`) is a different, weaker verdict than one that
 * survived it — it must never be served to a run that asked for verification.
 */
export function judgeId(
  clientId: string | undefined,
  verifierIds: Array<string | undefined> = [],
  opts: { verify?: boolean } = {},
): string {
  const panel = verifierIds.map((v) => v ?? 'unknown');
  const base = `${clientId ?? 'unknown'}${panel.length ? `|panel:${panel.join(',')}` : ''}`;
  return opts.verify === false ? `${base}|noverify` : base;
}

/** Resolve the operator's cache directory (see module doc). */
export function cacheBaseDir(env: NodeJS.ProcessEnv = process.env, platform = process.platform): string {
  if (env.PRISM_CACHE_DIR) return env.PRISM_CACHE_DIR;
  if (env.XDG_CACHE_HOME) return join(env.XDG_CACHE_HOME, 'prism');
  if (platform === 'win32' && env.LOCALAPPDATA) return join(env.LOCALAPPDATA, 'prism', 'cache');
  return join(homedir(), '.cache', 'prism');
}

export class VerdictCache {
  private data: CacheFile | null = null;
  /** Set after an I/O failure: reads keep working from memory, writes stop. */
  disabled = false;
  readonly stats = { hits: 0, misses: 0, writes: 0 };

  /** `maxEntries` is injectable so eviction is testable without thousands of synchronous writes. */
  constructor(
    readonly filePath: string,
    private readonly maxEntries = MAX_CACHE_ENTRIES,
  ) {}

  /** The cache file for a project root, under the operator's cache dir. */
  static forProject(projectRoot: string, env: NodeJS.ProcessEnv = process.env): VerdictCache {
    let real = projectRoot;
    try {
      real = realpathSync(projectRoot);
    } catch {
      // A root that cannot be resolved still gets a stable (path-string) key.
    }
    const file = join(cacheBaseDir(env), 'verdicts', `${sha256(real).slice(0, 16)}.json`);
    return new VerdictCache(file);
  }

  get(key: string): unknown | undefined {
    const entry = this.load().entries[key];
    if (!entry) {
      this.stats.misses++;
      return undefined;
    }
    this.stats.hits++;
    entry.usedAt = new Date().toISOString();
    return entry.value;
  }

  put(key: string, value: unknown): void {
    const data = this.load();
    data.entries[key] = { value, usedAt: new Date().toISOString() };
    this.evict(data);
    this.persist(data);
  }

  /** Number of entries currently held (after any eviction). */
  size(): number {
    return Object.keys(this.load().entries).length;
  }

  private load(): CacheFile {
    if (this.data) return this.data;
    let parsed: CacheFile | null = null;
    try {
      if (existsSync(this.filePath)) {
        const raw = JSON.parse(readFileSync(this.filePath, 'utf-8')) as Partial<CacheFile>;
        if (raw && raw.format === CACHE_FORMAT && raw.entries && typeof raw.entries === 'object') {
          parsed = { format: CACHE_FORMAT, entries: raw.entries as Record<string, Entry> };
        }
      }
    } catch {
      // Corrupt or unreadable cache: start empty. Never let a cache file break a triage.
      parsed = null;
    }
    this.data = parsed ?? { format: CACHE_FORMAT, entries: {} };
    return this.data;
  }

  private evict(data: CacheFile): void {
    const keys = Object.keys(data.entries);
    if (keys.length <= this.maxEntries) return;
    const oldest = keys
      .sort((a, b) => data.entries[a].usedAt.localeCompare(data.entries[b].usedAt))
      .slice(0, keys.length - this.maxEntries);
    for (const k of oldest) delete data.entries[k];
  }

  private persist(data: CacheFile): void {
    if (this.disabled) return;
    try {
      mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
      const tmp = `${this.filePath}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
      renameSync(tmp, this.filePath);
      this.stats.writes++;
    } catch {
      // Read-only home, full disk, permissions: degrade to "no cache", never fail the run.
      this.disabled = true;
    }
  }
}

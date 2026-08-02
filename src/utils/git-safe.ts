import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Hardened git invocation flags/env for running git against an UNTRUSTED repo.
 *
 * The threat: a repo can ship its own `.git/config` (e.g. unpacked from a zip
 * or a directory the operator points at) with `core.fsmonitor = <cmd>`,
 * `core.hooksPath`, or filter drivers. git will happily spawn those as the
 * operator. `safe.directory` does NOT help — it only guards by ownership, and
 * a tree the operator unpacked is owned by the operator.
 *
 * - `core.fsmonitor=false` neutralizes the fsmonitor command (fires even on
 *   plumbing like `ls-files`, no checkout needed — verified: it executes).
 * - `core.hooksPath=<empty dir>` points hooks at a directory we own that holds
 *   no hook files, so no repo hook (post-checkout etc.) can run.
 * - `protocol.ext.allow=never` blocks `ext::` remote-helper transports.
 * - `GIT_CONFIG_NOSYSTEM=1` + `GIT_CONFIG_GLOBAL=<empty file>` ignore system and
 *   global config so only the (now-hardened) repo config is in play.
 *
 * We use a real empty DIRECTORY and a real empty FILE rather than `/dev/null`:
 * the null device is not portable as a git path (native Windows git rejects
 * `core.hooksPath=/dev/null` and `GIT_CONFIG_GLOBAL=\\.\nul`), which broke the
 * whole invocation on Windows. An empty dir/file is unambiguous on every OS.
 *
 * Residual (documented): a checkout (`git worktree add`) still applies
 * `.gitattributes`-selected smudge/clean filters from the repo config; there is
 * no single git switch to disable per-name filters. The zip path removes `.git/`
 * entirely (see input.ts), closing that vector for downloaded archives; for a
 * local repo the operator points at, hooks and fsmonitor — the automated
 * vectors — are closed here.
 */
let cached: { hooksDir: string; emptyConfig: string } | undefined;
function ensureSafeGitPaths(): { hooksDir: string; emptyConfig: string } {
  if (!cached) {
    const dir = mkdtempSync(join(tmpdir(), 'prism-gitsafe-'));
    const emptyConfig = join(dir, 'empty.gitconfig');
    writeFileSync(emptyConfig, '');
    cached = { hooksDir: dir, emptyConfig };
  }
  return cached;
}

/** Hardening `-c` flags — placed before the git subcommand. */
export function safeGitArgs(): string[] {
  const { hooksDir } = ensureSafeGitPaths();
  return ['-c', 'core.fsmonitor=false', '-c', `core.hooksPath=${hooksDir}`, '-c', 'protocol.ext.allow=never'];
}

/** The hardened env merged over the current process env. */
export function safeGitEnv(): NodeJS.ProcessEnv {
  const { emptyConfig } = ensureSafeGitPaths();
  return {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: emptyConfig,
    GIT_TERMINAL_PROMPT: '0',
  };
}

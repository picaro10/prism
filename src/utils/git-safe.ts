import { devNull } from 'node:os';

/**
 * Hardened git invocation flags/env for running git against an UNTRUSTED repo.
 *
 * The threat: a repo can ship its own `.git/config` (e.g. unpacked from a zip
 * or a directory the operator points at) with `core.fsmonitor = <cmd>`,
 * `core.hooksPath`, or filter drivers. git will happily spawn those as the
 * operator. `safe.directory` does NOT help — it only guards by ownership, and
 * a tree the operator unpacked is owned by the operator.
 *
 * `-c core.fsmonitor=false` — neutralizes the fsmonitor command (fires on
 *   plumbing like `ls-files`, no checkout needed — verified: it executes).
 * `-c core.hooksPath=/dev/null` — no repo hook (post-checkout etc.) can run.
 * `-c protocol.ext.allow=never` — blocks `ext::` remote-helper transports.
 * GIT_CONFIG_NOSYSTEM / GIT_CONFIG_GLOBAL=devnull — ignore system + global
 *   config so only the (still-hardened) repo config is in play.
 * GIT_TERMINAL_PROMPT=0 — never block on credential prompts.
 *
 * Residual (documented): a checkout (`git worktree add`) still applies
 * `.gitattributes`-selected smudge/clean filters from the repo config; there
 * is no single git switch to disable per-name filters. The zip path removes
 * `.git/` entirely (see input.ts), which closes that vector for downloaded
 * archives; for a local repo the operator explicitly pointed at, hooks and
 * fsmonitor — the automated vectors — are closed here.
 */
export const SAFE_GIT_ARGS: readonly string[] = [
  '-c',
  'core.fsmonitor=false',
  '-c',
  'core.hooksPath=/dev/null',
  '-c',
  'protocol.ext.allow=never',
];

export const SAFE_GIT_ENV: Readonly<Record<string, string>> = {
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: devNull,
  GIT_TERMINAL_PROMPT: '0',
};

/** Merge the hardened env over the current process env. */
export function safeGitEnv(): NodeJS.ProcessEnv {
  return { ...process.env, ...SAFE_GIT_ENV };
}

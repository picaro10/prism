import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { gitTrackedFiles } from '../../src/utils/git-files.js';
import { resolveBaselineReport } from '../../src/core/baseline.js';

// Threat model: an untrusted repo ships its own .git/config with a
// core.fsmonitor / hook command. git spawns those as the operator on ordinary
// plumbing/checkout calls. These tests plant such a landmine and assert PRISM's
// git invocations do NOT trip it.

const CANARY = join(tmpdir(), `prism-pwned-canary-${process.pid}`);

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, {
    cwd,
    stdio: 'ignore',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 't',
      GIT_AUTHOR_EMAIL: 't@t',
      GIT_COMMITTER_NAME: 't',
      GIT_COMMITTER_EMAIL: 't@t',
    },
  });
}

describe('git invocations are hardened against untrusted repo config', () => {
  let repo: string;

  beforeAll(async () => {
    repo = await mkdtemp(join(tmpdir(), 'prism-hostile-'));
    git(repo, 'init', '-q');
    await writeFile(join(repo, 'a.txt'), 'x\n');
    git(repo, 'add', 'a.txt');
    git(repo, 'commit', '-q', '-m', 'init');
    // The landmine: fsmonitor writes a canary file if git ever runs it.
    git(repo, 'config', 'core.fsmonitor', `sh -c "touch ${CANARY}; false"`);
    await rm(CANARY, { force: true });
  });

  afterAll(async () => {
    await rm(repo, { recursive: true, force: true });
    await rm(CANARY, { force: true });
  });

  it('gitTrackedFiles does not execute core.fsmonitor', async () => {
    const tracked = await gitTrackedFiles(repo);
    expect(tracked).toContain('a.txt'); // still works
    let fired = false;
    try {
      await import('node:fs/promises').then((fs) => fs.access(CANARY));
      fired = true;
    } catch {
      fired = false;
    }
    expect(fired).toBe(false); // fsmonitor never ran
  });

  it('resolveBaselineReport (worktree checkout) does not execute a post-checkout hook', async () => {
    // Plant a hook that writes the canary on checkout.
    const hookDir = join(repo, '.git', 'hooks');
    await writeFile(join(hookDir, 'post-checkout'), `#!/bin/sh\ntouch ${CANARY}\n`, { mode: 0o755 });
    await rm(CANARY, { force: true });
    // HEAD is a valid ref; run a baseline audit against it.
    await resolveBaselineReport('HEAD', repo);
    let fired = false;
    try {
      await import('node:fs/promises').then((fs) => fs.access(CANARY));
      fired = true;
    } catch {
      fired = false;
    }
    expect(fired).toBe(false); // hook never ran
  });
});

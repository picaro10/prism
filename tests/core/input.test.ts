import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import AdmZip from 'adm-zip';
import {
  isGitUrl,
  assertSafeGitUrl,
  repoNameFromUrl,
  extractZip,
  cloneRepo,
  resolveTarget,
} from '../../src/core/input.js';

const exec = promisify(execFile);

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

describe('isGitUrl', () => {
  it('accepts https/ssh/scp-style and .git targets', () => {
    expect(isGitUrl('https://github.com/user/repo')).toBe(true);
    expect(isGitUrl('http://gitlab.com/user/repo.git')).toBe(true);
    expect(isGitUrl('git@github.com:user/repo.git')).toBe(true);
    expect(isGitUrl('ssh://git@host/repo')).toBe(true);
    expect(isGitUrl('/some/local/bare-repo.git')).toBe(true);
  });

  it('rejects local paths and user/repo shorthand (collides with dirs)', () => {
    expect(isGitUrl('/opt/prism')).toBe(false);
    expect(isGitUrl('./project')).toBe(false);
    expect(isGitUrl('user/repo')).toBe(false);
  });

  it('rejects targets that start with "-" (would be read as a git flag)', () => {
    expect(isGitUrl('--upload-pack=sh -c "id" x.git')).toBe(false);
  });
});

describe('assertSafeGitUrl', () => {
  it('accepts ordinary remote and local repo references', () => {
    expect(() => assertSafeGitUrl('https://github.com/user/repo.git')).not.toThrow();
    expect(() => assertSafeGitUrl('git@github.com:user/repo.git')).not.toThrow();
    expect(() => assertSafeGitUrl('ssh://git@host/repo.git')).not.toThrow();
    expect(() => assertSafeGitUrl('file:///some/local/repo.git')).not.toThrow();
    expect(() => assertSafeGitUrl('/some/local/bare-repo.git')).not.toThrow();
  });

  it('rejects argument injection (leading "-")', () => {
    expect(() => assertSafeGitUrl('--upload-pack=sh -c "id" x.git')).toThrow(/unsafe target/);
  });

  it('rejects command-executing remote-helper transports (ext::, fd::)', () => {
    expect(() => assertSafeGitUrl('ext::sh -c "id" x.git')).toThrow(/unsafe git transport/);
    expect(() => assertSafeGitUrl('fd::7,8.git')).toThrow(/unsafe git transport/);
  });

  it('is enforced by cloneRepo before any clone runs', async () => {
    await expect(cloneRepo('ext::sh -c "touch /tmp/pwned" x.git')).rejects.toThrow(/unsafe git transport/);
    await expect(cloneRepo('--upload-pack=sh -c "id" x.git')).rejects.toThrow(/unsafe target/);
  });
});

describe('repoNameFromUrl', () => {
  it('extracts the repo name from common URL shapes', () => {
    expect(repoNameFromUrl('https://github.com/latenciatech/prism.git')).toBe('prism');
    expect(repoNameFromUrl('git@github.com:user/my-repo.git')).toBe('my-repo');
    expect(repoNameFromUrl('https://github.com/user/repo/')).toBe('repo');
  });
});

describe('extractZip', () => {
  it('extracts an archive into a temp dir named after it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'prism-zip-src-'));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const zip = new AdmZip();
    zip.addFile('package.json', Buffer.from('{"name":"zipped-app"}'));
    zip.addFile('src/index.ts', Buffer.from('export const x = 1;'));
    const zipPath = join(dir, 'zipped-app.zip');
    await writeFile(zipPath, zip.toBuffer());

    const resolved = await extractZip(zipPath);
    cleanups.push(resolved.cleanup);
    expect(resolved.source).toBe('zip');
    expect(resolved.path.endsWith('zipped-app')).toBe(true);
    await expect(access(join(resolved.path, 'src/index.ts'))).resolves.toBeUndefined();
  });

  it('rejects zip-slip entries that escape the destination', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'prism-zip-evil-'));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    // adm-zip sanitizes names on addFile, but a hostile archive arrives with
    // the traversal bytes already in place — forge one by patching the raw
    // buffer ('AA/' and '../' have the same length, so offsets survive).
    const zip = new AdmZip();
    zip.addFile('AA/evil.txt', Buffer.from('pwned'));
    const forged = Buffer.from(zip.toBuffer().toString('latin1').replaceAll('AA/evil.txt', '../evil.txt'), 'latin1');
    const zipPath = join(dir, 'evil.zip');
    await writeFile(zipPath, forged);

    await expect(extractZip(zipPath)).rejects.toThrow(/unsafe entry path/);
  });

  it('throws a clear error for a corrupt archive', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'prism-zip-bad-'));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const zipPath = join(dir, 'corrupt.zip');
    await writeFile(zipPath, 'this is not a zip');
    await expect(extractZip(zipPath)).rejects.toThrow(/Could not extract/);
  });
});

describe('cloneRepo', () => {
  it('shallow-clones a local repo via file:// URL', async () => {
    // Build a tiny real git repo to clone — no network needed.
    const srcDir = await mkdtemp(join(tmpdir(), 'prism-git-src-'));
    cleanups.push(() => rm(srcDir, { recursive: true, force: true }));
    await mkdir(join(srcDir, 'tiny-proj'));
    const repo = join(srcDir, 'tiny-proj');
    await writeFile(join(repo, 'README.md'), '# tiny');
    const git = (...args: string[]) => exec('git', ['-C', repo, ...args]);
    await git('init', '--quiet');
    await git('-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '.');
    await git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '--quiet', '-m', 'init');

    const resolved = await cloneRepo(`file://${repo}`);
    cleanups.push(resolved.cleanup);
    expect(resolved.source).toBe('git');
    expect(resolved.path.endsWith('tiny-proj')).toBe(true);
    await expect(access(join(resolved.path, 'README.md'))).resolves.toBeUndefined();
  });

  it('throws a clear error when the clone fails', async () => {
    await expect(cloneRepo('file:///nonexistent/nowhere.git')).rejects.toThrow(/Could not clone/);
  });
});

describe('resolveTarget', () => {
  it('passes local paths through with a no-op cleanup', async () => {
    const r = await resolveTarget('/opt/prism');
    expect(r).toMatchObject({ path: '/opt/prism', source: 'local' });
    await r.cleanup(); // must not throw
  });
});

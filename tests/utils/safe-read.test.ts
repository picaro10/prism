import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveWithin, confinedReader } from '../../src/utils/safe-read.js';

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'prism-safe-read-'));
  mkdirSync(join(root, 'src'));
  writeFileSync(join(root, 'src', 'a.ts'), 'export const a = 1;\n');
  writeFileSync(join(tmpdir(), 'prism-outside-secret.txt'), 'outside\n');
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(join(tmpdir(), 'prism-outside-secret.txt'), { force: true });
});

describe('resolveWithin', () => {
  it('resolves a normal relative path inside the root', () => {
    expect(resolveWithin(root, 'src/a.ts')).toBe(join(root, 'src', 'a.ts'));
  });

  it('rejects absolute paths', () => {
    expect(() => resolveWithin(root, '/etc/passwd')).toThrow(/absolute/);
  });

  it('rejects ../ escapes (a manipulated report must not read outside its projectPath)', () => {
    expect(() => resolveWithin(root, '../prism-outside-secret.txt')).toThrow(/escapes/);
    expect(() => resolveWithin(root, 'src/../../prism-outside-secret.txt')).toThrow(/escapes/);
  });

  it('allows ../ that stays inside the root', () => {
    expect(resolveWithin(root, 'src/../src/a.ts')).toBe(join(root, 'src', 'a.ts'));
  });
});

describe('confinedReader', () => {
  it('reads a file inside the root', async () => {
    const reader = confinedReader(root);
    expect(await reader('src/a.ts')).toContain('export const a');
  });

  it('refuses to read outside the root', async () => {
    const reader = confinedReader(root);
    await expect(reader('../prism-outside-secret.txt')).rejects.toThrow(/escapes/);
    await expect(reader('/etc/passwd')).rejects.toThrow(/absolute/);
  });
});

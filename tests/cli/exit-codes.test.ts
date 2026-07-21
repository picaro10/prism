import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';

const exec = promisify(execFile);
const CLI = resolve(__dirname, '../../src/cli/index.ts');
const ROOT = resolve(__dirname, '../..');
const FIXTURE = resolve(__dirname, '../fixtures/sample-project'); // scores well below 10

/** Run the CLI via tsx and return its exit code (0 when it resolves). */
async function runExit(args: string[]): Promise<number> {
  try {
    await exec('npx', ['tsx', CLI, ...args], { cwd: ROOT });
    return 0;
  } catch (err) {
    return (err as { code?: number }).code ?? -1;
  }
}

describe('analyze exit codes (agent/CI contract)', () => {
  it('exits 0 when the score meets the threshold', async () => {
    expect(await runExit(['analyze', ROOT])).toBe(0);
  }, 60_000);

  it('exits 1 when the score is below --min-score (findings)', async () => {
    // A high threshold the fixture cannot meet → result failure, not an error.
    expect(await runExit(['analyze', FIXTURE, '--min-score', '9.9'])).toBe(1);
  }, 60_000);

  it('exits 2 on a usage error (unknown --only category)', async () => {
    expect(await runExit(['analyze', ROOT, '--only', 'nope'])).toBe(2);
  }, 60_000);

  it('exits 2 on a usage error (nonexistent path)', async () => {
    expect(await runExit(['analyze', '/nonexistent/nowhere'])).toBe(2);
  }, 60_000);

  it('exits 2 on an out-of-range --min-score', async () => {
    expect(await runExit(['analyze', ROOT, '--min-score', '11'])).toBe(2);
  }, 60_000);
});

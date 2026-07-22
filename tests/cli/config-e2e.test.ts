import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, resolve } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';

const exec = promisify(execFile);
const CLI = resolve(__dirname, '../../src/cli/index.ts');
const ROOT = resolve(__dirname, '../..');

async function runExit(args: string[]): Promise<number> {
  try {
    await exec('npx', ['tsx', CLI, ...args], { cwd: ROOT });
    return 0;
  } catch (err) {
    return (err as { code?: number }).code ?? -1;
  }
}

/**
 * A minimal project with two deterministic criticals: a Stripe live key
 * (SEC-STRIPE-SK) and no tests (TST-001). Small enough to audit in ms.
 */
let project: string;

beforeAll(() => {
  project = mkdtempSync(join(tmpdir(), 'prism-config-e2e-'));
  mkdirSync(join(project, 'src'));
  // The fake Stripe key is assembled at runtime so the contiguous literal never
  // exists in this repo (GitHub push protection would block it — correctly).
  // The file WRITTEN to the temp project does contain it, which is the point.
  const fakeStripeKey = ['sk', 'live', 'abcDEF123456789012345678'].join('_');
  writeFileSync(join(project, 'src', 'config.ts'), `const key = "${fakeStripeKey}";\n`);
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'config-e2e', version: '1.0.0' }));
});

afterAll(() => {
  rmSync(project, { recursive: true, force: true });
});

function writeConfig(config: unknown): void {
  writeFileSync(join(project, 'prism.config.json'), JSON.stringify(config));
}

describe('prism.config.json end to end', () => {
  it('a failOn gate from the config file fails the run', async () => {
    writeConfig({ failOn: 'critical' });
    expect(await runExit(['analyze', project])).toBe(1);
  }, 60_000);

  it('justified suppressions rescue the same gate', async () => {
    writeConfig({
      failOn: 'critical',
      suppressions: [
        { rule: 'SEC-STRIPE-SK', file: 'src/**', reason: 'sandbox key' },
        { rule: 'TST-001', reason: 'demo project' },
      ],
    });
    expect(await runExit(['analyze', project])).toBe(0);
  }, 60_000);

  it('--no-config ignores the file (its gate no longer fires)', async () => {
    writeConfig({ failOn: 'critical' });
    expect(await runExit(['analyze', project, '--no-config'])).toBe(0);
  }, 60_000);

  it('an invalid config file is a usage error (exit 2)', async () => {
    writeConfig({ minscore: 8 }); // typo → strict schema rejects
    expect(await runExit(['analyze', project])).toBe(2);
  }, 60_000);

  it('init --yes writes a config; running again without --force is a usage error', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-init-e2e-'));
    try {
      expect(await runExit(['init', '--yes', '--dir', dir])).toBe(0);
      expect(existsSync(join(dir, 'prism.config.json'))).toBe(true);
      expect(await runExit(['init', '--yes', '--dir', dir])).toBe(2);
      expect(await runExit(['init', '--yes', '--dir', dir, '--force'])).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});

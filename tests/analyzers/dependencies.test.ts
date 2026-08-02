import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DependenciesAnalyzer } from '../../src/analyzers/dependencies.js';
import { scanProject } from '../../src/core/scanner.js';

// The npm-audit path is gated on package-lock.json existing. These cases cover
// the "vulnerability status UNKNOWN, not clean" doctrine for package managers
// that npm audit can't check — without hitting the network.

describe('DependenciesAnalyzer — audit coverage honesty', () => {
  async function analyzeDir(dir: string) {
    const scan = await scanProject(dir);
    const analyzer = new DependenciesAnalyzer();
    return analyzer.analyze(scan, async (p) => readFile(join(dir, p), 'utf-8'));
  }

  let pnpm: string;
  beforeAll(async () => {
    pnpm = await mkdtemp(join(tmpdir(), 'prism-pnpm-'));
    await writeFile(join(pnpm, 'package.json'), JSON.stringify({ name: 'app', dependencies: { left: '1.0.0' } }));
    await writeFile(join(pnpm, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  });
  afterAll(async () => {
    await rm(pnpm, { recursive: true, force: true });
  });

  it('emits DEP-AUDIT-SKIP for a pnpm project (npm audit cannot check it)', async () => {
    const result = await analyzeDir(pnpm);
    const skip = result.findings.find((f) => f.id === 'DEP-AUDIT-SKIP');
    expect(skip).toBeDefined();
    expect(skip?.description).toMatch(/unknown, not clean/i);
    // Must NOT also claim there's no lock file — pnpm-lock.yaml counts.
    expect(result.findings.find((f) => f.id === 'DEP-001')).toBeUndefined();
  });
});

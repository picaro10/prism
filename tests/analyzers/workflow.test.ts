import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { WorkflowAnalyzer, checkWorkflow } from '../../src/analyzers/workflow.js';
import type { ProjectScan } from '../../src/core/types.js';

const CTX = { branches: ['main', 'dev'], hasLockfile: true };

function ids(raw: string, ctx = CTX): string[] {
  return checkWorkflow(parse(raw), raw, '.github/workflows/ci.yml', ctx).map((f) => f.id);
}

/** A hygienic baseline workflow no rule should fire on. */
const CLEAN = `
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
concurrency:
  group: ci-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci && npm test
`;

describe('checkWorkflow rules', () => {
  it('is silent on a hygienic workflow', () => {
    expect(ids(CLEAN)).toEqual([]);
  });

  it('WFL-001: pull_request_target + PR-head checkout (pwn request)', () => {
    const wf = `
on:
  pull_request_target:
permissions:
  contents: read
concurrency: x
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`;
    expect(ids(wf)).toContain('WFL-001');
    // plain pull_request checking out its own head is the normal case
    expect(ids(wf.replace('pull_request_target', 'pull_request'))).not.toContain('WFL-001');
  });

  it('WFL-002: untrusted event data interpolated into run (script injection)', () => {
    const wf = CLEAN.replace('npm ci && npm test', 'echo "${{ github.event.issue.title }}"');
    expect(ids(wf)).toContain('WFL-002');
    // the same value routed through env is the fix — and github.repository is not attacker-controlled
    expect(ids(CLEAN.replace('npm ci && npm test', 'echo "${{ github.repository }}"'))).toEqual([]);
  });

  it('WFL-003: third-party action unpinned — high on branch, medium on tag, silent on SHA and first-party', () => {
    const withUses = (uses: string) => CLEAN.replace('- run: npm ci && npm test', `- uses: ${uses}`);
    const onBranch = checkWorkflow(parse(withUses('someone/action@main')), withUses('someone/action@main'), 'f', CTX);
    expect(onBranch.find((f) => f.id === 'WFL-003')?.severity).toBe('high');
    const onTag = checkWorkflow(parse(withUses('someone/action@v2')), withUses('someone/action@v2'), 'f', CTX);
    expect(onTag.find((f) => f.id === 'WFL-003')?.severity).toBe('medium');
    expect(ids(withUses(`someone/action@${'a'.repeat(40)}`))).toEqual([]);
    expect(ids(withUses('actions/cache@v4'))).toEqual([]);
  });

  it('WFL-004/WFL-005: missing permissions block; explicit write-all', () => {
    expect(ids(CLEAN.replace('permissions:\n  contents: read\n', ''))).toContain('WFL-004');
    const writeAll = CLEAN.replace('permissions:\n  contents: read', 'permissions: write-all');
    expect(ids(writeAll)).toContain('WFL-005');
  });

  it('WFL-006: trigger filtering only nonexistent branches (CI never runs)', () => {
    const dead = CLEAN.replace('branches: [main]', 'branches: [master]');
    expect(ids(dead)).toContain('WFL-006');
    // one existing branch in the list = it runs; globs and unknown repos are skipped
    expect(ids(CLEAN.replace('branches: [main]', 'branches: [master, main]'))).toEqual([]);
    expect(ids(CLEAN.replace('branches: [main]', "branches: ['releases/**']"))).toEqual([]);
    expect(ids(dead, { branches: [], hasLockfile: true })).not.toContain('WFL-006');
  });

  it('WFL-007/WFL-008: no timeouts; no concurrency on push/PR workflows', () => {
    expect(ids(CLEAN.replace('    timeout-minutes: 15\n', ''))).toContain('WFL-007');
    expect(
      ids(CLEAN.replace('concurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\n', '')),
    ).toContain('WFL-008');
  });

  it('WFL-009: continue-on-error on a gate job fails open', () => {
    const wf = CLEAN.replace('    runs-on: ubuntu-latest', '    continue-on-error: true\n    runs-on: ubuntu-latest');
    expect(ids(wf)).toContain('WFL-009');
    // an advisory job that is not a gate may continue on error
    const advisory = wf.replace('  test:', '  preview-deploy:').replace('npm ci && npm test', 'echo preview');
    expect(ids(advisory)).not.toContain('WFL-009');
  });

  it('WFL-010: setup-node without cache while the repo has a lockfile', () => {
    const noCache = CLEAN.replace('          cache: npm\n', '');
    expect(ids(noCache)).toContain('WFL-010');
    expect(ids(noCache, { branches: ['main'], hasLockfile: false })).not.toContain('WFL-010');
  });

  it('WFL-011: self-hosted runner on a PR-triggered workflow', () => {
    const wf = CLEAN.replace('on:\n  push:\n    branches: [main]', 'on:\n  pull_request:').replace(
      'runs-on: ubuntu-latest',
      'runs-on: [self-hosted, linux]',
    );
    expect(ids(wf)).toContain('WFL-011');
    expect(ids(CLEAN.replace('runs-on: ubuntu-latest', 'runs-on: [self-hosted, linux]'))).not.toContain('WFL-011');
  });
});

describe('WorkflowAnalyzer', () => {
  const analyzer = new WorkflowAnalyzer();
  function scan(files: string[]): ProjectScan {
    return {
      rootPath: resolve('/proj'),
      files,
      fileTree: [],
      meta: {
        stack: { primary: 'typescript', secondary: [] },
        totalLoc: 0,
        totalFiles: files.length,
        hasGit: false,
        hasDocker: false,
        hasCi: true,
        frameworks: [],
      },
    };
  }

  it('is N/A (score 10) when there are no workflows', async () => {
    const result = await analyzer.analyze(scan(['src/a.ts']), async () => '');
    expect(result.score).toBe(10);
    expect(result.summary).toMatch(/N\/A/);
  });

  it('reports findings with file/line and caps the unpinned-action penalty', async () => {
    const uses = Array.from({ length: 6 }, (_, i) => `      - uses: vendor${i}/act@main`).join('\n');
    const wf = `on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n${uses}\n`;
    const result = await analyzer.analyze(scan(['.github/workflows/ci.yml']), async () => wf);
    const unpinned = result.findings.filter((f) => f.id === 'WFL-003');
    expect(unpinned).toHaveLength(6);
    expect(unpinned[0].file).toBe('.github/workflows/ci.yml');
    // 6×1.0 raw would be -6; cap holds it at -2 (plus WFL-004/007/008 minors)
    expect(result.score).toBeGreaterThanOrEqual(7);
  });

  it('flags an unparseable workflow instead of crashing', async () => {
    const result = await analyzer.analyze(scan(['.github/workflows/ci.yml']), async () => 'jobs: [unclosed');
    expect(result.findings.map((f) => f.id)).toContain('WFL-PARSE');
  });
});

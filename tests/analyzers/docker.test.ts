import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { scanProject } from '../../src/core/scanner.js';
import { DockerAnalyzer } from '../../src/analyzers/docker.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ProjectScan } from '../../src/core/types.js';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

describe('DockerAnalyzer', () => {
  const analyzer = new DockerAnalyzer();

  async function runAnalysis() {
    const scan = await scanProject(FIXTURE_PATH);
    const fileReader = async (p: string) => readFile(join(FIXTURE_PATH, p), 'utf-8');
    return analyzer.analyze(scan, fileReader);
  }

  it('returns the correct category', async () => {
    const result = await runAnalysis();
    expect(result.category).toBe('docker');
  });

  it('returns a score between 0 and 10', async () => {
    const result = await runAnalysis();
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(10);
  });

  it('detects missing .dockerignore', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('detects container running as root', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-010');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('detects :latest tag usage', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-012');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('detects missing HEALTHCHECK', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-013');
    expect(finding).toBeDefined();
  });

  it('detects COPY . . in Dockerfile', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-014');
    expect(finding).toBeDefined();
  });

  it('detects hardcoded credentials in docker-compose', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-021');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('detects missing restart policy in docker-compose', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-022');
    expect(finding).toBeDefined();
  });

  it('detects ports exposed on all interfaces', async () => {
    const result = await runAnalysis();
    const finding = result.findings.find((f) => f.id === 'DOC-024');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('penalizes score for bad Docker practices', async () => {
    const result = await runAnalysis();
    // Fixture has many issues — score should be noticeably below 10
    expect(result.score).toBeLessThan(7);
  });

  it('generates a non-empty summary', async () => {
    const result = await runAnalysis();
    expect(result.summary).toContain('Dockerfile');
    expect(result.summary).toContain('compose');
  });
});

describe('DockerAnalyzer — fixture/vendor exclusion', () => {
  const analyzer = new DockerAnalyzer();
  const badDockerfile = 'FROM node:latest\nCOPY . .\nCMD ["node", "x.js"]\n';

  function scanWith(files: string[]): ProjectScan {
    return {
      rootPath: '/fake',
      files,
      fileTree: [],
      meta: {
        stack: { primary: 'typescript', secondary: [] },
        totalLoc: 0,
        totalFiles: files.length,
        hasGit: true,
        hasDocker: true,
        hasCi: false,
        frameworks: ['Docker'],
      },
    };
  }

  it('does NOT flag a Dockerfile that lives in a test fixture', async () => {
    const scan = scanWith(['tests/fixtures/sample-project/Dockerfile']);
    const result = await analyzer.analyze(scan, async () => badDockerfile);
    expect(result.findings.filter((f) => f.file?.includes('fixtures'))).toHaveLength(0);
  });

  it('DOES flag the same Dockerfile when it is real project source (control)', async () => {
    const scan = scanWith(['Dockerfile']);
    const result = await analyzer.analyze(scan, async () => badDockerfile);
    expect(result.findings.some((f) => f.id === 'DOC-010')).toBe(true);
  });
});

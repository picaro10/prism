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

  it('is not applicable when there is no Docker configuration at all', async () => {
    const scan = scanWith(['src/a.ts']);
    const result = await analyzer.analyze(scan, async () => '');
    expect(result.applicable).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.summary).toMatch(/N\/A/);
  });

  it('is not applicable when the only Dockerfile lives in a test fixture (used to score 10/10 "looks solid")', async () => {
    const scan = scanWith(['tests/fixtures/sample-project/Dockerfile']);
    const result = await analyzer.analyze(scan, async () => badDockerfile);
    expect(result.applicable).toBe(false);
  });

  it('IS applicable when a real Dockerfile exists', async () => {
    const scan = scanWith(['Dockerfile']);
    const result = await analyzer.analyze(scan, async () => badDockerfile);
    expect(result.applicable).toBeUndefined();
  });
});

describe('DockerAnalyzer — compose services: docker.sock (DOC-025) and per-service DOC-024', () => {
  const analyzer = new DockerAnalyzer();

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
  const run = (compose: string) => analyzer.analyze(scanWith(['docker-compose.yml']), async () => compose);

  it('flags a docker.sock mount as critical, once per service, naming the service', async () => {
    const compose = [
      'services:',
      '  api:',
      '    image: node:22',
      '    restart: unless-stopped',
      '    volumes:',
      '      - /var/run/docker.sock:/var/run/docker.sock:ro',
      '      - ./data:/data',
      '  traefik:',
      '    image: traefik:v3.1',
      '    restart: unless-stopped',
      '    volumes:',
      '      - type: bind',
      '        source: /var/run/docker.sock',
      '        target: /var/run/docker.sock',
      '',
    ].join('\n');
    const r = await run(compose);
    const socks = r.findings.filter((f) => f.id === 'DOC-025');
    expect(socks).toHaveLength(2);
    expect(socks.map((f) => f.severity)).toEqual(['critical', 'critical']);
    expect(socks[0].title).toMatch(/api/);
    expect(socks[0].line).toBe(6);
    expect(socks[1].title).toMatch(/traefik/);
    expect(socks[1].suggestion).toMatch(/socket proxy/i);
    // :ro does not make it safe — the Docker API over that socket is full control of the host.
    expect(socks[0].description).toMatch(/read-only/i);
  });

  it('does NOT flag other sockets, commented-out mounts, or a docker.sock mentioned outside a mount', async () => {
    const compose = [
      'services:',
      '  db:',
      '    image: mysql:8',
      '    restart: unless-stopped',
      '    # - /var/run/docker.sock:/var/run/docker.sock',
      '    volumes:',
      '      - /var/run/mysqld/mysqld.sock:/var/run/mysqld/mysqld.sock',
      '    environment:',
      '      - DOCKER_HOST=unix:///var/run/docker.sock',
      '',
    ].join('\n');
    const r = await run(compose);
    expect(r.findings.filter((f) => f.id === 'DOC-025')).toHaveLength(0);
  });

  it('reports DOC-024 once per SERVICE, not once per file, naming each service', async () => {
    const compose = [
      'services:',
      '  api:',
      '    image: node:22',
      '    ports:',
      '      - "8000:8000"',
      '      - "8001:8001"',
      '  db:',
      '    image: postgres:16',
      '    ports:',
      '      - "5432:5432"',
      '  cache:',
      '    image: redis:7',
      '    ports:',
      '      - "127.0.0.1:6379:6379"',
      '',
    ].join('\n');
    const r = await run(compose);
    const ports = r.findings.filter((f) => f.id === 'DOC-024');
    expect(ports).toHaveLength(2); // api once (not twice), db once, cache never
    expect(ports[0].title).toMatch(/api/);
    expect(ports[0].line).toBe(5);
    expect(ports[1].title).toMatch(/db/);
    expect(ports[1].line).toBe(10);
  });

  it('treats an explicit 0.0.0.0 binding like a bare mapping', async () => {
    const compose = ['services:', '  api:', '    ports:', '      - "0.0.0.0:8000:8000"', ''].join('\n');
    const r = await run(compose);
    expect(r.findings.filter((f) => f.id === 'DOC-024')).toHaveLength(1);
  });

  it('caps the DOC-024 penalty per file — six published dev services are one decision, not six failures', async () => {
    const lines = ['services:'];
    for (let i = 0; i < 6; i++)
      lines.push(`  svc${i}:`, '    image: node:22', '    ports:', `      - "${8000 + i}:${8000 + i}"`);
    lines.push('');
    const r = await run(lines.join('\n'));
    expect(r.findings.filter((f) => f.id === 'DOC-024')).toHaveLength(6);
    // Six services with only DOC-024 (+ DOC-022 -0.3, DOC-023 -0.2): capped at -2.0 for the ports, so ≥ 7.5.
    expect(r.score).toBeGreaterThanOrEqual(7.5);
  });
});

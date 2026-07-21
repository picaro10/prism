import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { type Server, request as httpRequest } from 'node:http';
import {
  loadReports,
  renderIndex,
  isPrismReport,
  isLocalHost,
  createDashboardServer,
} from '../../src/dashboard/server.js';
import type { AuditReport } from '../../src/core/types.js';

function report(p: Partial<AuditReport> = {}): AuditReport {
  return {
    projectName: 'demo-app',
    projectPath: '/demo',
    startedAt: '2026-06-11T10:00:00.000Z',
    completedAt: '2026-06-11T10:00:01.000Z',
    durationMs: 1000,
    overallScore: 8.2,
    categories: [{ category: 'security', score: 9, maxScore: 10, findings: [], summary: 'ok' }],
    findings: [],
    projectMeta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 10,
      totalFiles: 2,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
    prismVersion: '1.9.0',
    ...p,
  };
}

let dir: string;
let server: Server;
let base: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'prism-dash-'));
  await writeFile(join(dir, 'demo.json'), JSON.stringify(report()));
  await writeFile(
    join(dir, 'older.json'),
    JSON.stringify(report({ overallScore: 5.1, completedAt: '2026-06-10T10:00:00.000Z' })),
  );
  await writeFile(join(dir, 'not-a-report.json'), JSON.stringify({ hello: 'world' }));
  await writeFile(join(dir, 'broken.json'), '{nope');
  await writeFile(join(dir, 'notes.txt'), 'irrelevant');

  server = createDashboardServer(dir);
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise((ok) => server.close(ok));
  await rm(dir, { recursive: true, force: true });
});

describe('isPrismReport', () => {
  it('accepts a real report and rejects arbitrary JSON', () => {
    expect(isPrismReport(report())).toBe(true);
    expect(isPrismReport({ hello: 'world' })).toBe(false);
    expect(isPrismReport(null)).toBe(false);
    expect(isPrismReport([1, 2])).toBe(false);
  });
});

describe('isLocalHost', () => {
  it('accepts loopback hosts (with optional port)', () => {
    for (const h of ['localhost', 'localhost:4180', '127.0.0.1', '127.0.0.1:4180', '[::1]:4180']) {
      expect(isLocalHost(h)).toBe(true);
    }
  });
  it('rejects non-loopback hosts (DNS rebinding) and missing header', () => {
    for (const h of ['evil.com', 'attacker.example:4180', '10.0.0.5', undefined]) {
      expect(isLocalHost(h)).toBe(false);
    }
  });
});

describe('loadReports', () => {
  it('loads only valid PRISM reports, newest first per project', async () => {
    const entries = await loadReports(dir);
    expect(entries.map((e) => e.file)).toEqual(['demo.json', 'older.json']);
  });

  it('returns [] for a missing directory', async () => {
    expect(await loadReports('/nonexistent/nowhere')).toEqual([]);
  });
});

describe('renderIndex', () => {
  it('lists reports with scores and escaped names', () => {
    const html = renderIndex([{ file: 'x.json', report: report({ projectName: '<evil&app>' }) }], '/reports');
    expect(html).toContain('&lt;evil&amp;app&gt;');
    expect(html).toContain('8.2/10');
    expect(html).toContain('/report?f=x.json');
    expect(html).not.toMatch(/<script\b/);
  });

  it('shows a helpful empty state', () => {
    expect(renderIndex([], '/reports')).toContain('No PRISM reports found');
  });
});

describe('dashboard server', () => {
  it('serves the index at /', async () => {
    const res = await fetch(`${base}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('PRISM Dashboard');
    expect(html).toContain('demo-app');
    expect(html).not.toContain('not-a-report');
  });

  it('rejects a request with a non-loopback Host header (DNS rebinding)', async () => {
    const { port } = server.address() as AddressInfo;
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port, path: '/', headers: { Host: 'evil.com' } }, (r) => {
        r.resume();
        resolve(r.statusCode ?? 0);
      });
      req.on('error', reject);
      req.end();
    });
    expect(status).toBe(403);
  });

  it('renders a full report at /report?f=', async () => {
    const res = await fetch(`${base}/report?f=demo.json`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('PRISM Audit Report');
    expect(html).toContain('demo-app');
  });

  it('rejects path traversal and unknown files with 404', async () => {
    expect((await fetch(`${base}/report?f=${encodeURIComponent('../etc/passwd')}`)).status).toBe(404);
    expect((await fetch(`${base}/report?f=nope.json`)).status).toBe(404);
    expect((await fetch(`${base}/report?f=not-a-report.json`)).status).toBe(404);
    expect((await fetch(`${base}/whatever`)).status).toBe(404);
  });
});

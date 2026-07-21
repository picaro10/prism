import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeJsonReport } from '../../src/reporters/json.js';
import type { AuditReport } from '../../src/core/types.js';

const report = { projectName: 'demo', findings: [] } as unknown as AuditReport;

let dir: string;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe('writeJsonReport', () => {
  it('creates missing parent directories instead of discarding the report', async () => {
    dir = await mkdtemp(join(tmpdir(), 'prism-json-'));
    const out = join(dir, 'reports', 'nested', 'report.json');
    await writeJsonReport(report, out);
    const saved = JSON.parse(await readFile(out, 'utf-8'));
    expect(saved.projectName).toBe('demo');
  });
});

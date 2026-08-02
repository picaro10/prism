// Real-semgrep integration: exercises the default runner + curated rules
// end-to-end against a materialized vulnerable project. Skips when semgrep
// is not on PATH (the unit suite covers the degradation path).
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SemgrepAnalyzer } from '../../src/analyzers/semgrep.js';
import type { ProjectScan, FileReader } from '../../src/core/types.js';

function semgrepAvailable(): boolean {
  try {
    execFileSync('semgrep', ['--version'], { stdio: 'ignore', timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

const VULN_JS = `const express = require('express');
const { exec } = require('node:child_process');
const app = express();
const db = require('./db');

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});
`;

const VULN_PY = `from flask import request
import os

def handler(cursor):
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    os.system("ping " + request.args.get("host"))
`;

describe.skipIf(!semgrepAvailable())('SemgrepAnalyzer against a real semgrep binary', () => {
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'prism-semgrep-e2e-'));
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'server.js'), VULN_JS);
    await writeFile(join(root, 'src', 'app.py'), VULN_PY);
  });

  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('finds taint flows in JS and Python and maps them with CWE metadata', { timeout: 120_000 }, async () => {
    const scan: ProjectScan = {
      rootPath: root,
      files: ['src/server.js', 'src/app.py'],
      fileTree: [],
      meta: {
        stack: { primary: 'JavaScript', secondary: ['Python'] },
        totalLoc: 0,
        totalFiles: 2,
        hasGit: false,
        hasDocker: false,
        hasCi: false,
        frameworks: [],
      },
    };
    const readFile: FileReader = async () => '';
    const res = await new SemgrepAnalyzer().analyze(scan, readFile);

    const ids = res.findings.map((f) => f.id);
    expect(ids).toContain('SG-SQLI-TAINTED-QUERY');
    expect(ids).toContain('SG-XSS-TAINTED-RESPONSE');
    expect(ids).toContain('SG-SQLI-TAINTED-EXECUTE-PY');
    expect(ids).toContain('SG-COMMAND-INJECTION-PY');

    const sqli = res.findings.find((f) => f.id === 'SG-SQLI-TAINTED-QUERY')!;
    expect(sqli.severity).toBe('critical');
    expect(sqli.file).toBe('src/server.js');
    expect(sqli.line).toBeGreaterThan(0);
    expect(sqli.meta?.cwe).toBe('CWE-89');
    expect(res.score).toBeLessThan(10);
  });
});

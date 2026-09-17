/**
 * The PRISM benchmark corpus: planted true positives and the false-positive
 * traps that were actually hit in the field (each FP trap here once produced a
 * wrong finding, or was explicitly engineered out — see SESSION_LOG lessons).
 *
 * Cases are defined as code, not committed files, for two reasons:
 * - planted secrets must never exist as contiguous literals in this repo
 *   (GitHub push protection would rightly block them; PRISM's own dogfood
 *   would rightly flag them), so the risky strings are assembled at runtime;
 * - each case materializes to a temp dir at run time, keeping the benchmark
 *   fully reproducible from a clean checkout.
 */

export interface BenchCase {
  name: string;
  /** Analyzer categories to run for this case (keeps unrelated noise out of the measurement). */
  categories: string[];
  /** Relative path → file content, materialized into a temp project. */
  files: Record<string, string>;
  /** Relative path → EXACT set of rule ids expected in that file ([] = any finding is an FP). */
  expect: Record<string, string[]>;
  /**
   * External capability this case needs. The runner probes and SKIPS (with an
   * explicit log line, never silently) when it is missing: 'semgrep' = the
   * binary on PATH; 'osv' = api.osv.dev reachable. External availability must
   * never fail the benchmark — the Day-6 lesson, applied to our own gate.
   */
  requires?: 'semgrep' | 'osv';
  /**
   * Rule ids tolerated (not counted as FPs) beyond the expected set. For
   * findings backed by a LIVE external database: OSV severity buckets shift
   * as advisories are added/reclassified, and an exact set would let osv.dev
   * break our CI — the expectation pins recall (the id must appear), not the
   * database's mood.
   */
  allowExtra?: string[];
}

/** Assemble a risky literal at runtime so it never exists contiguously in the repo. */
const join = (...parts: string[]) => parts.join('');
const STRIPE_KEY = join('sk', '_live_', 'abcDEF123456789012345678');
const PACKAGE_JSON = JSON.stringify({ name: 'bench-case', version: '1.0.0' });

export const CASES: BenchCase[] = [
  // ── True positives: each planted issue MUST be found ────────────────────
  {
    name: 'tp-stripe-key-in-source',
    categories: ['security'],
    files: { 'package.json': PACKAGE_JSON, 'src/pay.ts': `const key = "${STRIPE_KEY}";\n` },
    expect: { 'src/pay.ts': ['SEC-STRIPE-SK'] },
  },
  {
    name: 'tp-shell-injection-in-tool',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/tool.ts':
        'import { execSync } from "node:child_process";\nexport const run = (cmd: string) => execSync(`sh -c ${cmd}`);\n',
    },
    expect: { 'src/tool.ts': ['AGT-001'] },
  },
  {
    name: 'tp-secret-in-prompt',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/agent.ts': 'const system = `You are a bot. token=${process.env.API_KEY}`;\n',
    },
    expect: { 'src/agent.ts': ['AGT-002'] },
  },
  {
    name: 'tp-prompt-injection-from-fetch',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/summarize.ts': 'const prompt = `Summarize this page: ${await res.text()}`;\n',
    },
    expect: { 'src/summarize.ts': ['AGT-004'] },
  },
  {
    name: 'tp-fail-open-gate',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/guard.ts': [
        'export async function checkPermission(u: string) {',
        '  try { return await policy.evaluate(u); }',
        '  catch { return true; }',
        '}',
        '',
      ].join('\n'),
    },
    expect: { 'src/guard.ts': ['AGT-006'] },
  },
  {
    name: 'tp-privileged-compose',
    categories: ['docker'],
    files: {
      'package.json': PACKAGE_JSON,
      'docker-compose.yml': 'services:\n  app:\n    image: node:22\n    privileged: true\n',
    },
    expect: { 'docker-compose.yml': ['DOC-020', 'DOC-022', 'DOC-023'] },
  },

  {
    name: 'tp-workflow-pwn-and-injection',
    categories: ['workflow'],
    files: {
      'package.json': PACKAGE_JSON,
      '.github/workflows/risky.yml': [
        'on:',
        '  pull_request_target:',
        'permissions: write-all',
        'concurrency: x',
        'jobs:',
        '  build:',
        '    runs-on: ubuntu-latest',
        '    timeout-minutes: 10',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '        with:',
        '          ref: ${{ github.event.pull_request.head.sha }}',
        '      - run: echo "${{ github.event.pull_request.title }}"',
        '',
      ].join('\n'),
    },
    expect: { '.github/workflows/risky.yml': ['WFL-001', 'WFL-002', 'WFL-005'] },
  },

  // ── FP traps: files that once fooled a rule (or were engineered not to) ──
  {
    name: 'trap-placeholder-db-credentials',
    categories: ['security'],
    // Field FP (orion_new): generator scripts with user:password@ templates
    // were flagged critical. Placeholder passwords must not fire SEC-DB-URL.
    files: {
      'package.json': PACKAGE_JSON,
      'src/generate-skill.ts':
        'const example = "postgresql://user:password@localhost:5432/mydb";\nconst dev = "mysql://root:root@127.0.0.1/app";\n',
    },
    expect: { 'src/generate-skill.ts': [] },
  },
  {
    name: 'trap-readable-identifier-env-value',
    categories: ['security'],
    // Field FP (orion_new): a localStorage KEY NAME read as a hardcoded secret.
    files: {
      'package.json': PACKAGE_JSON,
      'src/dashboard.ts': "const STORAGE_KEY = 'orion_dashboard_token';\n",
    },
    expect: { 'src/dashboard.ts': [] },
  },
  {
    name: 'trap-scanner-writes-the-pattern',
    categories: ['agentic'],
    // Self-detection trap: a linter/scanner whose comments and regexes CONTAIN
    // the vulnerable pattern must not flag itself (the xit( lesson, generalized).
    files: {
      'package.json': PACKAGE_JSON,
      'src/lint-rule.ts': [
        '// flags exec(`ls ${dir}`) style calls',
        'const re = /\\bexec(Sync)?\\s*\\([^)]*\\$\\{/;',
        'export const check = (l: string) => re.test(l);',
        '',
      ].join('\n'),
    },
    expect: { 'src/lint-rule.ts': [] },
  },
  {
    name: 'trap-execfile-is-the-safe-pattern',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/safe-tool.ts':
        'import { execFileSync } from "node:child_process";\nexport const run = (dir: string) => execFileSync("ls", [dir]);\n',
    },
    expect: { 'src/safe-tool.ts': [] },
  },
  {
    name: 'trap-gated-destructive-tool',
    categories: ['agentic'],
    // A destructive tool WITH a confirmation marker must not fire AGT-003.
    files: {
      'package.json': PACKAGE_JSON,
      'src/tools.ts': [
        'export const tools = [{',
        "  name: 'delete_file',",
        "  description: 'Deletes a file from the workspace',",
        '  parameters: { type: "object" },',
        '  requiresConfirmation: true,',
        '}];',
        '',
      ].join('\n'),
    },
    expect: { 'src/tools.ts': [] },
  },
  {
    name: 'trap-docker-secret-mount-path',
    categories: ['docker'],
    // A secret MOUNT PATH in compose environment is not a hardcoded credential.
    files: {
      'package.json': PACKAGE_JSON,
      'docker-compose.yml': [
        'services:',
        '  app:',
        '    image: node:22',
        '    restart: unless-stopped',
        '    deploy:',
        '      resources:',
        '        limits:',
        '          memory: 512M',
        '    environment:',
        '      - DB_PASSWORD_FILE=/run/secrets/db_password',
        '',
      ].join('\n'),
    },
    expect: { 'docker-compose.yml': [] },
  },
  {
    name: 'trap-hygienic-workflow',
    categories: ['workflow'],
    // A workflow doing everything right (SHA-pinned third-party action,
    // least-privilege permissions, concurrency, timeout, cache) must be silent.
    files: {
      'package.json': PACKAGE_JSON,
      'package-lock.json': '{}',
      '.github/workflows/ci.yml': [
        'on:',
        '  push:',
        'permissions:',
        '  contents: read',
        'concurrency:',
        '  group: ci',
        '  cancel-in-progress: true',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    timeout-minutes: 15',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '      - uses: actions/setup-node@v4',
        '        with:',
        '          cache: npm',
        `      - uses: vendor/audited-action@${'b'.repeat(40)}`,
        '      - run: npm ci && npm test',
        '',
      ].join('\n'),
    },
    expect: { '.github/workflows/ci.yml': [] },
  },
  {
    name: 'trap-integration-test-without-sut-import',
    categories: ['tests'],
    // Integration tests exercising the system from outside (supertest) must
    // not be flagged for "missing SUT import".
    files: {
      'package.json': JSON.stringify({
        name: 'bench-case',
        version: '1.0.0',
        scripts: { test: 'vitest run' },
        devDependencies: { vitest: '^4.0.0', supertest: '^7.0.0' },
      }),
      'src/app.ts': 'export const app = () => "ok";\n',
      'tests/api.test.ts': [
        "import request from 'supertest';",
        "import { describe, it, expect } from 'vitest';",
        "describe('api', () => { it('responds', async () => { expect(1).toBe(1); }); });",
        '',
      ].join('\n'),
    },
    expect: { 'tests/api.test.ts': [] },
  },

  // ── Field sweep, 17 sep 2026: gaps found on real repos ─────────────────
  {
    name: 'tp-docker-socket-mount',
    categories: ['docker'],
    // Seen in a real production compose: the Docker API over that socket is
    // full control of the host, :ro or not.
    files: {
      'package.json': PACKAGE_JSON,
      'docker-compose.yml': [
        'services:',
        '  api:',
        '    image: node:22',
        '    restart: unless-stopped',
        '    deploy:',
        '      resources:',
        '        limits:',
        '          memory: 512M',
        '    volumes:',
        '      - /var/run/docker.sock:/var/run/docker.sock:ro',
        '',
      ].join('\n'),
    },
    expect: { 'docker-compose.yml': ['DOC-025'] },
  },
  {
    name: 'trap-other-unix-sockets-are-not-the-docker-socket',
    categories: ['docker'],
    files: {
      'package.json': PACKAGE_JSON,
      'docker-compose.yml': [
        'services:',
        '  db:',
        '    image: mysql:8',
        '    restart: unless-stopped',
        '    deploy:',
        '      resources:',
        '        limits:',
        '          memory: 512M',
        '    # - /var/run/docker.sock:/var/run/docker.sock  (removed after review)',
        '    volumes:',
        '      - /var/run/mysqld/mysqld.sock:/var/run/mysqld/mysqld.sock',
        '',
      ].join('\n'),
    },
    expect: { 'docker-compose.yml': [] },
  },
  {
    name: 'tp-messaging-text-in-prompt',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/bot.ts':
        'bot.on("message", async (msg) => {\n  const prompt = `Reply helpfully to: ${msg.text}`;\n  await llm(prompt);\n});\n',
    },
    expect: { 'src/bot.ts': ['AGT-004'] },
  },
  {
    name: 'trap-messaging-text-as-user-turn',
    categories: ['agentic'],
    // The recommended pattern: the message is a user-role content block (data),
    // it is logged, and it goes through a prompt firewall — never interpolated.
    files: {
      'package.json': PACKAGE_JSON,
      'src/bot.ts': [
        'bot.on("message", async (message) => {',
        '  logger.info(`incoming: ${message.text}`);',
        '  const verdict = analyzePrompt(message.text);',
        '  const preview = message.text.length > 150 ? `${message.text.slice(0, 147)}...` : message.text;',
        "  messages.push({ role: 'user', content: message.text });",
        '  const prev = messages[messages.length - 2];',
        '  for (const m of history) if (prev?.role === m.role) prev.content += `\\n${m.content}`;',
        '  await llm(messages);',
        '});',
        '',
      ].join('\n'),
    },
    expect: { 'src/bot.ts': [] },
  },

  // ── Taint (semgrep) — v1.4.0 pillar 1 ───────────────────────────────────
  {
    name: 'tp-sqli-taint-express',
    categories: ['security'],
    requires: 'semgrep',
    files: {
      'package.json': PACKAGE_JSON,
      'src/server.js': [
        "const express = require('express');",
        "const db = require('./db');",
        'const app = express();',
        "app.get('/user', (req, res) => {",
        '  const id = req.query.id;',
        '  db.query(`SELECT * FROM users WHERE id = ${id}`);',
        '});',
        '',
      ].join('\n'),
    },
    expect: { 'src/server.js': ['SG-SQLI-TAINTED-QUERY'] },
  },
  {
    name: 'tp-pickle-untrusted-py',
    categories: ['security'],
    requires: 'semgrep',
    files: {
      'package.json': PACKAGE_JSON,
      'src/app.py': [
        'from flask import request',
        'import pickle',
        '',
        'def load():',
        '    return pickle.loads(request.data)',
        '',
      ].join('\n'),
    },
    expect: { 'src/app.py': ['SG-PICKLE-LOAD-UNTRUSTED-PY'] },
  },
  {
    name: 'trap-parameterized-query-is-safe',
    categories: ['security'],
    requires: 'semgrep',
    // THE classic taint FP: request data flows into the PARAMS array of a
    // parameterized query — the query string itself is a constant. The sink
    // focuses on the query argument, so this must stay silent.
    files: {
      'package.json': PACKAGE_JSON,
      'src/safe-query.js': [
        "const express = require('express');",
        "const db = require('./db');",
        'const app = express();',
        "app.get('/user', (req, res) => {",
        "  db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);",
        '});',
        '',
      ].join('\n'),
    },
    expect: { 'src/safe-query.js': [] },
  },
  {
    name: 'trap-basename-sanitizes-traversal',
    categories: ['security'],
    requires: 'semgrep',
    // path.basename() strips any ../ segments — a sanitized user segment in a
    // filesystem path is the documented safe pattern, not a traversal.
    files: {
      'package.json': PACKAGE_JSON,
      'src/safe-file.js': [
        "const express = require('express');",
        "const path = require('node:path');",
        "const fs = require('node:fs');",
        'const app = express();',
        "app.get('/file', (req, res) => {",
        "  const data = fs.readFileSync('./uploads/' + path.basename(req.query.name));",
        '  res.json({ data });',
        '});',
        '',
      ].join('\n'),
    },
    expect: { 'src/safe-file.js': [] },
  },

  // ── OSV.dev SCA — v1.4.0 pillar 2 ───────────────────────────────────────
  {
    name: 'tp-osv-known-vulnerable-pin',
    categories: ['dependencies'],
    requires: 'osv',
    // requests 2.19.0 (2018) carries well-known HIGH advisories that will
    // never be unpublished. Recall pinned on DEP-OSV-HIGH; the other buckets
    // are tolerated because a live DB reclassifies over time.
    files: {
      'package.json': PACKAGE_JSON,
      'requirements.txt': 'requests==2.19.0\n',
    },
    expect: { 'requirements.txt': ['DEP-OSV-HIGH'] },
    allowExtra: ['DEP-OSV-CRITICAL', 'DEP-OSV-LOWER', 'DEP-OSV-UNKNOWN'],
  },
  {
    name: 'tp-osv-criticals-are-not-buried-as-low',
    categories: ['dependencies'],
    requires: 'osv',
    // Regression (found auditing 1.4.0, shipped in it): a per-run detail budget
    // of 30 left the rest of the advisories `unknown`, and `unknown` was folded
    // into the LOW bucket — django 1.11 + friends reported 4 criticals where
    // there are 29. A security tool that understates criticals is worse than
    // one that doesn't look. Recall pinned on CRITICAL specifically.
    files: {
      'package.json': PACKAGE_JSON,
      'requirements.txt': 'django==1.11.0\nflask==0.12.2\npyyaml==3.12\n',
    },
    expect: { 'requirements.txt': ['DEP-OSV-CRITICAL'] },
    allowExtra: ['DEP-OSV-HIGH', 'DEP-OSV-LOWER', 'DEP-OSV-UNKNOWN'],
  },
  {
    name: 'tp-sqli-taint-request-naming',
    categories: ['security'],
    requires: 'semgrep',
    // Regression (found auditing 1.4.0): the SAME SQLi went undetected purely
    // because the handler names its parameter `request` (Fastify, Next.js app
    // router) instead of `req`. A rule whose recall depends on a variable name
    // is a rule you can't trust.
    files: {
      'package.json': PACKAGE_JSON,
      'src/fastify-route.js': [
        "const db = require('./db');",
        "app.get('/user', (request, reply) => {",
        '  db.query(`SELECT * FROM users WHERE id = ${request.query.id}`);',
        '});',
        '',
      ].join('\n'),
    },
    expect: { 'src/fastify-route.js': ['SG-SQLI-TAINTED-QUERY'] },
  },
  {
    name: 'trap-osv-lockfile-in-fixtures',
    categories: ['dependencies'],
    // A vulnerable lockfile that is TEST DATA must not produce advisories —
    // the context filter has to stop it before any OSV query happens. Works
    // offline by design: an ignored lockfile means no network call at all.
    files: {
      'package.json': PACKAGE_JSON,
      'tests/fixtures/requirements.txt': 'requests==2.19.0\n',
    },
    expect: { 'tests/fixtures/requirements.txt': [] },
  },
];

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
      'src/tool.ts': 'import { execSync } from "node:child_process";\nexport const run = (cmd: string) => execSync(`sh -c ${cmd}`);\n',
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
      'src/generate-skill.ts': 'const example = "postgresql://user:password@localhost:5432/mydb";\nconst dev = "mysql://root:root@127.0.0.1/app";\n',
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
      'src/safe-tool.ts': 'import { execFileSync } from "node:child_process";\nexport const run = (dir: string) => execFileSync("ls", [dir]);\n',
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
];

/**
 * The AI-triage benchmark corpus: findings the static layer DOES emit, each
 * with the verdict a competent reviewer reaches after reading the code.
 *
 * The static benchmark (../cases.ts) measures the rules — a trap there is a
 * file where no finding must appear. This corpus measures the JUDGE: every
 * case here is letter-true for the rule, and the question is whether the
 * triage layer calls it right. Two kinds:
 *
 * - `real`: the finding is a genuine issue. The judge must NOT excuse it —
 *   a real issue confirmed as false-positive is the one failure that hides
 *   risk from the human, so it is the only outcome this benchmark hard-fails
 *   on. These include the two judgment errors seen in the field (a
 *   disconnected test excused as "testing style", a real exposed port
 *   excused by citing a different line).
 * - `false-positive`: the pattern matched but the context proves it benign.
 *   Catching these is the value of the AI layer; missing one is noise for a
 *   human, not hidden risk, so it is reported, not gated.
 *
 * `crossFile` cases are false positives whose exculpatory evidence lives in
 * ANOTHER file. Per-file triage cannot see it; they are the baseline that the
 * import-graph neighborhood context (next roadmap step) must move, and are
 * reported in their own section so the before/after is measurable.
 *
 * Same discipline as the static corpus: risky literals are assembled at
 * runtime, cases materialize to temp dirs, nothing risky is committed.
 */

export type ExpectedVerdict = 'real' | 'false-positive';

export interface AiBenchCase {
  name: string;
  /** Analyzer categories to run (keeps unrelated static noise out of the cost). */
  categories: string[];
  /** Relative path → file content, materialized into a temp project. */
  files: Record<string, string>;
  /** The ONE finding under judgment: the static layer must emit it (else the corpus is broken). */
  target: { file: string; id: string };
  expect: ExpectedVerdict;
  /** One line on why a careful human reaches that verdict — the rubric the judge is held to. */
  why: string;
  /** The exculpatory evidence is in another file; per-file triage is not expected to see it. */
  crossFile?: boolean;
}

const join = (...parts: string[]) => parts.join('');
const STRIPE_KEY = join('sk', '_live_', 'abcDEF123456789012345678');
const DB_URL = join('postgres://app:', 'S3cr3tPr0d', 'Pa55', '@db.internal:5432/app');
// A public VAPID key (Web Push): high entropy by construction, public by definition.
const VAPID_PUBLIC = join('BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA', '_-i8ptV4jr3sszLQ0tcmv1x5KFepJNEkcqHVfa2dS2S8');
const PACKAGE_JSON = JSON.stringify({ name: 'ai-bench-case', version: '1.0.0' });

export const AI_CASES: AiBenchCase[] = [
  // ── Real: the judge must not excuse these ─────────────────────────────────
  {
    name: 'real-stripe-live-key-in-source',
    categories: ['security'],
    files: { 'package.json': PACKAGE_JSON, 'src/pay.ts': `const key = "${STRIPE_KEY}";\nexport default key;\n` },
    target: { file: 'src/pay.ts', id: 'SEC-STRIPE-SK' },
    expect: 'real',
    why: 'A live-mode Stripe secret in a source file is a credential leak regardless of how it is used.',
  },
  {
    name: 'real-hardcoded-db-url-with-password',
    categories: ['security'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/db.ts': `export const DATABASE_URL = "${DB_URL}";\n`,
    },
    target: { file: 'src/db.ts', id: 'SEC-DB-URL' },
    expect: 'real',
    why: 'A connection string with a non-placeholder password committed in source.',
  },
  {
    name: 'real-shell-injection-in-agent-tool',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/tool.ts': [
        'import { execSync } from "node:child_process";',
        '/** Agent tool: runs a shell command the model chose. */',
        'export const run = (cmd: string) => execSync(`sh -c ${cmd}`).toString();',
        '',
      ].join('\n'),
    },
    target: { file: 'src/tool.ts', id: 'AGT-001' },
    expect: 'real',
    why: 'The model-controlled string reaches a shell unescaped; nothing in the file constrains it.',
  },
  {
    name: 'real-prompt-built-from-fetched-page',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/summarize.ts': [
        'export async function summarize(url: string) {',
        '  const res = await fetch(url);',
        '  const prompt = `Summarize this page: ${await res.text()}`;',
        '  return llm(prompt);',
        '}',
        '',
      ].join('\n'),
    },
    target: { file: 'src/summarize.ts', id: 'AGT-004' },
    expect: 'real',
    why: 'Untrusted page content is interpolated into the prompt with no delimiting or sanitizing — the prompt-injection door.',
  },
  {
    name: 'real-permission-check-fails-open',
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
    target: { file: 'src/guard.ts', id: 'AGT-006' },
    expect: 'real',
    why: 'The gate grants access exactly when the policy engine is down or throws.',
  },
  {
    name: 'real-privileged-compose-service',
    categories: ['docker'],
    files: {
      'package.json': PACKAGE_JSON,
      'docker-compose.yml': 'services:\n  app:\n    image: node:22\n    privileged: true\n',
    },
    target: { file: 'docker-compose.yml', id: 'DOC-020' },
    expect: 'real',
    why: 'privileged: true on an application container is full host access; nothing here needs it.',
  },
  {
    name: 'real-database-port-on-all-interfaces',
    categories: ['docker'],
    // Field case: a model once excused a real 0.0.0.0 binding by citing a
    // different service's localhost binding. The flagged line is the db.
    files: {
      'package.json': PACKAGE_JSON,
      'docker-compose.yml': [
        'services:',
        '  web:',
        '    image: nginx:1.27',
        '    ports:',
        '      - "127.0.0.1:8080:80"',
        '  db:',
        '    image: postgres:16',
        '    ports:',
        '      - "5432:5432"',
        '',
      ].join('\n'),
    },
    target: { file: 'docker-compose.yml', id: 'DOC-024' },
    expect: 'real',
    why: 'The database port is published on every interface; the web service binding to localhost says nothing about the db.',
  },
  {
    name: 'real-pull-request-target-checks-out-pr-head',
    categories: ['workflow'],
    files: {
      'package.json': PACKAGE_JSON,
      '.github/workflows/risky.yml': [
        'on:',
        '  pull_request_target:',
        'permissions:',
        '  contents: read',
        'concurrency: x',
        'jobs:',
        '  build:',
        '    runs-on: ubuntu-latest',
        '    timeout-minutes: 10',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '        with:',
        '          ref: ${{ github.event.pull_request.head.sha }}',
        '      - run: npm ci && npm test',
        '',
      ].join('\n'),
    },
    target: { file: '.github/workflows/risky.yml', id: 'WFL-001' },
    expect: 'real',
    why: 'pull_request_target runs with repo secrets and this checks out and executes the fork’s code (npm ci runs lifecycle scripts).',
  },
  {
    name: 'real-unit-test-redeclares-schema-inline',
    categories: ['tests'],
    // Field case (Day 1): config.test.ts tested a Zod schema re-declared inline
    // and never imported src/config. A lenient model excused it as "testing style".
    files: {
      'package.json': PACKAGE_JSON,
      'src/config.ts': [
        'import { z } from "zod";',
        'export const EnvSchema = z.object({ PORT: z.coerce.number().default(3000) });',
        'export const loadEnv = () => EnvSchema.parse(process.env);',
        '',
      ].join('\n'),
      'tests/config.test.ts': [
        'import { describe, it, expect } from "vitest";',
        'import { z } from "zod";',
        'const EnvSchema = z.object({ PORT: z.coerce.number().default(3000) });',
        'describe("config", () => {',
        '  it("defaults PORT to 3000", () => {',
        '    expect(EnvSchema.parse({}).PORT).toBe(3000);',
        '  });',
        '});',
        '',
      ].join('\n'),
    },
    target: { file: 'tests/config.test.ts', id: 'TST-014' },
    expect: 'real',
    why: 'The test exercises a copy of the schema, not src/config.ts — the real module can drift and the test stays green.',
  },

  // ── False positives: letter-true, benign in context, same file ────────────
  {
    name: 'fp-exec-argument-from-fixed-table',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/git.ts': [
        'import { execSync } from "node:child_process";',
        'const BRANCHES = { main: "main", release: "release/2026" } as const;',
        'export function recentCommits(choice: keyof typeof BRANCHES) {',
        '  const ref = BRANCHES[choice] ?? "main";',
        '  return execSync(`git log --oneline -5 ${ref}`).toString();',
        '}',
        '',
      ].join('\n'),
    },
    target: { file: 'src/git.ts', id: 'AGT-001' },
    expect: 'false-positive',
    why: 'The interpolated value is looked up from a constant table with a fixed fallback; no caller-controlled string reaches the shell.',
  },
  {
    name: 'fp-entropy-on-a-public-web-push-key',
    categories: ['security'],
    files: {
      'package.json': PACKAGE_JSON,
      'src/push.ts': [
        '// Web Push VAPID public key — shipped to every browser; the private key lives in the server env.',
        `export const VAPID_PUBLIC_KEY = "${VAPID_PUBLIC}";`,
        'export const vapidPrivateKey = () => process.env.VAPID_PRIVATE_KEY;',
        '',
      ].join('\n'),
    },
    target: { file: 'src/push.ts', id: 'SEC-ENTROPY' },
    expect: 'false-positive',
    why: 'A VAPID public key is public by design (sent to every subscriber); the private half is read from the environment.',
  },
  {
    name: 'fp-destructive-tool-gated-by-executor-in-same-file',
    categories: ['agentic'],
    files: {
      'package.json': PACKAGE_JSON,
      // The gate sits ~30 lines below the definition: outside the static rule's
      // window (5 lines up / 20 down), inside the file the judge reads whole.
      'src/tools.ts': [
        'export const tools = [',
        '  {',
        "    name: 'delete_file',",
        "    description: 'Deletes a file from the workspace',",
        '    parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },',
        '  },',
        '  {',
        "    name: 'read_file',",
        "    description: 'Reads a file from the workspace',",
        '    parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },',
        '  },',
        '  {',
        "    name: 'list_files',",
        "    description: 'Lists files under a directory',",
        '    parameters: { type: "object", properties: { dir: { type: "string" } }, required: ["dir"] },',
        '  },',
        '  {',
        "    name: 'search_files',",
        "    description: 'Searches file contents for a pattern',",
        '    parameters: { type: "object", properties: { pattern: { type: "string" } }, required: ["pattern"] },',
        '  },',
        '  {',
        "    name: 'stat_file',",
        "    description: 'Returns size and mtime of a file',",
        '    parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },',
        '  },',
        '];',
        '',
        '// Every tool call goes through here; there is no other dispatch path.',
        "const DESTRUCTIVE = new Set(['delete_file']);",
        'export async function execute(name: string, args: unknown) {',
        '  if (!tools.some((t) => t.name === name)) throw new Error(`unknown tool ${name}`);',
        '  if (DESTRUCTIVE.has(name)) await requireHumanApproval(name, args); // blocks until a human approves',
        '  return dispatch(name, args);',
        '}',
        '',
      ].join('\n'),
    },
    target: { file: 'src/tools.ts', id: 'AGT-003' },
    expect: 'false-positive',
    why: 'The definition carries no marker, but the only executor in the file gates every destructive tool behind human approval, 30 lines below.',
  },

  // ── Cross-file false positives: the evidence is in another file ───────────
  {
    name: 'xfile-destructive-tool-gated-by-policy-module',
    categories: ['agentic'],
    crossFile: true,
    files: {
      'package.json': PACKAGE_JSON,
      'src/tools.ts': [
        'export const tools = [{',
        "  name: 'delete_file',",
        "  description: 'Deletes a file from the workspace',",
        '  parameters: { type: "object", properties: { path: { type: "string" } } },',
        '}];',
        '',
      ].join('\n'),
      'src/executor.ts': [
        'import { tools } from "./tools.js";',
        "const DESTRUCTIVE = new Set(['delete_file']);",
        'export async function execute(name: string, args: unknown) {',
        '  if (!tools.some((t) => t.name === name)) throw new Error("unknown tool");',
        '  if (DESTRUCTIVE.has(name)) await requireHumanApproval(name, args); // blocks until approved',
        '  return dispatch(name, args);',
        '}',
        '',
      ].join('\n'),
    },
    target: { file: 'src/tools.ts', id: 'AGT-003' },
    expect: 'false-positive',
    why: 'The gate is real but lives in executor.ts, which imports the tool table — invisible from tools.ts alone.',
  },
  {
    name: 'xfile-exec-argument-validated-in-another-module',
    categories: ['agentic'],
    crossFile: true,
    files: {
      'package.json': PACKAGE_JSON,
      'src/validate.ts': [
        'export function assertSafeRef(ref: string): void {',
        '  if (!/^[A-Za-z0-9._\\/-]{1,64}$/.test(ref)) throw new Error("unsafe git ref");',
        '}',
        '',
      ].join('\n'),
      'src/git.ts': [
        'import { execSync } from "node:child_process";',
        'import { assertSafeRef } from "./validate.js";',
        'export function recentCommits(ref: string) {',
        '  assertSafeRef(ref);',
        '  return execSync(`git log --oneline -5 ${ref}`).toString();',
        '}',
        '',
      ].join('\n'),
    },
    target: { file: 'src/git.ts', id: 'AGT-001' },
    expect: 'false-positive',
    why: 'assertSafeRef rejects every shell metacharacter before the value reaches the shell; its body is in validate.ts.',
  },
  {
    name: 'xfile-assertion-helper-in-another-file',
    categories: ['tests'],
    crossFile: true,
    files: {
      'package.json': PACKAGE_JSON,
      'src/parser.ts': 'export const parse = (s: string) => JSON.parse(s);\n',
      'tests/helpers/assertions.ts': [
        'import { expect } from "vitest";',
        'export function assertParses(input: string, expected: unknown) {',
        '  expect(JSON.parse(input)).toEqual(expected);',
        '}',
        '',
      ].join('\n'),
      'tests/parser.test.ts': [
        'import { describe, it } from "vitest";',
        'import { parse } from "../src/parser.js";',
        'import { assertParses } from "./helpers/assertions.js";',
        'describe("parse", () => {',
        '  it("parses an object", () => {',
        '    assertParses(JSON.stringify(parse("{\\"a\\":1}")), { a: 1 });',
        '  });',
        '});',
        '',
      ].join('\n'),
    },
    target: { file: 'tests/parser.test.ts', id: 'TST-011' },
    expect: 'false-positive',
    why: 'Every test asserts through assertParses, whose expect() call lives in tests/helpers/assertions.ts.',
  },
];

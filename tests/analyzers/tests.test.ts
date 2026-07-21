import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { scanProject } from '../../src/core/scanner.js';
import { TestsAnalyzer, findPythonDecorativeTests, detectNoSutImport } from '../../src/analyzers/tests.js';
import type { ProjectScan } from '../../src/core/types.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

describe('TestsAnalyzer', () => {
  const analyzer = new TestsAnalyzer();

  async function runAnalysis() {
    const scan = await scanProject(FIXTURE_PATH);
    const fileReader = async (p: string) => readFile(join(FIXTURE_PATH, p), 'utf-8');
    return analyzer.analyze(scan, fileReader);
  }

  it('returns the correct category', async () => {
    const result = await runAnalysis();
    expect(result.category).toBe('tests');
  });

  it('returns a score between 0 and 10', async () => {
    const result = await runAnalysis();
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(10);
  });

  it('detects test files in the fixture', async () => {
    const result = await runAnalysis();
    // Fixture has 3 test files
    expect(result.summary).toContain('test files');
  });

  it('detects decorative tests (no assertions in file)', async () => {
    const result = await runAnalysis();
    const decorative = result.findings.find((f) => f.id === 'TST-011' && f.file?.includes('decorative'));
    expect(decorative).toBeDefined();
    expect(decorative?.severity).toBe('high');
  });

  it('detects tests without SUT imports', async () => {
    const result = await runAnalysis();
    const noSut = result.findings.find((f) => f.id === 'TST-014');
    // Fixture test files don't import from src/, so at least one should be flagged
    expect(noSut).toBeDefined();
    expect(noSut?.severity).toBe('medium');
  });

  it('detects skipped tests', async () => {
    const result = await runAnalysis();
    const skipped = result.findings.find((f) => f.id === 'TST-012' && f.file?.includes('skipped'));
    expect(skipped).toBeDefined();
    // Exactly the .skip + .todo — the fixture's `process.exit(` must not
    // count as `xit(` (regression: real FP on orion_new).
    expect(skipped?.title).toContain('2 skipped');
  });

  it('all findings have required fields', async () => {
    const result = await runAnalysis();
    for (const finding of result.findings) {
      expect(finding.id).toBeTruthy();
      expect(finding.category).toBe('tests');
      expect(finding.severity).toBeTruthy();
      expect(finding.title).toBeTruthy();
      expect(finding.description).toBeTruthy();
    }
  });

  it('generates a summary with ratio', async () => {
    const result = await runAnalysis();
    expect(result.summary).toContain('ratio');
  });

  it('does not fire TST-001 when there is no source code to test (infra repo)', async () => {
    // A pure infra/deployment repo: only Docker/compose/shell, zero source files.
    const scan: ProjectScan = {
      rootPath: '/fake/infra',
      files: ['Makefile', 'compose.yaml', 'docker/web/Dockerfile', 'scripts/setup.sh'],
      fileTree: [],
      meta: {
        stack: { primary: 'unknown', secondary: [] },
        totalLoc: 0,
        totalFiles: 4,
        hasGit: true,
        hasDocker: true,
        hasCi: false,
        frameworks: ['Docker'],
      },
    };
    const result = await analyzer.analyze(scan, async () => '');
    const noTests = result.findings.find((f) => f.id === 'TST-001');
    expect(noTests).toBeUndefined();
    // Tests dimension is N/A — must not tank the score to 0.
    expect(result.score).toBeGreaterThanOrEqual(8);
  });

  it('still fires TST-001 when source exists but no tests', async () => {
    const scan: ProjectScan = {
      rootPath: '/fake/app',
      files: ['src/index.ts', 'src/service.ts'],
      fileTree: [],
      meta: {
        stack: { primary: 'typescript', secondary: [] },
        totalLoc: 200,
        totalFiles: 2,
        hasGit: true,
        hasDocker: false,
        hasCi: false,
        frameworks: [],
      },
    };
    const result = await analyzer.analyze(scan, async () => 'export const x = 1;');
    expect(result.findings.find((f) => f.id === 'TST-001')).toBeDefined();
  });
});

describe('TestsAnalyzer — fixture exclusion', () => {
  const analyzer = new TestsAnalyzer();

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
        hasDocker: false,
        hasCi: false,
        frameworks: [],
      },
    };
  }

  it('does NOT flag a decorative test that lives in a test fixture', async () => {
    // A .test file under fixtures/ is intentional scaffolding, not a real test.
    const scan = scanWith(['src/index.ts', 'tests/fixtures/sample-project/tests/decorative.test.ts']);
    const decorativeBody = `describe('x', () => { it('does nothing', () => {}); });`;
    const result = await analyzer.analyze(scan, async (p) =>
      p.includes('decorative') ? decorativeBody : 'export const x = 1;',
    );
    expect(result.findings.find((f) => f.file?.includes('fixtures'))).toBeUndefined();
  });

  it('DOES flag the same decorative test when it is a real test (control)', async () => {
    const scan = scanWith(['src/index.ts', 'tests/decorative.test.ts']);
    const decorativeBody = `describe('x', () => { it('does nothing', () => {}); });`;
    const result = await analyzer.analyze(scan, async (p) =>
      p.includes('decorative') ? decorativeBody : 'export const x = 1;',
    );
    expect(result.findings.some((f) => f.id === 'TST-011')).toBe(true);
  });
});

describe('detectNoSutImport', () => {
  // The detector must NOT flag files that import the SUT via any standard
  // ES import form. The original regex only matched bare/dynamic imports and
  // require(), missing `import {x} from "path"` — the dominant real-world form.
  it('recognizes named imports from ../src', () => {
    const content = `import { describe, it, expect } from "vitest";
import { AuditRingBuffer } from "../src/logging/audit-buffer.js";`;
    expect(detectNoSutImport(content, 'tests/audit-buffer.test.ts', [])).toBe(false);
  });

  it('recognizes default imports from a relative parent path', () => {
    const content = `import App from "../src/app.js";`;
    expect(detectNoSutImport(content, 'tests/app.test.ts', [])).toBe(false);
  });

  it('recognizes namespace imports', () => {
    const content = `import * as core from "../src/core.js";`;
    expect(detectNoSutImport(content, 'tests/core.test.ts', [])).toBe(false);
  });

  it('recognizes src/ alias imports', () => {
    const content = `import { thing } from "src/thing.js";`;
    expect(detectNoSutImport(content, 'tests/thing.test.ts', [])).toBe(false);
  });

  it('recognizes integration packages imported via named import', () => {
    const content = `import { Client } from "@modelcontextprotocol/sdk/client/index.js";`;
    expect(detectNoSutImport(content, 'tests/client.test.ts', [])).toBe(false);
  });

  it('still flags a test that only imports the framework', () => {
    const content = `import { describe, it, expect } from "vitest";

describe("schema", () => {
  it("validates", () => { expect(1).toBe(1); });
});`;
    expect(detectNoSutImport(content, 'tests/schema.test.ts', [])).toBe(true);
  });

  it('flags a file with no imports at all', () => {
    expect(detectNoSutImport('const x = 1;', 'tests/x.test.ts', [])).toBe(true);
  });

  it('does not flag a test that exercises the app by forking a process', () => {
    // Integration test that runs the real entrypoint as a child process and
    // talks to it over HTTP — it tests real source via the process boundary,
    // not via import. Same legitimate pattern as supertest/playwright.
    const content = `import { describe, it, expect } from 'vitest';
import { fork } from 'node:child_process';
import http from 'node:http';

const agentPath = resolve('/opt/app/index.mjs');
const child = fork(agentPath, [], {});`;
    expect(detectNoSutImport(content, 'tests/unit/ops-agent.test.ts', [])).toBe(false);
  });
});

describe('findPythonDecorativeTests', () => {
  it('does not flag AsyncMock assertions (assert_awaited family)', () => {
    const content = `
class TestAgent:
    async def test_initialize_calls_memory(self):
        agent = _make_agent()
        await agent.initialize()
        agent.memory.initialize.assert_awaited_once()

    async def test_emit_silent_on_disabled(self):
        mock_get_redis = AsyncMock()
        await emit("request.started", {"user_id": "u1"})
        mock_get_redis.assert_not_awaited()
`;
    expect(findPythonDecorativeTests(content, 'test_agent.py')).toEqual([]);
  });

  it('does not flag standard Mock assertions (assert_called family)', () => {
    const content = `
def test_calls_handler():
    handler = Mock()
    dispatch(handler)
    handler.assert_called_once_with("event")
`;
    expect(findPythonDecorativeTests(content, 'test_x.py')).toEqual([]);
  });

  it('does not flag bare assert or unittest-style asserts', () => {
    const content = `
class TestThing(unittest.TestCase):
    def test_bare(self):
        assert compute() == 42

    def test_unittest(self):
        self.assertEqual(compute(), 42)
`;
    expect(findPythonDecorativeTests(content, 'test_t.py')).toEqual([]);
  });

  it('flags a test function with no assertions at all', () => {
    const content = `
def test_decorative():
    result = compute()
    print(result)
`;
    expect(findPythonDecorativeTests(content, 'test_d.py')).toEqual(['test_decorative']);
  });
});

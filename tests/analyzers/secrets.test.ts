import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { scanProject } from '../../src/core/scanner.js';
import { SecretsAnalyzer, hasPlaceholderDbCredentials } from '../../src/analyzers/secrets.js';
import { shannonEntropy } from '../../src/utils/patterns.js';
import { readFile } from 'node:fs/promises';

describe('hasPlaceholderDbCredentials (field-tested against orion_new)', () => {
  it('flags obvious placeholder credentials as NOT real secrets', () => {
    expect(hasPlaceholderDbCredentials('DATABASE_URL=postgres://user:password@db:5432/app')).toBe(true);
    expect(hasPlaceholderDbCredentials('mysql://user:password@localhost:3306/mydb')).toBe(true);
    expect(hasPlaceholderDbCredentials('mongodb://root:root@host/db')).toBe(true);
    expect(hasPlaceholderDbCredentials('postgres://admin:admin@localhost/x')).toBe(true);
  });

  it('does NOT treat a real credential as a placeholder (keeps the true positive)', () => {
    // The actual committed secret PRISM must still catch:
    expect(hasPlaceholderDbCredentials('postgresql://aether:Aether2024!@localhost:5433/mcp_db')).toBe(false);
    expect(hasPlaceholderDbCredentials('postgres://svc_prod:Xk9$mQ2vL@10.0.0.5/main')).toBe(false);
  });
});
import { join } from 'node:path';
import type { ProjectScan } from '../../src/core/types.js';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

describe('SecretsAnalyzer', () => {
  const analyzer = new SecretsAnalyzer();

  async function runAnalysis() {
    const scan = await scanProject(FIXTURE_PATH);
    const fileReader = async (p: string) => readFile(join(FIXTURE_PATH, p), 'utf-8');
    return analyzer.analyze(scan, fileReader);
  }

  it('detects .env file in project', async () => {
    const result = await runAnalysis();

    const envFinding = result.findings.find((f) => f.id === 'SEC-ENV-COMMITTED');
    expect(envFinding).toBeDefined();
    expect(envFinding?.severity).toBe('critical');
  });

  it('detects .env not in .gitignore', async () => {
    const result = await runAnalysis();

    const gitignoreFinding = result.findings.find((f) => f.id === 'SEC-GITIGNORE-ENV');
    expect(gitignoreFinding).toBeDefined();
  });

  it('detects hardcoded database URL', async () => {
    const result = await runAnalysis();

    const dbFinding = result.findings.find((f) => f.id === 'SEC-DB-URL' && f.file === 'src/config.ts');
    expect(dbFinding).toBeDefined();
    expect(dbFinding?.severity).toBe('critical');
    expect(dbFinding?.file).toBe('src/config.ts');
  });

  it('detects Anthropic API key pattern', async () => {
    const result = await runAnalysis();

    const anthropicFinding = result.findings.find((f) => f.id === 'SEC-ANTHROPIC');
    expect(anthropicFinding).toBeDefined();
    expect(anthropicFinding?.severity).toBe('critical');
  });

  it('never includes actual secret values in findings', async () => {
    const result = await runAnalysis();

    for (const finding of result.findings) {
      const meta = finding.meta as Record<string, unknown> | undefined;
      if (meta?.linePreview) {
        const preview = String(meta.linePreview);
        expect(preview).toMatch(/\[REDACTED(?:_URI)?\]/);
      }
    }
  });

  it('penalizes score for critical findings', async () => {
    const result = await runAnalysis();

    // Fixture has multiple critical secrets — score should be low
    expect(result.score).toBeLessThan(7);
  });

  it('returns the correct category', async () => {
    const result = await runAnalysis();
    expect(result.category).toBe('security');
  });
});

describe('SecretsAnalyzer — fixture exclusion', () => {
  const analyzer = new SecretsAnalyzer();

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

  it('does NOT raise SEC-ENV-COMMITTED for a .env that lives in a test fixture', async () => {
    const scan = scanWith(['tests/fixtures/sample-project/.env']);
    const result = await analyzer.analyze(scan, async () => 'API_KEY=sk-test\n');
    expect(result.findings.find((f) => f.id === 'SEC-ENV-COMMITTED')).toBeUndefined();
  });

  it('DOES raise SEC-ENV-COMMITTED for a real project .env (control)', async () => {
    const scan = scanWith(['.env']);
    const result = await analyzer.analyze(scan, async () => 'API_KEY=sk-test\n');
    expect(result.findings.find((f) => f.id === 'SEC-ENV-COMMITTED')).toBeDefined();
  });
});

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for single-char string', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });

  it('returns high entropy for random-looking strings', () => {
    const entropy = shannonEntropy('aB3$kL9!mN2@pQ5#');
    expect(entropy).toBeGreaterThan(3.5);
  });

  it('returns low entropy for repetitive strings', () => {
    const entropy = shannonEntropy('aaabbbccc');
    expect(entropy).toBeLessThan(2);
  });
});

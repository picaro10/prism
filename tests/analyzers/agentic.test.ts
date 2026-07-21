import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { AgenticAnalyzer, detectShellInjection, detectSecretInPrompt } from '../../src/analyzers/agentic.js';
import type { ProjectScan } from '../../src/core/types.js';

describe('detectShellInjection', () => {
  it('flags exec/execSync built with interpolation or concatenation', () => {
    expect(detectShellInjection('const o = execSync(`ls ${dir}`);')).toEqual([1]);
    expect(detectShellInjection('exec("cmd " + userInput);')).toEqual([1]);
    expect(detectShellInjection('const c = `rm ${x}`;\nexec(c + " -rf");')).toEqual([2]);
  });

  it('does NOT flag shell-less execFile/execFileSync (the safe pattern)', () => {
    expect(detectShellInjection('execFile("git", [arg]);')).toEqual([]);
    expect(detectShellInjection('execFileSync("ls", [dir]);')).toEqual([]);
  });

  it('does NOT flag a plain literal command (no interpolation)', () => {
    expect(detectShellInjection('execSync("npm audit --json");')).toEqual([]);
  });

  it('does NOT self-detect: skips comments and regex definitions (anti-self-flag)', () => {
    expect(detectShellInjection('// example: exec(`ls ${dir}`)')).toEqual([]);
    expect(detectShellInjection(' * writes exec(`... ${x}`) in a doc comment')).toEqual([]);
    expect(detectShellInjection('const re = /\\bexec\\s*\\([^)]*\\$\\{/.test(l);')).toEqual([]);
  });
});

describe('detectSecretInPrompt', () => {
  it('flags an env secret interpolated into prompt/message content', () => {
    expect(detectSecretInPrompt('const system = `You are a bot. token=${process.env.API_KEY}`;')).toEqual([1]);
    expect(detectSecretInPrompt('messages.push({ role: "user", content: `${process.env.SECRET}` });')).toEqual([1]);
  });

  it('does NOT flag ordinary env usage away from prompt context', () => {
    expect(detectSecretInPrompt('const port = `${process.env.PORT}`;')).toEqual([]);
    expect(detectSecretInPrompt('const key = process.env.API_KEY; // config')).toEqual([]);
  });
});

describe('AgenticAnalyzer', () => {
  const analyzer = new AgenticAnalyzer();
  function scan(files: string[]): ProjectScan {
    return {
      rootPath: resolve('/proj'),
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

  it('reports AGT-001 and AGT-002 on real agent-risk source', async () => {
    const reader = async (p: string) =>
      p === 'src/tool.ts'
        ? 'export function run(cmd) { return execSync(`sh -c ${cmd}`); }\nconst sys = `key ${process.env.OPENAI_API_KEY}`; // system'
        : '';
    const result = await analyzer.analyze(scan(['src/tool.ts']), reader);
    const ids = result.findings.map((f) => f.id).sort();
    expect(ids).toEqual(['AGT-001', 'AGT-002']);
    expect(result.score).toBeLessThan(10);
  });

  it('is clean on safe code (execFile, no secrets in prompt)', async () => {
    const reader = async () => 'execFile("git", ["status"]);\nconst k = process.env.KEY;';
    const result = await analyzer.analyze(scan(['src/safe.ts']), reader);
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(10);
  });

  it('skips test fixtures and non-source files (anti-FP)', async () => {
    const reader = async () => 'exec(`rm ${x}`);';
    const result = await analyzer.analyze(scan(['tests/fixtures/sample/tool.ts']), reader);
    expect(result.findings).toHaveLength(0);
  });
});

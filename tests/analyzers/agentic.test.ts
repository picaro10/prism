import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import {
  AgenticAnalyzer,
  detectShellInjection,
  detectSecretInPrompt,
  detectUnconfirmedDestructiveTool,
  detectExternalContentInPrompt,
  detectPublicMcpBind,
  detectFailOpenFallback,
} from '../../src/analyzers/agentic.js';
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

describe('detectUnconfirmedDestructiveTool (AGT-003)', () => {
  const destructiveTool = [
    'const tools = [{',
    "  name: 'delete_file',",
    "  description: 'Deletes a file from the workspace',",
    '  parameters: { type: "object", properties: { path: { type: "string" } } },',
    '}];',
  ].join('\n');

  it('flags a destructive tool definition with no confirmation gate', () => {
    expect(detectUnconfirmedDestructiveTool(destructiveTool)).toEqual([2]);
  });

  it('does NOT flag when a confirmation marker is present in the block', () => {
    const gated = destructiveTool.replace('}];', '  requiresConfirmation: true,\n}];');
    expect(detectUnconfirmedDestructiveTool(gated)).toEqual([]);
  });

  it('does NOT flag a non-destructive tool, or a destructive NAME outside a tool definition', () => {
    const readTool = destructiveTool.replace('delete_file', 'read_file').replace('Deletes', 'Reads');
    expect(detectUnconfirmedDestructiveTool(readTool)).toEqual([]);
    // A variable named delete_file with no description/schema around it is not a tool definition.
    expect(detectUnconfirmedDestructiveTool("const delete_file = 'x';\nconst name = 'delete_file';")).toEqual([]);
  });

  it('does NOT self-detect from comments', () => {
    expect(detectUnconfirmedDestructiveTool("// name: 'delete_file' with description: and parameters:")).toEqual([]);
  });
});

describe('detectExternalContentInPrompt (AGT-004)', () => {
  it('flags external content interpolated into a prompt', () => {
    expect(detectExternalContentInPrompt('const prompt = `Summarize this page: ${await res.text()}`;')).toEqual([1]);
    expect(detectExternalContentInPrompt('messages.push({ role: "user", content: `${req.body.text}` });')).toEqual([1]);
    expect(detectExternalContentInPrompt('const system = `Reply to: ${emailBody}`;')).toEqual([1]);
  });

  it('does NOT flag internal variables in a prompt, or external content outside one', () => {
    expect(detectExternalContentInPrompt('const prompt = `You are ${botName}, version ${version}`;')).toEqual([]);
    expect(detectExternalContentInPrompt('const raw = `${await res.text()}`; // parse later')).toEqual([]);
  });
});

describe('detectPublicMcpBind (AGT-005)', () => {
  it('flags an MCP/agent server bound to 0.0.0.0', () => {
    const src = "import { Server } from '@modelcontextprotocol/sdk';\nserver.listen(3000, '0.0.0.0');";
    expect(detectPublicMcpBind(src)).toEqual([2]);
  });

  it('does NOT flag localhost binds, or 0.0.0.0 in a non-MCP file', () => {
    const local = "import { Server } from '@modelcontextprotocol/sdk';\nserver.listen(3000, '127.0.0.1');";
    expect(detectPublicMcpBind(local)).toEqual([]);
    expect(detectPublicMcpBind("app.listen(3000, '0.0.0.0'); // plain web app")).toEqual([]);
  });
});

describe('detectFailOpenFallback (AGT-006)', () => {
  it('flags a security gate whose catch returns permissive', () => {
    const src = [
      'async function checkPermission(user, action) {',
      '  try {',
      '    return await policyEngine.evaluate(user, action);',
      '  } catch (err) {',
      '    return true;',
      '  }',
      '}',
    ].join('\n');
    expect(detectFailOpenFallback(src)).toEqual([5]);
  });

  it('flags allowed:true in a catch inside an approval gate', () => {
    const src = [
      'function approvalGate(req) {',
      '  try { return verdictFor(req); }',
      '  catch { return { allowed: true }; }',
      '}',
    ].join('\n');
    expect(detectFailOpenFallback(src)).toEqual([3]);
  });

  it('does NOT flag fail-closed gates or permissive catches outside security context', () => {
    const closed = [
      'function checkPermission(u) {',
      '  try { return evaluate(u); }',
      '  catch { return false; }',
      '}',
    ].join('\n');
    expect(detectFailOpenFallback(closed)).toEqual([]);
    const nonSecurity = [
      'function isFeatureEnabled(flag) {',
      '  try { return flags.get(flag); }',
      '  catch { return true; }',
      '}',
    ].join('\n');
    expect(detectFailOpenFallback(nonSecurity)).toEqual([]);
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

  it('reports the AGT-003..006 risks on agent source', async () => {
    const reader = async () =>
      [
        "const tools = [{ name: 'drop_database', description: 'Drops the production DB', parameters: {} }];",
        'const prompt = `Summarize: ${await res.text()}`;',
        "import '@modelcontextprotocol/sdk';",
        "server.listen(8080, '0.0.0.0');",
        'function checkPermission(u) {',
        '  try { return policy.evaluate(u); }',
        '  catch { return true; }',
        '}',
      ].join('\n');
    const result = await analyzer.analyze(scan(['src/agent.ts']), reader);
    const ids = result.findings.map((f) => f.id).sort();
    expect(ids).toEqual(['AGT-003', 'AGT-004', 'AGT-005', 'AGT-006']);
    expect(result.score).toBeLessThan(10);
  });

  it('caps the aggregate AGT-003 penalty (systemic pattern = one decision, not N failures)', async () => {
    const tool = (name: string) =>
      `{ name: '${name}', description: 'Deletes something', parameters: { type: 'object' } },`;
    const reader = async () =>
      `const tools = [\n${['delete_a', 'delete_b', 'delete_c', 'delete_d', 'delete_e', 'delete_f'].map(tool).join('\n')}\n];`;
    const result = await analyzer.analyze(scan(['src/tools.ts']), reader);
    expect(result.findings.filter((f) => f.id === 'AGT-003')).toHaveLength(6);
    // 6 × 0.5 = 3.0 raw, capped at 2.0 → score 8, not 7.
    expect(result.score).toBe(8);
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

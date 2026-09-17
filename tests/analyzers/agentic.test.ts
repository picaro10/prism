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

  it('flags chat/messaging text (Telegram, Discord, Slack handlers) interpolated into a prompt', () => {
    expect(detectExternalContentInPrompt('const prompt = `Reply to the user: ${msg.text}`;')).toEqual([1]);
    expect(detectExternalContentInPrompt('const system = `Context: ${ctx.message.text}`;')).toEqual([1]);
    expect(
      detectExternalContentInPrompt('messages.push({ role: "user", content: `Task: ${message.caption}` });'),
    ).toEqual([1]);
    expect(detectExternalContentInPrompt('const prompt = `Summarize: ${event.text}`;')).toEqual([1]);
    expect(detectExternalContentInPrompt('const instruction = `${update.message.caption}`;')).toEqual([1]);
  });

  it('does NOT flag message text passed as a structured user turn, or merely logged (the recommended patterns)', () => {
    // A user-role content block is data, not instructions — no interpolation, no finding.
    expect(detectExternalContentInPrompt("messages.push({ role: 'user', content: message.text });")).toEqual([]);
    expect(detectExternalContentInPrompt('logger.info(`incoming: ${msg.text}`);')).toEqual([]);
    expect(detectExternalContentInPrompt('const firewall = analyzePrompt(message.text);')).toEqual([]);
  });

  it('does NOT flag chat-history merging or preview slicing (field FPs on a real agent)', () => {
    // Consecutive same-role turns merged: the content stays in its role block.
    expect(detectExternalContentInPrompt('prev.content += `\\n${msg.content}`;')).toEqual([]);
    // A preview: the word "message" outside the interpolation is not prompt context.
    expect(
      detectExternalContentInPrompt(
        'const msgPreview = message.text.length > 150 ? `${message.text.slice(0, 147)}...` : message.text;',
      ),
    ).toEqual([]);
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

describe('Python parity — the same risks in the shapes Python agents actually write', () => {
  describe('detectShellInjection (AGT-001, Python)', () => {
    it('flags os.system / os.popen with an f-string, .format, % or + command', () => {
      expect(detectShellInjection('os.system(f"ls {path}")')).toEqual([1]);
      expect(detectShellInjection("os.popen('git log ' + ref)")).toEqual([1]);
      expect(detectShellInjection('os.system("rm -rf {}".format(target))')).toEqual([1]);
      expect(detectShellInjection('os.system("cat %s" % name)')).toEqual([1]);
    });

    it('flags subprocess with shell=True and a dynamic command, and sh -c with an f-string', () => {
      expect(detectShellInjection('subprocess.run(f"convert {src} out.png", shell=True)')).toEqual([1]);
      expect(detectShellInjection('subprocess.check_output("ls " + d, shell=True)')).toEqual([1]);
      expect(detectShellInjection('subprocess.Popen(["sh", "-c", f"echo {msg}"])')).toEqual([1]);
    });

    it('does NOT flag subprocess with an argument list, a literal command with shell=True, or shell-less f-strings', () => {
      expect(detectShellInjection('subprocess.run(["ls", path], check=True)')).toEqual([]);
      expect(detectShellInjection('subprocess.run("ls -la", shell=True)')).toEqual([]);
      // No shell: the f-string is the program name, not a shell line.
      expect(detectShellInjection('subprocess.run(f"{tool}", capture_output=True)')).toEqual([]);
      expect(detectShellInjection('# os.system(f"ls {path}")  -- documented anti-pattern')).toEqual([]);
    });
  });

  describe('detectSecretInPrompt (AGT-002, Python)', () => {
    it('flags os.environ / os.getenv interpolated into prompt context', () => {
      expect(detectSecretInPrompt('prompt = f"You are a bot. token={os.environ[\'API_KEY\']}"')).toEqual([1]);
      expect(detectSecretInPrompt('system = f"key={os.getenv(\'OPENAI_KEY\')}"')).toEqual([1]);
      expect(
        detectSecretInPrompt('messages.append({"role": "system", "content": f"secret={os.environ.get(\'S\')}"})'),
      ).toEqual([1]);
    });
    it('does NOT flag env usage away from prompt context', () => {
      expect(detectSecretInPrompt('port = int(os.environ.get("PORT", "8000"))')).toEqual([]);
      expect(detectSecretInPrompt('url = f"http://{os.environ[\'HOST\']}:8000"')).toEqual([]);
    });
  });

  describe('detectExternalContentInPrompt (AGT-004, Python)', () => {
    it('flags request/response/message/email content interpolated with an f-string or .format into a prompt', () => {
      expect(detectExternalContentInPrompt('prompt = f"Summarize: {request.json[\'text\']}"')).toEqual([1]);
      expect(detectExternalContentInPrompt('prompt = f"Summarize this page: {response.text}"')).toEqual([1]);
      expect(detectExternalContentInPrompt('system = "Reply to: {}".format(update.message.text)')).toEqual([1]);
      expect(
        detectExternalContentInPrompt('messages.append({"role": "user", "content": f"Task: {email_body}"})'),
      ).toEqual([1]);
    });
    it('does NOT flag a structured user turn, a log line, or internal variables', () => {
      expect(detectExternalContentInPrompt('messages.append({"role": "user", "content": message.text})')).toEqual([]);
      expect(detectExternalContentInPrompt('logger.info(f"incoming: {message.text}")')).toEqual([]);
      expect(detectExternalContentInPrompt('prompt = f"You are {bot_name} v{version}"')).toEqual([]);
      // Field FP shape from AETHER: a summarizer transcript line with role/content of prior turns.
      expect(detectExternalContentInPrompt('parts.append(f"[{role}]: {content}")')).toEqual([]);
    });
  });

  describe('detectFailOpenFallback (AGT-006, Python)', () => {
    it('flags a security gate whose except returns permissive', () => {
      const src = [
        'async def check_permission(user, action):',
        '    try:',
        '        return await policy.evaluate(user, action)',
        '    except Exception:',
        '        return True',
      ].join('\n');
      expect(detectFailOpenFallback(src)).toEqual([5]);
    });
    it('flags allowed=True / {"allowed": True} in an except inside an approval gate', () => {
      const src = [
        'def approve(request):',
        '    try:',
        '        return approval_service.decide(request)',
        '    except TimeoutError:',
        '        return {"allowed": True, "reason": "timeout"}',
      ].join('\n');
      expect(detectFailOpenFallback(src)).toEqual([5]);
    });
    it('does NOT flag fail-closed gates or a permissive except outside security context', () => {
      const closed = [
        'def check_auth(u):',
        '    try:',
        '        return verify(u)',
        '    except Exception:',
        '        return False',
      ].join('\n');
      expect(detectFailOpenFallback(closed)).toEqual([]);
      const flag = [
        'def show_banner(u):',
        '    try:',
        '        return flags.get(u)',
        '    except Exception:',
        '        return True',
      ].join('\n');
      expect(detectFailOpenFallback(flag)).toEqual([]);
    });
  });
});

describe('Python parity — field false positives from a real agent framework, engineered out', () => {
  it('AGT-006: a NEGATIVE predicate (is_locked_out, is_blocked…) returning True on error is fail-CLOSED', () => {
    const src = [
      'async def is_locked_out(self, user_id: str) -> bool:',
      '    """Check if user is locked out due to too many failed auth attempts."""',
      '    try:',
      '        return bool(await client.exists(key) > 0)',
      '    except Exception as e:',
      '        logger.error(f"is_locked_out failed: {e}")',
      '        return True  # fail-closed: assume locked out',
    ].join('\n');
    expect(detectFailOpenFallback(src)).toEqual([]);
  });

  it('AGT-006: an inline "fail-closed" comment on the return is an explicit, documented decision', () => {
    const src = [
      'def check_permission(u):',
      '    try:',
      '        return policy.allows(u)',
      '    except Exception:',
      '        return True  # fail-closed by design: this predicate means DENY',
    ].join('\n');
    expect(detectFailOpenFallback(src)).toEqual([]);
  });

  it('AGT-006: a permissive return AFTER the except block (dedented) is not the except handler', () => {
    const src = [
      'def _is_settings_admin(self, ctx) -> bool:',
      '    """Check trusted server-side admin allowlists."""',
      '    try:',
      '        uid = int(ctx.user_id)',
      '        if uid in settings.TELEGRAM_ADMIN_IDS:',
      '            return True',
      '    except (ValueError, TypeError):',
      '        pass',
      '',
      '    if ctx.user_id in settings.WHATSAPP_ADMIN_NUMBERS:',
      '        return True',
      '    return False',
    ].join('\n');
    expect(detectFailOpenFallback(src)).toEqual([]);
  });

  it('AGT-004: an error message is not a prompt, even when a product name contains "Assistant"', () => {
    expect(
      detectExternalContentInPrompt(
        'raise RuntimeError(f"Home Assistant API {response.status_code}: {response.text[:200]}")',
      ),
    ).toEqual([]);
  });

  it('AGT-004: the same error message split over two lines (raise on the opener line) is still not a prompt', () => {
    const src = [
      'if response.status_code >= 400:',
      '    raise RuntimeError(',
      '        f"Home Assistant API {response.status_code}: {response.text[:200]}"',
      '    )',
    ].join('\n');
    expect(detectExternalContentInPrompt(src)).toEqual([]);
  });

  it('AGT-004: an MCP tool-result content block is transport, not prompt construction — unless a role is set', () => {
    // Tool result envelope: `content: [{type: text, text: ...}]` with no role/prompt/system word.
    expect(
      detectExternalContentInPrompt(
        '"content": [{"type": "text", "text": f"HTTP {resp.status_code}: {resp.text[:500]}"}],',
      ),
    ).toEqual([]);
    // The same block shape inside a user turn IS prompt construction.
    expect(
      detectExternalContentInPrompt(
        'messages.append({"role": "user", "content": [{"type": "text", "text": f"Page: {response.text}"}]})',
      ),
    ).toEqual([1]);
  });
});

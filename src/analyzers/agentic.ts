import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding } from '../core/types.js';
import { extname } from 'node:path';
import { classifyFile, isExcludedContext } from '../utils/file-context.js';

/**
 * AgenticAnalyzer — risks specific to code that builds or runs AI agents.
 *
 * This is PRISM's own territory: mainstream static analyzers (Semgrep, Sonar)
 * don't model the failure modes of agent code. The checks here are deliberately
 * high-signal and conservative — PRISM's north star is credibility, and a noisy
 * "AI-security" check would be worse than none.
 *
 * Checks:
 * - AGT-001: a shell command built with interpolation/concatenation (exec/execSync
 *   always spawn a shell) — the classic path for tool/agent command injection.
 *   execFile/execFileSync (shell-less) are intentionally NOT flagged.
 * - AGT-002: an environment secret interpolated into an LLM prompt/message — a
 *   credential leaking into model context.
 * - AGT-003: a destructive agent tool (delete/drop/kill/…) defined with no
 *   confirmation/approval gate anywhere in its definition block.
 * - AGT-004: external content (fetched page, request body, email…) interpolated
 *   into an LLM prompt — the prompt-injection front door.
 * - AGT-005: an MCP/agent server bound to 0.0.0.0 — the agent's tool surface
 *   exposed to the network.
 * - AGT-006: a security gate (auth/permission/policy/approval) whose catch
 *   returns permissive — the gate fails OPEN exactly when it breaks.
 */
export class AgenticAnalyzer implements Analyzer {
  readonly name = 'agentic';
  readonly category = 'agentic' as const;
  readonly description = 'Detects AI-agent-specific risks: shell injection in tools, secrets leaking into LLM context';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;
    // AGT-003 hits usually share ONE root cause (no gating convention), so the
    // aggregate penalty is capped: ten ungated tools are one decision to fix,
    // not ten independent failures. Each finding is still reported.
    let agt003Penalty = 0;

    const sourceFiles = scan.files.filter((f) => {
      if (!AGENT_SOURCE_EXTS.includes(extname(f))) return false;
      const ctx = classifyFile(f);
      return ctx === 'source' && !isExcludedContext(ctx);
    });

    let skipped = 0;
    for (const file of sourceFiles) {
      let content: string;
      try {
        content = await readFile(file);
      } catch {
        skipped++;
        continue;
      }
      if (content.length > MAX_FILE_SIZE) {
        skipped++;
        continue;
      }

      for (const line of detectShellInjection(content)) {
        findings.push({
          id: 'AGT-001',
          category: 'agentic',
          severity: 'high',
          title: 'Shell command built with interpolation (agent command-injection risk)',
          description:
            'exec/execSync spawn a shell; interpolating a variable into the command lets untrusted (e.g. LLM- or tool-derived) input inject commands.',
          suggestion: 'Use execFile/execFileSync with an argument array (no shell), or strictly validate the argument.',
          file,
          line,
        });
        score -= 1.0;
      }

      for (const line of detectSecretInPrompt(content)) {
        findings.push({
          id: 'AGT-002',
          category: 'agentic',
          severity: 'medium',
          title: 'Environment secret interpolated into an LLM prompt',
          description:
            'A process.env secret is being placed into prompt/message content, leaking the credential into the model context (and any provider logs).',
          suggestion: 'Never put secrets in prompts. Pass credentials via the client/transport, not the message body.',
          file,
          line,
        });
        score -= 0.5;
      }

      for (const line of detectUnconfirmedDestructiveTool(content)) {
        findings.push({
          id: 'AGT-003',
          category: 'agentic',
          severity: 'medium',
          title: 'Destructive agent tool with no confirmation gate',
          description:
            'A tool the agent can call autonomously performs a destructive action (delete/drop/kill/…) and its definition carries no confirmation, approval, or dangerous-operation marker.',
          suggestion:
            'Gate destructive tools behind explicit human confirmation (e.g. a requiresConfirmation flag your executor enforces, or an approval step). If an external policy engine already gates them, add the marker to the definition — or accept the finding with a justified suppression naming that policy.',
          file,
          line,
        });
        agt003Penalty += 0.5;
      }

      for (const line of detectExternalContentInPrompt(content)) {
        findings.push({
          id: 'AGT-004',
          category: 'agentic',
          severity: 'high',
          title: 'External content interpolated into an LLM prompt (prompt-injection risk)',
          description:
            'Fetched/scraped/user-submitted content is placed directly into prompt or message content. Instructions embedded in that content can hijack the agent (exfiltrate data, fire tools).',
          suggestion:
            'Treat external content as data, not instructions: delimit it clearly, pass it in a separate user/content block, and never grant tool access to a turn that includes raw external text without a firewall.',
          file,
          line,
        });
        score -= 1.0;
      }

      for (const line of detectPublicMcpBind(content)) {
        findings.push({
          id: 'AGT-005',
          category: 'agentic',
          severity: 'high',
          title: 'MCP/agent server bound to 0.0.0.0 (publicly exposed tool surface)',
          description:
            "An MCP or agent server listens on all interfaces. Anyone who can reach the host can call the agent's tools — usually without auth, since MCP assumes a trusted transport.",
          suggestion:
            "Bind to 127.0.0.1 and put the server behind an authenticated reverse proxy if remote access is genuinely needed — PRISM's own dashboard does exactly this.",
          file,
          line,
        });
        score -= 1.0;
      }

      for (const line of detectFailOpenFallback(content)) {
        findings.push({
          id: 'AGT-006',
          category: 'agentic',
          severity: 'high',
          title: 'Security gate fails open (catch returns permissive)',
          description:
            'An auth/permission/policy/approval check returns an allow verdict from its catch block — the gate grants access exactly when it is broken (provider down, bad config, exception).',
          suggestion:
            'Fail closed: return deny/false from the error path and surface the failure. If availability demands otherwise, make the fail-open explicit, logged, and alarmed.',
          file,
          line,
        });
        score -= 1.0;
      }
    }

    score -= Math.min(agt003Penalty, MAX_AGT003_PENALTY);
    const capped = Math.max(0, Math.round(score * 10) / 10);
    const byId = (id: string) => findings.filter((f) => f.id === id).length;
    const parts = [
      [byId('AGT-001'), 'shell-injection'],
      [byId('AGT-002'), 'secret-in-prompt'],
      [byId('AGT-003'), 'unconfirmed-destructive-tool'],
      [byId('AGT-004'), 'external-content-in-prompt'],
      [byId('AGT-005'), 'public-mcp-bind'],
      [byId('AGT-006'), 'fail-open-gate'],
    ]
      .filter(([n]) => (n as number) > 0)
      .map(([n, label]) => `${n} ${label}`);
    return {
      category: 'agentic',
      score: capped,
      findings,
      summary: (() => {
        const coverage = skipped > 0 ? ` (${skipped} file(s) unreadable/too large — NOT analyzed)` : '';
        return findings.length === 0
          ? `No agent-specific risks detected (shell injection, secrets/external content in prompts, unconfirmed destructive tools, public MCP binds, fail-open gates)${coverage}.`
          : `${findings.length} agent-specific risk(s): ${parts.join(', ')}${coverage}.`;
      })(),
    };
  }
}

const AGENT_SOURCE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py'];
const MAX_FILE_SIZE = 2 * 1024 * 1024;
const MAX_AGT003_PENALTY = 2.0;

/**
 * Lines where a shell command (exec/execSync — which use a shell) is built with
 * an interpolated template or string concatenation. execFile/execFileSync are
 * shell-less and never flagged. Returns 1-based line numbers.
 */
export function detectShellInjection(content: string): number[] {
  const hits: number[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (isPatternDefinition(l)) continue; // a linter/scanner writing this very pattern, not calling it
    const interpolatedTemplate = /\bexec(Sync)?\s*\([^)]*\$\{/.test(l); // exec(`... ${x} ...`) or exec(tmpl) with ${
    const stringConcat = /\bexec(Sync)?\s*\(\s*['"][^'"]*['"]\s*\+/.test(l); // exec("cmd " + x)
    const varConcat = /\bexec(Sync)?\s*\(\s*\w+\s*\+/.test(l); // exec(cmd + " -rf")
    // Python: os.system/os.popen always use a shell; subprocess only with
    // shell=True or an explicit `sh -c`. A dynamic command is an f-string,
    // .format(), % formatting or + concatenation on the same line. A literal
    // with shell=True, or an argument list, never fires.
    const pyOsShell = /\bos\.(system|popen)\s*\(/.test(l) && PY_DYNAMIC_STRING.test(l);
    const pySubprocessShell =
      /\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\(/.test(l) &&
      /\bshell\s*=\s*True\b/.test(l) &&
      PY_DYNAMIC_STRING.test(l);
    const pyShDashC = /\[\s*["'](?:\/bin\/)?(?:sh|bash|zsh)["']\s*,\s*["']-c["']\s*,\s*f["']/.test(l);
    if (interpolatedTemplate || stringConcat || varConcat || pyOsShell || pySubprocessShell || pyShDashC)
      hits.push(i + 1);
  }
  return hits;
}

/** A Python string built at runtime: f-string, .format(), % formatting, or + concatenation. */
const PY_DYNAMIC_STRING = /\bf["']|\.format\(|["']\s*%\s*\(?\w|["']\s*\+\s*\w|\w\s*\+\s*["']/;

/**
 * True when a line is NOT real executable code that could inject — a comment,
 * or a regex/pattern definition. A scanner (like this file) writes these very
 * patterns in comments and regexes; flagging them would be self-detection.
 */
function isPatternDefinition(line: string): boolean {
  const t = line.trim();
  if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('#')) return true;
  return /\\[bsdw]|\[\^|\.test\(|\.match\(|new RegExp|RegExp\(/.test(line);
}

/**
 * Lines where an environment secret is interpolated into what reads like an LLM
 * prompt/message. Requires BOTH a `${process.env.X}` interpolation and a prompt
 * keyword on the same line — conservative, to keep false positives near zero.
 * Returns 1-based line numbers.
 */
export function detectSecretInPrompt(content: string): number[] {
  const hits: number[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (isPatternDefinition(l)) continue;
    const jsEnv = /\$\{\s*process\.env\.\w+/.test(l);
    const pyEnv = /\{[^}]*\bos\.(environ|getenv)\b/.test(l); // f"...{os.environ['X']}..." / {os.getenv('X')}
    if ((jsEnv || pyEnv) && PROMPT_CTX.test(l)) hits.push(i + 1);
  }
  return hits;
}

/** Words that make a line read like LLM prompt/message construction. */
const PROMPT_CTX = /\b(prompt|system|messages?|content|instruction|role|assistant)\b/i;

/** Tool names an agent can fire that destroy or exfiltrate irreversibly. */
const DESTRUCTIVE_NAME = /['"`](?:\w+_)?(delete|remove|drop|destroy|wipe|truncate|kill|terminate)(_\w+)?['"`]/i;

/** Markers that show a human gate exists somewhere in the tool's definition. */
const CONFIRMATION_MARKER = /requires?_?(confirmation|approval)|confirm|approval|approve|dangerous|destructive/i;

/**
 * AGT-003 — a tool DEFINITION (name + description + a parameter schema nearby)
 * whose name is destructive, with no confirmation marker anywhere in the
 * surrounding block. The schema requirement is what keeps this conservative: a
 * plain variable or string that happens to contain "delete" never qualifies.
 * Returns the 1-based line of the tool's name.
 */
export function detectUnconfirmedDestructiveTool(content: string): number[] {
  const hits: number[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (isPatternDefinition(l)) continue;
    if (!/\bname\s*:/.test(l) || !DESTRUCTIVE_NAME.test(l)) continue;
    const block = lines.slice(Math.max(0, i - 5), i + 20).join('\n');
    const isToolDefinition =
      /\bdescription\s*:/.test(block) && /\b(parameters|inputSchema|input_schema|schema)\s*:/.test(block);
    if (isToolDefinition && !CONFIRMATION_MARKER.test(block)) hits.push(i + 1);
  }
  return hits;
}

/**
 * Expressions whose interpolation into a prompt means EXTERNAL content is
 * entering the model's context: fetched bodies, request input, emails, scraped
 * pages. Deliberately a closed list — a generic "any variable" rule would drown
 * the report in noise.
 */
const EXTERNAL_CONTENT = new RegExp(
  [
    'fetch\\s*\\(',
    '\\.text\\(\\)',
    '\\.html\\(',
    'req\\.(body|query|params)',
    'response\\.data',
    'email(Body|Content|Text|Html)',
    'email\\.(body|content|text|html)',
    '(page|web|scraped?|fetched)[A-Z_]?\\w*(Content|Text|Html|Body)?',
    'document\\.body',
    // Chat/messaging handlers — the input channel of most real agents
    // (Telegram, Discord, Slack, WhatsApp): the message text a stranger typed.
    // Only interpolation into a prompt counts; a structured user-role turn
    // (`content: message.text`) is the recommended pattern and stays silent.
    // `.content` is deliberately NOT a source: every chat-history loop says
    // `msg.content` (field FP on orion's history merge) — Discord's
    // message.content is a known gap, not worth that noise.
    '\\b(msg|message|ctx\\.message|update\\.message|ctx\\.update\\.message)\\.(text|caption)\\b',
    '\\bevent\\.text\\b',
    '\\binteraction\\.(content|options)\\b',
    '\\bpayload\\.text\\b',
    // Python web/HTTP shapes: Flask/FastAPI request, requests/aiohttp responses.
    '\\brequest\\.(json|data|form|args|values|get_json)\\b',
    '\\b(resp|response|res)\\.(text|content|json)\\b',
    'email_(body|text|html|content)',
  ].join('|'),
);
const EXTERNAL_CONTENT_ALL = new RegExp(EXTERNAL_CONTENT.source, 'g');

/**
 * AGT-004 — external content interpolated into an LLM prompt/message: the line
 * must read like prompt construction AND interpolate one of the known external
 * sources. Returns 1-based line numbers.
 */
export function detectExternalContentInPrompt(content: string): number[] {
  const hits: number[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (isPatternDefinition(l)) continue;
    // Where a value enters the string: JS `${...}`, Python f-string `{...}`
    // (only on a line that has an f-prefix), and `.format(...)` arguments.
    const exprs: string[] = l.match(/\$\{[^}]*\}/g) ?? [];
    if (/\bf["']/.test(l)) exprs.push(...(l.match(/\{[^{}]+\}/g) ?? []));
    for (const m of l.matchAll(/\.format\(([^)]*)\)/g)) exprs.push(...m[1].split(','));
    if (exprs.length === 0) continue;
    // Judge the prompt context on the line WITHOUT its interpolations and
    // without any external-source expression: `${message.text}` — or a bare
    // `message.text.length` next to it — must not itself supply the word
    // "message" that makes a log line or a preview slice look like prompt
    // construction (field FPs on orion).
    const frame = l
      .replace(/\$\{[^}]*\}/g, '')
      .replace(/\{[^{}]+\}/g, '')
      .replace(/\.format\([^)]*\)/g, '.format()')
      .replace(EXTERNAL_CONTENT_ALL, '');
    if (!PROMPT_CTX.test(frame)) continue;
    // An error message is not a prompt — even when a product name contains
    // "Assistant" (field FP: raise RuntimeError(f"Home Assistant API …")).
    // The `raise …Error(` may sit on the previous line with the f-string as
    // a continuation, so the opener line counts too.
    const opener = i > 0 && /\($/.test(lines[i - 1].trim()) ? lines[i - 1] : '';
    if (/\braise\b|\b\w*(Error|Exception)\s*\(/.test(`${opener}\n${frame}`)) continue;
    // An MCP / content-block tool RESULT (`content: [{type: text, text: …}]`)
    // is transport back to the model, not prompt authoring — unless the same
    // line also sets a role or names a prompt/system/instruction.
    if (/["']type["']\s*:\s*["']text["']/.test(frame) && !/\b(role|prompt|system|instruction)\b/i.test(frame)) continue;
    if (exprs.some((expr) => EXTERNAL_CONTENT.test(expr))) hits.push(i + 1);
  }
  return hits;
}

/**
 * AGT-005 — an MCP/agent server bound to all interfaces. Requires the FILE to
 * be MCP/agent-server code (imports the MCP SDK or names an MCP server) and the
 * LINE to bind 0.0.0.0 — a plain web app binding 0.0.0.0 is the docker
 * analyzer's business, not an agentic risk. Returns 1-based line numbers.
 */
export function detectPublicMcpBind(content: string): number[] {
  const isMcpFile = /@modelcontextprotocol|McpServer|\bmcp[-_.]?server/i.test(content);
  if (!isMcpFile) return [];
  const hits: number[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (isPatternDefinition(l)) continue;
    if (/\b(listen|bind|host)\b/i.test(l) && /0\.0\.0\.0/.test(l)) hits.push(i + 1);
  }
  return hits;
}

/** Function/context names that mean "this code IS a security gate". */
const SECURITY_GATE_CTX = /auth|permission|policy|guard|approv|rbac|\bacl\b|access/i;

/** Function names whose TRUE means deny: returning true on error is fail-closed for these. */
const NEGATIVE_PREDICATE = /\w*(lock|block|deny|denied|reject|ban|forbid|revok|expir|throttl|limited|suspend)\w*/i;

/** A permissive verdict: `return true`/`return True`, or allowed/granted/authorized: true (JS object or Python dict/kwarg). */
const PERMISSIVE_RETURN = /return\s+[Tt]rue\b|(allowed|granted|authorized|permitted)["']?\s*[:=]\s*[Tt]rue\b/;

/**
 * AGT-006 — a security gate that fails OPEN: a catch block returning a
 * permissive verdict, inside code whose nearby context (function names within
 * the previous ~20 lines) reads like auth/permission/policy/approval. Returns
 * the 1-based line of the permissive return.
 */
export function detectFailOpenFallback(content: string): number[] {
  const hits: number[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    // JS `catch` or a Python `except ...:` clause.
    const isExcept = /^\s*except\b.*:\s*$/.test(lines[i]);
    if (!(/\bcatch\b/.test(lines[i]) || isExcept) || isPatternDefinition(lines[i])) continue;
    const before = lines.slice(Math.max(0, i - 20), i + 1);
    if (!SECURITY_GATE_CTX.test(before.join('\n'))) continue;
    // A NEGATIVE predicate (is_locked_out, isBlocked, should_deny…) means
    // "true = deny": returning true on error is fail-CLOSED. Field FP on a
    // real agent's session guard.
    const enclosing =
      [...before].reverse().find((l) => /\b(def|function)\s+\w+|\w+\s*[:=]\s*(async\s*)?\(/.test(l)) ?? '';
    if (NEGATIVE_PREDICATE.test(enclosing)) continue;
    // Same-line `catch { return true; }` or a permissive return within the
    // next lines — for Python, only while still INSIDE the except block
    // (deeper indentation than the `except` line).
    const exceptIndent = isExcept ? lines[i].length - lines[i].trimStart().length : -1;
    for (let j = i; j < Math.min(lines.length, i + 6); j++) {
      if (isPatternDefinition(lines[j])) continue;
      const indent = lines[j].length - lines[j].trimStart().length;
      if (isExcept && j > i && lines[j].trim() !== '' && indent <= exceptIndent) break; // dedented: handler ended
      if (PERMISSIVE_RETURN.test(lines[j])) {
        // An inline "fail-closed" note is an explicit, documented decision.
        if (/fail[- ]?closed/i.test(lines[j])) break;
        hits.push(j + 1);
        break;
      }
    }
  }
  return hits;
}

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
 */
export class AgenticAnalyzer implements Analyzer {
  readonly name = 'agentic';
  readonly category = 'agentic' as const;
  readonly description = 'Detects AI-agent-specific risks: shell injection in tools, secrets leaking into LLM context';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;

    const sourceFiles = scan.files.filter((f) => {
      if (!AGENT_SOURCE_EXTS.includes(extname(f))) return false;
      const ctx = classifyFile(f);
      return ctx === 'source' && !isExcludedContext(ctx);
    });

    for (const file of sourceFiles) {
      let content: string;
      try {
        content = await readFile(file);
      } catch {
        continue;
      }
      if (content.length > MAX_FILE_SIZE) continue;

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
    }

    const capped = Math.max(0, Math.round(score * 10) / 10);
    return {
      category: 'agentic',
      score: capped,
      findings,
      summary:
        findings.length === 0
          ? 'No agent-specific risks detected (shell injection, secrets in prompt).'
          : `${findings.length} agent-specific risk(s): ${findings.filter((f) => f.id === 'AGT-001').length} shell-injection, ${findings.filter((f) => f.id === 'AGT-002').length} secret-in-prompt.`,
    };
  }
}

const AGENT_SOURCE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py'];
const MAX_FILE_SIZE = 2 * 1024 * 1024;

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
    if (interpolatedTemplate || stringConcat || varConcat) hits.push(i + 1);
  }
  return hits;
}

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
  const PROMPT_CTX = /\b(prompt|system|messages?|content|instruction|role|assistant)\b/i;
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (isPatternDefinition(l)) continue;
    if (/\$\{\s*process\.env\.\w+/.test(l) && PROMPT_CTX.test(l)) hits.push(i + 1);
  }
  return hits;
}

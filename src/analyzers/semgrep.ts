// ============================================================
// PRISM — Semgrep Analyzer (security category)
//
// Wraps the semgrep CLI (if installed) to run PRISM's curated taint rules:
// real dataflow findings (SQLi, XSS, SSRF, path traversal, deserialization,
// command/code injection) that structural analysis cannot see. Degrades to
// an info notice when semgrep is not on PATH — taint depth is optional,
// never a requirement. Results merge into the same `security` category as
// the secrets analyzer (the engine merges same-category results), and the
// AI triage layer runs over these findings like any other — that pass is
// what kills the false positives taint analysis is famous for.
// ============================================================

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, extname } from 'node:path';
import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding, Severity } from '../core/types.js';
import { classifyFile, adjustSeverity, isExcludedContext } from '../utils/file-context.js';
import { SEMGREP_RULES_YAML } from './semgrep-rules.js';

/** Injectable seam: runs the semgrep binary. Tests inject a fake. */
export type SemgrepRunner = (args: string[], opts: { cwd: string; timeoutMs: number }) => Promise<{ stdout: string }>;

const execFileAsync = promisify(execFile);

const defaultRunner: SemgrepRunner = async (args, opts) => {
  const { stdout } = await execFileAsync('semgrep', args, {
    cwd: opts.cwd,
    timeout: opts.timeoutMs,
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return { stdout };
};

/** File extensions our curated rules can say anything about. */
const SUPPORTED_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.py']);

/** Hard cap on mapped findings so a pathological repo can't flood the report. */
const MAX_FINDINGS = 200;

/** Whole-scan subprocess timeout. Per-rule timeout is passed to semgrep itself. */
const SCAN_TIMEOUT_MS = 120_000;

const SEVERITY_DELTAS: Record<Severity, number> = {
  critical: 1.5,
  high: 1,
  medium: 0.5,
  low: 0.2,
  info: 0,
};

/** Fallback when a rule carries no prism-severity metadata (e.g. user rules later). */
const SEMGREP_SEVERITY_MAP: Record<string, Severity> = {
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
};

interface SemgrepResult {
  check_id: string;
  path: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: Record<string, unknown>;
  };
}

export class SemgrepAnalyzer implements Analyzer {
  readonly name = 'semgrep';
  readonly category = 'security' as const;
  readonly description = 'Taint/dataflow analysis (SQLi, XSS, SSRF, traversal, deserialization) via semgrep';

  constructor(private readonly runner: SemgrepRunner = defaultRunner) {}

  async analyze(scan: ProjectScan, _readFile: FileReader): Promise<AnalyzerResult> {
    if (!scan.files.some((f) => SUPPORTED_EXTENSIONS.has(extname(f).toLowerCase()))) {
      return this.result(10, [], 'Semgrep: no JS/TS/Python files to analyze');
    }

    let raw: string;
    // The rules ship embedded in the bundle; semgrep needs them as a file.
    const dir = await mkdtemp(join(tmpdir(), 'prism-semgrep-'));
    try {
      const rulesPath = join(dir, 'prism-rules.yml');
      await writeFile(rulesPath, SEMGREP_RULES_YAML, 'utf-8');
      const args = [
        'scan',
        '--json',
        '--config',
        rulesPath,
        '--metrics=off',
        '--quiet',
        '--disable-version-check',
        '--timeout',
        '10',
        '.',
      ];
      ({ stdout: raw } = await this.runner(args, { cwd: scan.rootPath, timeoutMs: SCAN_TIMEOUT_MS }));
    } catch (err) {
      if ((err as { code?: unknown } | null)?.code === 'ENOENT') {
        return this.result(
          10,
          [
            this.notice(
              'SEC-SEMGREP-MISSING',
              'info',
              'Semgrep not installed — taint analysis skipped',
              'PRISM runs curated taint rules (SQLi, XSS, SSRF, path traversal, deserialization) through semgrep when it is available. Without it, only structural security checks ran.',
              'Install semgrep (`pipx install semgrep` or `brew install semgrep`) and re-run for dataflow-level findings.',
            ),
          ],
          'Semgrep not installed — taint analysis skipped',
        );
      }
      // Non-zero exit can still leave the JSON report on stdout (same salvage
      // pattern as npm audit). Only give up when there is nothing to parse.
      const stdout = (err as { stdout?: string | Buffer } | null)?.stdout?.toString();
      if (!stdout) return this.errorResult(err);
      raw = stdout;
    } finally {
      await rm(dir, { recursive: true, force: true });
    }

    let results: SemgrepResult[];
    try {
      const parsed = JSON.parse(raw) as { results?: SemgrepResult[] };
      if (!Array.isArray(parsed.results)) throw new Error('missing results[]');
      results = parsed.results;
    } catch (err) {
      return this.errorResult(err);
    }

    const findings = this.mapResults(results);
    const truncated = findings.length > MAX_FINDINGS;
    const kept = truncated ? findings.slice(0, MAX_FINDINGS) : findings;
    if (truncated) {
      kept.push(
        this.notice(
          'SEC-SEMGREP-TRUNCATED',
          'info',
          `Semgrep findings truncated to ${MAX_FINDINGS}`,
          `Semgrep produced ${findings.length} findings; only the first ${MAX_FINDINGS} are reported. A count this high usually means a rule is misfiring on generated or vendored code.`,
          'Fix the dominant finding class (or exclude the offending paths) and re-run.',
        ),
      );
    }

    let score = 10;
    for (const f of kept) score -= SEVERITY_DELTAS[f.severity];
    score = Math.max(0, Math.min(10, Math.round(score * 10) / 10));

    const summary =
      kept.length === 0 ? 'Semgrep taint analysis: clean' : `Semgrep taint analysis: ${kept.length} finding(s)`;
    return this.result(score, kept, summary);
  }

  private mapResults(results: SemgrepResult[]): Finding[] {
    const findings: Finding[] = [];
    for (const r of results) {
      if (typeof r.check_id !== 'string' || typeof r.path !== 'string') continue;
      const path = r.path.replace(/\\/g, '/');

      const context = classifyFile(path);
      if (isExcludedContext(context)) continue;

      const meta = r.extra?.metadata ?? {};
      const declared = meta['prism-severity'];
      const base: Severity =
        typeof declared === 'string' && declared in SEVERITY_DELTAS
          ? (declared as Severity)
          : (SEMGREP_SEVERITY_MAP[r.extra?.severity ?? ''] ?? 'medium');
      const severity = adjustSeverity(base, context);
      if (severity === null) continue;

      const ruleName = r.check_id.split('.').pop() ?? r.check_id;
      const message = r.extra?.message?.trim() || `Semgrep rule ${ruleName} matched`;
      findings.push({
        id: `SG-${ruleName.replace(/^prism-/, '').toUpperCase()}`,
        category: 'security',
        severity,
        title: message.split('\n')[0].slice(0, 140),
        description: message,
        file: path,
        ...(r.start?.line ? { line: r.start.line } : {}),
        ...(typeof meta.fix === 'string' ? { suggestion: meta.fix } : {}),
        meta: {
          engine: 'semgrep',
          checkId: r.check_id,
          ...(typeof meta.cwe === 'string' ? { cwe: meta.cwe } : {}),
          ...(typeof meta.owasp === 'string' ? { owasp: meta.owasp } : {}),
          semgrepSeverity: r.extra?.severity ?? 'unknown',
        },
      });
    }
    return findings;
  }

  private errorResult(err: unknown): AnalyzerResult {
    const detail = err instanceof Error ? err.message.split('\n')[0].slice(0, 200) : 'unknown error';
    return this.result(
      9.5,
      [
        this.notice(
          'SEC-SEMGREP-ERROR',
          'low',
          'Semgrep could not run — taint status UNKNOWN',
          `Semgrep is installed but the scan failed (${detail}). Dataflow vulnerability status is unknown, not clean.`,
          'Run `semgrep scan` manually in the project to see the underlying error, then re-run PRISM.',
        ),
      ],
      'Semgrep failed — taint status unknown',
    );
  }

  private notice(id: string, severity: Severity, title: string, description: string, suggestion: string): Finding {
    return { id, category: 'security', severity, title, description, suggestion, meta: { engine: 'semgrep' } };
  }

  private result(score: number, findings: Finding[], summary: string): AnalyzerResult {
    return { category: 'security', score, findings, summary };
  }
}

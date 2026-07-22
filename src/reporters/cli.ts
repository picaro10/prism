import chalk from 'chalk';
import type { AuditReport, Finding, CategoryScore } from '../core/types.js';
import type { Verdict, Remediation } from '../ai/types.js';
import { findingKey } from '../ai/types.js';

function verdictLabel(v: Verdict): string {
  if (v.classification === 'real') return chalk.green('✓ real');
  if (v.classification === 'false-positive') return chalk.dim('✗ likely FP');
  return chalk.yellow('? uncertain');
}

const SEVERITY_COLORS = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.gray,
};

const SEVERITY_ICONS = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: 'ℹ️ ',
};

const SCORE_COLOR = (score: number) => {
  if (score >= 8) return chalk.green.bold;
  if (score >= 6) return chalk.yellow.bold;
  if (score >= 4) return chalk.hex('#FFA500').bold; // orange
  return chalk.red.bold;
};

export function renderCliReport(report: AuditReport): void {
  console.log('');
  renderHeader(report);
  if (report.aiSummary) renderAiSummary(report.aiSummary);
  renderProjectInfo(report);
  renderOverallScore(report);
  renderCategoryBreakdown(report.categories);

  const verdictByKey = new Map<string, Verdict>();
  if (report.aiTriage) {
    for (const v of report.aiTriage.verdicts) verdictByKey.set(v.findingKey, v);
  }
  const fixByKey = new Map<string, Remediation>();
  for (const r of report.aiRemediation ?? []) fixByKey.set(r.findingKey, r);
  renderFindings(report.findings, verdictByKey, fixByKey);

  if (report.suppressed && report.suppressed.length > 0) {
    console.log(
      chalk.dim(
        `  ${report.suppressed.length} finding${report.suppressed.length === 1 ? '' : 's'} suppressed by config:`,
      ),
    );
    for (const s of report.suppressed) {
      console.log(chalk.dim(`    · ${s.finding.id}${s.finding.file ? ` ${s.finding.file}` : ''} — ${s.reason}`));
    }
    console.log('');
  }

  if (report.aiTriage) {
    const s = report.aiTriage.summary;
    console.log(
      `  ${chalk.bold('AI triage:')} ${chalk.green(`${s.real} real`)} · ${chalk.dim(
        `${s.falsePositive} false positives`,
      )} · ${chalk.yellow(`${s.uncertain} uncertain`)}`,
    );
    if (report.aiRemediation) {
      const coverage = `${report.aiRemediation.length}/${s.real}`;
      console.log(`  ${chalk.bold('AI fixes:')} ${coverage} confirmed-real findings got a fix proposal`);
    }
    console.log('');
  }

  renderFooter(report);
}

function renderHeader(report: AuditReport): void {
  const width = 60;
  const border = chalk.dim('═'.repeat(width));

  console.log(border);
  console.log(chalk.bold.white('  🔍 PRISM Audit Report'));
  console.log(chalk.dim(`  ${report.projectName} · v${report.prismVersion}`));
  console.log(border);
  console.log('');
}

function renderAiSummary(summary: string): void {
  console.log(chalk.bold('  🧠 AI Assessment'));
  console.log(chalk.dim('  ─────────────────'));
  for (const line of wrapText(summary, 72)) {
    console.log(`  ${line}`);
  }
  console.log('');
}

/** Word-wrap prose to a column width for terminal display. */
function wrapText(text: string, width: number): string[] {
  const out: string[] = [];
  for (const paragraph of text.split('\n')) {
    let line = '';
    for (const word of paragraph.split(/\s+/)) {
      if (line && line.length + word.length + 1 > width) {
        out.push(line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    out.push(line);
  }
  return out;
}

function renderProjectInfo(report: AuditReport): void {
  const m = report.projectMeta;

  console.log(chalk.bold('  Project Overview'));
  console.log(chalk.dim('  ─────────────────'));
  console.log(
    `  Stack:      ${chalk.white(m.stack.primary)}${m.stack.secondary.length ? chalk.dim(` + ${m.stack.secondary.join(', ')}`) : ''}`,
  );
  console.log(`  Files:      ${chalk.white(String(m.totalFiles))}`);
  console.log(`  Package:    ${chalk.white(m.packageManager || 'none')}`);
  console.log(`  Git:        ${m.hasGit ? chalk.green('✓') : chalk.red('✗')}`);
  console.log(`  Docker:     ${m.hasDocker ? chalk.green('✓') : chalk.red('✗')}`);
  console.log(`  CI/CD:      ${m.hasCi ? chalk.green('✓') : chalk.red('✗')}`);

  if (m.frameworks.length > 0) {
    console.log(`  Frameworks: ${chalk.white(m.frameworks.join(', '))}`);
  }

  console.log('');
}

function renderOverallScore(report: AuditReport): void {
  const colorFn = SCORE_COLOR(report.overallScore);
  const bar = renderScoreBar(report.overallScore, 40);

  console.log(chalk.bold('  Overall Score'));
  console.log(chalk.dim('  ─────────────────'));
  console.log(`  ${bar}  ${colorFn(`${report.overallScore}/10`)}`);
  console.log('');
}

function renderCategoryBreakdown(categories: CategoryScore[]): void {
  console.log(chalk.bold('  Category Breakdown'));
  console.log(chalk.dim('  ─────────────────'));

  for (const cat of categories) {
    const colorFn = SCORE_COLOR(cat.score);
    const bar = renderScoreBar(cat.score, 20);
    const label = cat.category.padEnd(14);
    const findingCount =
      cat.findings.length > 0 ? chalk.dim(` (${cat.findings.length} findings)`) : chalk.dim(' (clean)');

    console.log(`  ${label} ${bar}  ${colorFn(`${cat.score}/10`)}${findingCount}`);
  }

  console.log('');
}

function renderFindings(
  findings: Finding[],
  verdictByKey: Map<string, Verdict>,
  fixByKey: Map<string, Remediation>,
): void {
  if (findings.length === 0) {
    console.log(chalk.green.bold('  ✨ No issues found! Clean project.'));
    console.log('');
    return;
  }

  console.log(chalk.bold(`  Findings (${findings.length})`));
  console.log(chalk.dim('  ─────────────────'));

  // Group by severity
  const grouped = {
    critical: findings.filter((f) => f.severity === 'critical'),
    high: findings.filter((f) => f.severity === 'high'),
    medium: findings.filter((f) => f.severity === 'medium'),
    low: findings.filter((f) => f.severity === 'low'),
    info: findings.filter((f) => f.severity === 'info'),
  };

  for (const [severity, items] of Object.entries(grouped)) {
    if (items.length === 0) continue;

    const icon = SEVERITY_ICONS[severity as keyof typeof SEVERITY_ICONS];
    const colorFn = SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS];

    console.log('');
    console.log(`  ${icon} ${colorFn(severity.toUpperCase())} (${items.length})`);

    for (const finding of items) {
      const location = finding.file ? chalk.dim(` → ${finding.file}${finding.line ? `:${finding.line}` : ''}`) : '';

      console.log(`    ${chalk.white(finding.id)} ${finding.title}${location}`);

      const verdict = verdictByKey.get(findingKey(finding));
      if (verdict) {
        const pct = Math.round(Math.min(1, Math.max(0, verdict.confidence)) * 100);
        console.log(`      ${verdictLabel(verdict)} ${chalk.dim(`(${pct}%)`)} — ${verdict.reasoning}`);
      }

      const fix = fixByKey.get(findingKey(finding));
      if (fix) {
        const lines = wrapText(fix.fix, 66);
        console.log(`      🔧 ${chalk.bold('fix')} ${chalk.dim(`(${fix.effort} effort)`)} — ${lines[0]}`);
        for (const line of lines.slice(1)) {
          console.log(`         ${line}`);
        }
      }

      if (finding.suggestion) {
        console.log(`      ${chalk.dim(`💡 ${finding.suggestion}`)}`);
      }
    }
  }

  console.log('');
}

function renderFooter(report: AuditReport): void {
  const border = chalk.dim('═'.repeat(60));
  console.log(border);
  console.log(chalk.dim(`  Completed in ${report.durationMs}ms · ${new Date(report.completedAt).toLocaleString()}`));
  console.log(chalk.dim(`  PRISM v${report.prismVersion} · @latenciatech/prism`));
  console.log(border);
  console.log('');
}

function renderScoreBar(score: number, width: number): string {
  const filled = Math.round((score / 10) * width);
  const empty = width - filled;

  let color: typeof chalk;
  if (score >= 8) color = chalk.green;
  else if (score >= 6) color = chalk.yellow;
  else if (score >= 4) color = chalk.hex('#FFA500');
  else color = chalk.red;

  return color('█'.repeat(filled)) + chalk.dim('░'.repeat(empty));
}

import type { AuditReport, Finding, CategoryScore, Severity } from '../core/types.js';
import type { Verdict, Remediation } from '../ai/types.js';
import { findingKey } from '../ai/types.js';
import { writeReportFile } from './write.js';

/** Escape text for safe interpolation into HTML (content and attributes). */
export function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * Coerce a value to a finite number for safe interpolation. Reports rendered by
 * the dashboard come from JSON files on disk whose numeric fields aren't deeply
 * validated; a crafted `"<script>"` in a numeric slot must not reach the HTML.
 */
function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#e5484d' },
  high: { label: 'High', color: '#f76b15' },
  medium: { label: 'Medium', color: '#f5d90a' },
  low: { label: 'Low', color: '#3dd6f5' },
  info: { label: 'Info', color: '#8b8d98' },
};

function scoreColor(score: number): string {
  if (score >= 8) return '#46a758';
  if (score >= 6) return '#f5d90a';
  if (score >= 4) return '#f76b15';
  return '#e5484d';
}

function scoreBar(score: number, height = 10): string {
  const pct = Math.max(0, Math.min(100, score * 10));
  return `<div class="bar" style="height:${height}px"><div class="bar-fill" style="width:${pct}%;background:${scoreColor(score)}"></div></div>`;
}

function verdictBadge(v: Verdict): string {
  const pct = Math.round(Math.min(1, Math.max(0, v.confidence)) * 100);
  const map = {
    real: { cls: 'v-real', label: `✓ real (${pct}%)` },
    'false-positive': { cls: 'v-fp', label: `✗ likely FP (${pct}%)` },
    uncertain: { cls: 'v-uncertain', label: `? uncertain (${pct}%)` },
  } as const;
  const m = map[v.classification];
  return `<span class="badge ${m.cls}">${escapeHtml(m.label)}</span> <span class="reasoning">${escapeHtml(v.reasoning)}</span>`;
}

function renderFinding(f: Finding, verdict: Verdict | undefined, fix: Remediation | undefined): string {
  const location = f.file ? `<code class="loc">${escapeHtml(f.file)}${f.line ? `:${num(f.line)}` : ''}</code>` : '';
  const parts = [
    `<div class="finding">`,
    `<div class="finding-head"><code class="fid">${escapeHtml(f.id)}</code> <strong>${escapeHtml(f.title)}</strong> ${location}</div>`,
    `<p class="desc">${escapeHtml(f.description)}</p>`,
  ];
  if (verdict) parts.push(`<p class="verdict">${verdictBadge(verdict)}</p>`);
  if (fix) {
    parts.push(
      `<div class="fix"><span class="fix-tag">🔧 fix · ${escapeHtml(fix.effort)} effort</span><pre>${escapeHtml(fix.fix)}</pre></div>`,
    );
  }
  if (f.suggestion) parts.push(`<p class="suggestion">💡 ${escapeHtml(f.suggestion)}</p>`);
  parts.push('</div>');
  return parts.join('\n');
}

function renderCategory(cat: CategoryScore): string {
  const count = cat.findings.length;
  return [
    `<div class="cat-row">`,
    `<span class="cat-name">${escapeHtml(cat.category)}</span>`,
    scoreBar(num(cat.score)),
    `<span class="cat-score" style="color:${scoreColor(num(cat.score))}">${num(cat.score)}/10</span>`,
    `<span class="cat-count">${count === 0 ? 'clean' : `${count} finding${count === 1 ? '' : 's'}`}</span>`,
    '</div>',
  ].join('');
}

const STYLE = `
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1rem; background: #101114; color: #e0e1e6;
  font: 15px/1.55 system-ui, -apple-system, 'Segoe UI', sans-serif; }
.wrap { max-width: 880px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0; }
h2 { font-size: 1.05rem; margin: 2rem 0 0.8rem; color: #b8babf; text-transform: uppercase;
  letter-spacing: 0.06em; }
code { font-family: ui-monospace, 'Cascadia Code', Menlo, monospace; font-size: 0.92em; }
.sub { color: #8b8d98; margin-top: 0.25rem; }
.card { background: #18191d; border: 1px solid #26272c; border-radius: 10px; padding: 1.1rem 1.3rem;
  margin-top: 0.8rem; }
.ai-summary { border-left: 3px solid #6e56cf; white-space: pre-wrap; }
.overview { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.7rem; }
.ov-item .k { color: #8b8d98; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.ov-item .v { margin-top: 0.15rem; }
.score-big { display: flex; align-items: center; gap: 1.2rem; }
.score-num { font-size: 2.6rem; font-weight: 700; }
.bar { flex: 1; background: #26272c; border-radius: 99px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 99px; }
.cat-row { display: grid; grid-template-columns: 9rem 1fr 4.5rem 7rem; gap: 0.9rem; align-items: center;
  padding: 0.45rem 0; border-bottom: 1px solid #1f2025; }
.cat-row:last-child { border-bottom: none; }
.cat-name { text-transform: capitalize; }
.cat-score { font-weight: 600; text-align: right; }
.cat-count { color: #8b8d98; font-size: 0.85rem; }
details.sev { margin-top: 0.8rem; }
details.sev summary { cursor: pointer; font-weight: 600; padding: 0.5rem 0.8rem; border-radius: 8px;
  background: #18191d; border: 1px solid #26272c; list-style-position: inside; }
.sev-dot { display: inline-block; width: 0.65em; height: 0.65em; border-radius: 50%; margin-right: 0.45em; }
.finding { border-left: 2px solid #26272c; margin: 0.8rem 0 0.8rem 0.6rem; padding: 0.1rem 0 0.1rem 1rem; }
.finding-head .fid { color: #8b8d98; margin-right: 0.3rem; }
.loc { color: #8b8d98; }
.desc { margin: 0.35rem 0; color: #b8babf; }
.badge { padding: 0.1rem 0.5rem; border-radius: 99px; font-size: 0.8rem; font-weight: 600; }
.v-real { background: #1d3520; color: #6fd87a; }
.v-fp { background: #2a2b31; color: #8b8d98; }
.v-uncertain { background: #3a3013; color: #f5d90a; }
.reasoning { color: #8b8d98; font-size: 0.9rem; }
.fix { background: #15191f; border: 1px solid #1f2a38; border-radius: 8px; padding: 0.6rem 0.8rem;
  margin: 0.5rem 0; }
.fix-tag { color: #74b3f5; font-size: 0.82rem; font-weight: 600; }
.fix pre { margin: 0.4rem 0 0; white-space: pre-wrap; font-size: 0.88em; color: #c7d4e4; }
.suggestion { color: #8b8d98; font-size: 0.9rem; margin: 0.3rem 0; }
.tally { color: #b8babf; }
footer { margin-top: 2.5rem; color: #6c6e79; font-size: 0.85rem; border-top: 1px solid #1f2025;
  padding-top: 1rem; }
.clean { color: #6fd87a; font-weight: 600; }
`;

/** Render the audit report as a fully self-contained HTML document. */
export function formatHtmlReport(report: AuditReport): string {
  const verdictByKey = new Map<string, Verdict>();
  for (const v of report.aiTriage?.verdicts ?? []) verdictByKey.set(v.findingKey, v);
  const fixByKey = new Map<string, Remediation>();
  for (const r of report.aiRemediation ?? []) fixByKey.set(r.findingKey, r);

  const m = report.projectMeta;
  const overview: Array<[string, string]> = [
    ['Stack', m.stack.primary + (m.stack.secondary.length ? ` + ${m.stack.secondary.join(', ')}` : '')],
    ['Files', String(m.totalFiles)],
    ['Package', m.packageManager ?? 'none'],
    ['Git', m.hasGit ? 'yes' : 'no'],
    ['Docker', m.hasDocker ? 'yes' : 'no'],
    ['CI/CD', m.hasCi ? 'yes' : 'no'],
  ];
  if (m.frameworks.length > 0) overview.push(['Frameworks', m.frameworks.join(', ')]);

  const sections: string[] = [];

  sections.push(`<h1>🔍 PRISM Audit Report</h1>
<p class="sub">${escapeHtml(report.projectName)} · PRISM v${escapeHtml(report.prismVersion)} · ${escapeHtml(
    new Date(report.completedAt).toLocaleString(),
  )}</p>`);

  if (report.aiSummary) {
    sections.push(`<h2>🧠 AI Assessment</h2>
<div class="card ai-summary">${escapeHtml(report.aiSummary)}</div>`);
  }

  sections.push(`<h2>Overview</h2>
<div class="card overview">
${overview.map(([k, v]) => `<div class="ov-item"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div></div>`).join('\n')}
</div>`);

  sections.push(`<h2>Overall Score</h2>
<div class="card score-big">
<span class="score-num" style="color:${scoreColor(num(report.overallScore))}">${num(report.overallScore)}/10</span>
${scoreBar(num(report.overallScore), 14)}
</div>`);

  sections.push(`<h2>Category Breakdown</h2>
<div class="card">
${report.categories.map(renderCategory).join('\n')}
</div>`);

  sections.push(`<h2>Findings (${report.findings.length})</h2>`);
  if (report.findings.length === 0) {
    sections.push(`<div class="card clean">✨ No issues found — clean project.</div>`);
  } else {
    for (const severity of SEVERITY_ORDER) {
      const items = report.findings.filter((f) => f.severity === severity);
      if (items.length === 0) continue;
      const meta = SEVERITY_META[severity];
      sections.push(`<details class="sev" open>
<summary><span class="sev-dot" style="background:${meta.color}"></span>${meta.label} (${items.length})</summary>
${items.map((f) => renderFinding(f, verdictByKey.get(findingKey(f)), fixByKey.get(findingKey(f)))).join('\n')}
</details>`);
    }
  }

  if (report.aiTriage) {
    const s = report.aiTriage.summary;
    const fixLine = report.aiRemediation
      ? ` · <strong>AI fixes:</strong> ${report.aiRemediation.length}/${s.real} confirmed-real findings got a fix proposal`
      : '';
    sections.push(
      `<p class="tally"><strong>AI triage:</strong> ${s.real} real · ${s.falsePositive} false positives · ${s.uncertain} uncertain${fixLine}</p>`,
    );
  }

  sections.push(
    `<footer>Completed in ${num(report.durationMs)}ms · PRISM v${escapeHtml(report.prismVersion)} · @latenciatech/prism</footer>`,
  );

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PRISM Audit — ${escapeHtml(report.projectName)}</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
${sections.join('\n\n')}
</div>
</body>
</html>
`;
}

/** Write the audit report as a self-contained HTML file (creates parent directories). */
export async function writeHtmlReport(report: AuditReport, outputPath: string): Promise<void> {
  await writeReportFile(outputPath, formatHtmlReport(report));
}

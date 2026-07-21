import { createServer, type Server } from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { join, basename } from 'node:path';
import type { AuditReport } from '../core/types.js';
import { formatHtmlReport, escapeHtml } from '../reporters/html.js';

/** A report file the dashboard can list and render. */
export interface ReportEntry {
  /** File name within the dashboard directory (always a plain basename). */
  file: string;
  report: AuditReport;
}

/** Shape check: is this parsed JSON a PRISM audit report? */
export function isPrismReport(value: unknown): value is AuditReport {
  if (!value || typeof value !== 'object') return false;
  const r = value as Partial<AuditReport>;
  return (
    typeof r.projectName === 'string' &&
    typeof r.overallScore === 'number' &&
    Array.isArray(r.findings) &&
    Array.isArray(r.categories)
  );
}

/**
 * Load every PRISM report in a directory (non-recursive). Files that are not
 * JSON or not PRISM reports are skipped silently — the dir may hold anything.
 * Reads fresh on every call so new audits appear without restarting.
 */
export async function loadReports(dir: string): Promise<ReportEntry[]> {
  const entries: ReportEntry[] = [];
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  for (const name of names.filter((n) => n.endsWith('.json')).sort()) {
    try {
      const parsed = JSON.parse(await readFile(join(dir, name), 'utf-8'));
      if (isPrismReport(parsed)) entries.push({ file: name, report: parsed });
    } catch {
      // unreadable or invalid JSON — not a report, skip
    }
  }
  // Newest first; group cohesion comes from sorting by project then date.
  entries.sort(
    (a, b) =>
      a.report.projectName.localeCompare(b.report.projectName) ||
      (b.report.completedAt ?? '').localeCompare(a.report.completedAt ?? ''),
  );
  return entries;
}

function scoreColor(score: number): string {
  if (score >= 8) return '#46a758';
  if (score >= 6) return '#f5d90a';
  if (score >= 4) return '#f76b15';
  return '#e5484d';
}

const INDEX_STYLE = `
:root { color-scheme: dark; }
body { margin: 0; padding: 2rem 1rem; background: #101114; color: #e0e1e6;
  font: 15px/1.55 system-ui, -apple-system, 'Segoe UI', sans-serif; }
.wrap { max-width: 880px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 0.2rem; }
.sub { color: #8b8d98; margin: 0 0 1.5rem; }
table { width: 100%; border-collapse: collapse; background: #18191d; border: 1px solid #26272c;
  border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 0.6rem 0.9rem; border-bottom: 1px solid #1f2025; }
th { color: #8b8d98; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
tr:last-child td { border-bottom: none; }
a { color: #74b3f5; text-decoration: none; }
a:hover { text-decoration: underline; }
.score { font-weight: 700; }
.muted { color: #8b8d98; font-size: 0.88rem; }
.empty { background: #18191d; border: 1px solid #26272c; border-radius: 10px; padding: 1.2rem;
  color: #8b8d98; }
`;

/** Render the dashboard index for a set of report entries. Pure. */
export function renderIndex(entries: ReportEntry[], dir: string): string {
  let body: string;
  if (entries.length === 0) {
    body = `<div class="empty">No PRISM reports found in <code>${escapeHtml(dir)}</code>.
Generate one with <code>prism analyze &lt;target&gt; -o json -f ${escapeHtml(dir)}/report.json</code>.</div>`;
  } else {
    const rows = entries
      .map((e) => {
        const r = e.report;
        const ai = r.aiTriage
          ? `${r.aiTriage.summary.real} real · ${r.aiTriage.summary.falsePositive} fp · ${r.aiTriage.summary.uncertain} unc`
          : '—';
        const date = r.completedAt ? new Date(r.completedAt).toLocaleString() : '—';
        return `<tr>
<td><a href="/report?f=${encodeURIComponent(e.file)}">${escapeHtml(r.projectName)}</a></td>
<td class="score" style="color:${scoreColor(r.overallScore)}">${r.overallScore}/10</td>
<td>${r.findings.length}</td>
<td class="muted">${escapeHtml(ai)}</td>
<td class="muted">${escapeHtml(date)}</td>
<td class="muted">${escapeHtml(e.file)}</td>
</tr>`;
      })
      .join('\n');
    body = `<table>
<thead><tr><th>Project</th><th>Score</th><th>Findings</th><th>AI triage</th><th>Date</th><th>File</th></tr></thead>
<tbody>${rows}</tbody>
</table>`;
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PRISM Dashboard</title>
<style>${INDEX_STYLE}</style>
</head>
<body>
<div class="wrap">
<h1>🔍 PRISM Dashboard</h1>
<p class="sub">${entries.length} report${entries.length === 1 ? '' : 's'} in <code>${escapeHtml(dir)}</code> · @latenciatech/prism</p>
${body}
</div>
</body>
</html>
`;
}

/**
 * Create the dashboard HTTP server over a directory of saved JSON reports.
 * Routes: `/` (index), `/report?f=<file>` (full HTML render). The file param
 * must be a plain basename of an actual report in the directory — anything
 * else is a 404, so the server can never read outside its directory.
 * The caller binds it (always to 127.0.0.1 — this is a local tool; PRISM
 * itself flags services exposed on all interfaces).
 */
/**
 * True only for a Host header pointing at the local loopback (with optional
 * port). Blocks DNS-rebinding: a remote page that resolves its own hostname to
 * 127.0.0.1 would otherwise reach this server and read report contents.
 */
export function isLocalHost(host: string | undefined): boolean {
  if (!host) return false;
  const hostname = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0];
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

export function createDashboardServer(dir: string): Server {
  return createServer(async (req, res) => {
    if (!isLocalHost(req.headers.host)) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('forbidden');
      return;
    }
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (url.pathname === '/') {
        const entries = await loadReports(dir);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(renderIndex(entries, dir));
        return;
      }
      if (url.pathname === '/report') {
        const f = url.searchParams.get('f') ?? '';
        const entries = await loadReports(dir);
        const entry = basename(f) === f ? entries.find((e) => e.file === f) : undefined;
        if (!entry) {
          res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('report not found');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(formatHtmlReport(entry.report));
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('not found');
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`dashboard error: ${err instanceof Error ? err.message : 'unknown'}`);
    }
  });
}

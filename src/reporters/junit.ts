import type { AuditReport, Finding } from '../core/types.js';
import { writeReportFile } from './write.js';

/** Escape text for safe interpolation into XML (content and attributes). */
export function escapeXml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function testcase(f: Finding): string {
  const name = escapeXml(`${f.id}: ${f.title}`);
  const cls = escapeXml(f.category);
  const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : 'project-level';
  const msg = escapeXml(`[${f.severity}] ${f.title} (${where})`);
  const body = escapeXml(`${f.description}${f.suggestion ? `\n\nSuggestion: ${f.suggestion}` : ''}`);
  return [
    `    <testcase name="${name}" classname="prism.${cls}">`,
    `      <failure message="${msg}" type="${escapeXml(f.severity)}">${body}</failure>`,
    '    </testcase>',
  ].join('\n');
}

/**
 * Render an audit report as a JUnit XML document: one <testsuite> per category,
 * one failing <testcase> per finding. CI systems (GitHub Actions, GitLab) render
 * this natively, so findings show up as failed tests. A clean category emits an
 * empty suite (0 tests) rather than a spurious passing case.
 */
export function formatJunitReport(report: AuditReport): string {
  const totalFailures = report.findings.length;
  const suites = report.categories.map((cat) => {
    const cases = cat.findings.map(testcase).join('\n');
    const open = `  <testsuite name="${escapeXml(cat.category)}" tests="${cat.findings.length}" failures="${cat.findings.length}">`;
    return cat.findings.length > 0 ? `${open}\n${cases}\n  </testsuite>` : `${open}</testsuite>`;
  });
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="PRISM ${escapeXml(report.projectName)}" tests="${totalFailures}" failures="${totalFailures}">`,
    ...suites,
    '</testsuites>',
    '',
  ].join('\n');
}

export async function writeJunitReport(report: AuditReport, outputPath: string): Promise<void> {
  await writeReportFile(outputPath, formatJunitReport(report));
}

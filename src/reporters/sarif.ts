import type { AuditReport, Finding, Severity } from '../core/types.js';
import { writeReportFile } from './write.js';

/** SARIF result levels; PRISM severities map onto the three SARIF levels. */
type SarifLevel = 'error' | 'warning' | 'note';

function levelFor(severity: Severity): SarifLevel {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

/** SARIF security-severity is a 0.0–10.0 string; GitHub uses it to rank alerts. */
function securitySeverity(severity: Severity): string {
  return { critical: '9.5', high: '8.0', medium: '5.0', low: '3.0', info: '1.0' }[severity];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: { category: string; 'security-severity': string; tags: string[] };
}

function buildResult(f: Finding): unknown {
  const location = f.file
    ? [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file },
            ...(f.line !== undefined ? { region: { startLine: f.line } } : {}),
          },
        },
      ]
    : [];
  return {
    ruleId: f.id,
    level: levelFor(f.severity),
    message: { text: f.suggestion ? `${f.description} — ${f.suggestion}` : f.description },
    ...(location.length ? { locations: location } : {}),
    // Stable-ish fingerprint so Code Scanning can track an alert across lines.
    partialFingerprints: { prismFinding: `${f.id}:${f.file ?? ''}:${f.instance ?? 0}` },
  };
}

/**
 * Render an audit report as a SARIF 2.1.0 document. SARIF is the standard
 * static-analysis interchange format; emitting it lets PRISM feed GitHub Code
 * Scanning (inline PR annotations), VS Code, and other tooling directly. Rules
 * are deduplicated (one per finding id); results reference them by ruleId.
 */
export function formatSarifReport(report: AuditReport): string {
  const rulesById = new Map<string, SarifRule>();
  for (const f of report.findings) {
    if (!rulesById.has(f.id)) {
      rulesById.set(f.id, {
        id: f.id,
        name: f.id,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        properties: {
          category: f.category,
          'security-severity': securitySeverity(f.severity),
          tags: [f.category, f.severity],
        },
      });
    }
  }

  const doc = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PRISM',
            informationUri: 'https://github.com/picaro10/prism',
            version: report.prismVersion,
            rules: [...rulesById.values()],
          },
        },
        results: report.findings.map(buildResult),
      },
    ],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

export async function writeSarifReport(report: AuditReport, outputPath: string): Promise<void> {
  await writeReportFile(outputPath, formatSarifReport(report));
}

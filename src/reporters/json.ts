import type { AuditReport } from '../core/types.js';
import { writeReportFile } from './write.js';

/** Write the audit report as a JSON file (creates parent directories). */
export async function writeJsonReport(report: AuditReport, outputPath: string): Promise<void> {
  await writeReportFile(outputPath, JSON.stringify(report, null, 2));
}

/**
 * Returns the report as a formatted JSON string.
 */
export function formatJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

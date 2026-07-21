import { writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

/**
 * Write report text to a file, creating parent directories if needed — a
 * missing directory must not discard a report that may include paid AI passes.
 */
export async function writeReportFile(outputPath: string, content: string): Promise<void> {
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, content, 'utf-8');
}

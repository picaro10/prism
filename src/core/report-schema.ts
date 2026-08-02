import { z } from 'zod';
import type { AuditReport } from './types.js';

/**
 * Deep shape validation for saved reports — every entry point that accepts a
 * report file (triage, diff, finding get, dashboard) funnels through here.
 * The old check looked at four top-level properties, so a structurally
 * broken report (finding without severity, category without findings array)
 * crashed later in a renderer instead of failing fast at the boundary.
 *
 * Deliberately tolerant of reports from older PRISM versions: unknown extra
 * keys pass through, and everything added after 1.0 is optional.
 */

const severitySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

const findingSchema = z
  .object({
    id: z.string().min(1),
    category: z.string().min(1),
    severity: severitySchema,
    title: z.string(),
    description: z.string(),
    file: z.string().optional(),
    line: z.number().optional(),
    suggestion: z.string().optional(),
    fingerprint: z.string().optional(),
    meta: z.record(z.string(), z.unknown()).optional(),
  })
  .loose();

const categorySchema = z
  .object({
    category: z.string().min(1),
    score: z.number(),
    maxScore: z.literal(10).optional(),
    findings: z.array(findingSchema),
    summary: z.string(),
    applicable: z.boolean().optional(),
  })
  .loose();

const reportSchema = z
  .object({
    projectName: z.string().min(1),
    projectPath: z.string().min(1),
    overallScore: z.number(),
    categories: z.array(categorySchema),
    findings: z.array(findingSchema),
    prismVersion: z.string().optional(),
    startedAt: z.string().optional(),
    completedAt: z.string().optional(),
    durationMs: z.number().optional(),
  })
  .loose();

/** Validate parsed JSON as a PRISM report. Returns the report or null. */
export function parseReport(value: unknown): AuditReport | null {
  return reportSchema.safeParse(value).success ? (value as AuditReport) : null;
}

/** Like parseReport, but returns human-readable reasons on failure. */
export function parseReportDetailed(value: unknown): { report: AuditReport } | { errors: string[] } {
  const result = reportSchema.safeParse(value);
  if (result.success) return { report: value as AuditReport };
  const errors = result.error.issues.slice(0, 5).map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);
  return { errors };
}

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

// The HTML and CLI renderers dereference projectMeta unconditionally
// (m.stack.primary, m.frameworks.length, …) and every PRISM since v1.0.0 has
// written it — so it is REQUIRED, with exactly the fields the renderers touch.
const projectMetaSchema = z
  .object({
    stack: z
      .object({
        primary: z.string(),
        secondary: z.array(z.string()),
        runtime: z.string().optional(),
      })
      .loose(),
    totalFiles: z.number(),
    hasGit: z.boolean(),
    hasDocker: z.boolean(),
    hasCi: z.boolean(),
    packageManager: z.string().optional(),
    frameworks: z.array(z.string()),
  })
  .loose();

// AI sections are optional (only present after --ai / triage), but when
// present they must hold what the renderers index them by: findingKey.
const verdictSchema = z.object({ findingKey: z.string() }).loose();
const aiTriageSchema = z
  .object({
    verdicts: z.array(verdictSchema),
    summary: z.object({}).loose(),
  })
  .loose();
const remediationSchema = z.object({ findingKey: z.string(), fix: z.string() }).loose();
const suppressedFindingSchema = z.object({ finding: findingSchema, reason: z.string() }).loose();

const reportSchema = z
  .object({
    projectName: z.string().min(1),
    projectPath: z.string().min(1),
    overallScore: z.number(),
    categories: z.array(categorySchema),
    findings: z.array(findingSchema),
    projectMeta: projectMetaSchema,
    aiTriage: aiTriageSchema.optional(),
    aiRemediation: z.array(remediationSchema).optional(),
    suppressed: z.array(suppressedFindingSchema).optional(),
    suppressionWarnings: z.array(z.string()).optional(),
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

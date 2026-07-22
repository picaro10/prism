import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import { ANALYZER_CATEGORIES } from './engine.js';
import type { AnalysisCategory, Severity, Suppression } from './types.js';

/**
 * Persistent configuration — `prism.config.json` (or `.prismrc.json`) at the
 * analyzed project's root. Everything here mirrors a CLI flag; an explicit CLI
 * flag always beats the file, the file beats the built-in default.
 *
 * The schema is strict: unknown keys are an error, so a typo can't silently
 * disable a gate (same philosophy as the `--only` category validation).
 */

export const DEFAULT_MIN_SCORE = 6;

export const CONFIG_FILENAMES = ['prism.config.json', '.prismrc.json'] as const;

const categorySchema = z.enum(ANALYZER_CATEGORIES as unknown as [AnalysisCategory, ...AnalysisCategory[]]);
const severitySchema = z.enum(['critical', 'high', 'medium', 'low', 'info'] as const);

const suppressionSchema = z
  .object({
    rule: z.string().min(1, 'rule must not be empty'),
    file: z.string().min(1).optional(),
    reason: z.string().min(1, 'a suppression requires a non-empty reason — that is the justified part'),
    expires: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'expires must be a YYYY-MM-DD date')
      .refine((d) => !Number.isNaN(new Date(`${d}T00:00:00Z`).getTime()), 'expires is not a real date')
      .optional(),
  })
  .strict();

const fileConfigSchema = z
  .object({
    minScore: z.number().min(0).max(10).optional(),
    categories: z.array(categorySchema).min(1).optional(),
    failOn: severitySchema.optional(),
    maxCritical: z.number().int().min(0).optional(),
    maxHigh: z.number().int().min(0).optional(),
    baseline: z.string().min(1).optional(),
    verbose: z.boolean().optional(),
    output: z
      .object({
        format: z.enum(['cli', 'json', 'html']).optional(),
        file: z.string().min(1).optional(),
        junit: z.string().min(1).optional(),
        sarif: z.string().min(1).optional(),
      })
      .strict()
      .optional(),
    ai: z
      .object({
        enabled: z.boolean().optional(),
        provider: z.enum(['anthropic', 'openrouter']).optional(),
        model: z.string().min(1).optional(),
        verify: z.boolean().optional(),
        remediate: z.boolean().optional(),
        summary: z.boolean().optional(),
        concurrency: z.number().int().min(1).optional(),
        vote: z.array(z.string().min(1)).min(1).optional(),
      })
      .strict()
      .optional(),
    suppressions: z.array(suppressionSchema).optional(),
  })
  .strict();

export type PrismFileConfig = z.infer<typeof fileConfigSchema>;

/**
 * Load the config file for a project directory. Discovery order:
 * explicit path (error if missing) → prism.config.json → .prismrc.json.
 * Returns null when nothing is found; throws with a descriptive message on
 * malformed JSON or schema violations.
 */
export function loadConfigFile(dir: string, explicitPath?: string): { config: PrismFileConfig; path: string } | null {
  let path: string | undefined;
  if (explicitPath) {
    path = resolve(explicitPath);
    if (!existsSync(path)) throw new Error(`Config file not found: ${path}`);
  } else {
    path = CONFIG_FILENAMES.map((name) => join(dir, name)).find((p) => existsSync(p));
    if (!path) return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    throw new Error(`Config file is not valid JSON: ${path}`);
  }

  const result = fileConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  · ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n');
    throw new Error(`Invalid config in ${path}:\n${issues}`);
  }
  return { config: result.data, path };
}

/** The flat, fully-resolved option set the analyze command runs with. */
export interface EffectiveOptions {
  minScore: number;
  categories?: AnalysisCategory[];
  failOn?: Severity;
  maxCritical?: number;
  maxHigh?: number;
  baseline?: string;
  verbose: boolean;
  output: 'cli' | 'json' | 'html';
  outputFile?: string;
  junit?: string;
  sarif?: string;
  ai: boolean;
  aiProvider?: 'anthropic' | 'openrouter';
  aiModel?: string;
  aiVerify: boolean;
  aiSummary: boolean;
  aiRemediate: boolean;
  aiConcurrency?: number;
  aiVoteModels?: string[];
  suppressions: Suppression[];
}

/** Raw commander option values for the analyze command (subset we merge). */
export type CliOptionValues = Record<string, string | boolean | undefined>;

function parseList(value: string): string[] {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Merge precedence: explicit CLI flag > config file > built-in default.
 * `isCliSet(name)` reports whether the user actually passed the flag (as
 * opposed to commander filling in a default) — wire it to
 * `command.getOptionValueSource(name) === 'cli'`.
 */
export function resolveEffectiveOptions(
  file: PrismFileConfig | null,
  cli: CliOptionValues,
  isCliSet: (name: string) => boolean,
): EffectiveOptions {
  const pick = <T>(name: string, cliValue: T | undefined, fileValue: T | undefined, fallback: T): T => {
    if (isCliSet(name) && cliValue !== undefined) return cliValue;
    if (fileValue !== undefined) return fileValue;
    return fallback;
  };
  const pickOpt = <T>(name: string, cliValue: T | undefined, fileValue: T | undefined): T | undefined => {
    if (isCliSet(name) && cliValue !== undefined) return cliValue;
    return fileValue;
  };

  const cliCategories =
    typeof cli.only === 'string' && cli.only ? (parseList(cli.only) as AnalysisCategory[]) : undefined;
  const cliVote = typeof cli.aiVote === 'string' && cli.aiVote ? parseList(cli.aiVote) : undefined;

  return {
    minScore: pick(
      'minScore',
      cli.minScore !== undefined ? Number(String(cli.minScore)) : undefined,
      file?.minScore,
      DEFAULT_MIN_SCORE,
    ),
    categories: pickOpt('only', cliCategories, file?.categories),
    failOn: pickOpt('failOn', cli.failOn as Severity | undefined, file?.failOn),
    maxCritical: pickOpt(
      'maxCritical',
      cli.maxCritical !== undefined ? Number(String(cli.maxCritical)) : undefined,
      file?.maxCritical,
    ),
    maxHigh: pickOpt('maxHigh', cli.maxHigh !== undefined ? Number(String(cli.maxHigh)) : undefined, file?.maxHigh),
    baseline: pickOpt('baseline', cli.baseline as string | undefined, file?.baseline),
    verbose: pick('verbose', Boolean(cli.verbose), file?.verbose, false),
    output: pick('output', cli.output as EffectiveOptions['output'] | undefined, file?.output?.format, 'cli'),
    outputFile: pickOpt('file', cli.file as string | undefined, file?.output?.file),
    junit: pickOpt('junit', cli.junit as string | undefined, file?.output?.junit),
    sarif: pickOpt('sarif', cli.sarif as string | undefined, file?.output?.sarif),
    ai: pick('ai', Boolean(cli.ai), file?.ai?.enabled, false),
    aiProvider: pickOpt('aiProvider', cli.aiProvider as EffectiveOptions['aiProvider'], file?.ai?.provider),
    aiModel: pickOpt('aiModel', cli.aiModel as string | undefined, file?.ai?.model),
    aiVerify: pick('aiVerify', cli.aiVerify as boolean | undefined, file?.ai?.verify, true),
    aiSummary: pick('aiSummary', cli.aiSummary as boolean | undefined, file?.ai?.summary, true),
    aiRemediate: pick('aiRemediate', cli.aiRemediate as boolean | undefined, file?.ai?.remediate, true),
    aiConcurrency: pickOpt(
      'aiConcurrency',
      cli.aiConcurrency !== undefined ? Number(String(cli.aiConcurrency)) : undefined,
      file?.ai?.concurrency,
    ),
    aiVoteModels: pickOpt('aiVote', cliVote, file?.ai?.vote),
    suppressions: file?.suppressions ?? [],
  };
}

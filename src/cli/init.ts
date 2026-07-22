import { ANALYZER_CATEGORIES } from '../core/engine.js';
import type { PrismFileConfig } from '../core/config-file.js';
import type { AnalysisCategory, Severity } from '../core/types.js';

/**
 * `prism init` — the interactive part of the config file. The wizard asks the
 * handful of decisions worth making once, writes prism.config.json, and from
 * then on `prism analyze .` needs no flags. Pure logic here; the CLI command
 * wires it to readline so scripted answers can drive it in tests.
 */

/** Ask a question with a default; returns the raw (possibly empty) answer. */
export type Ask = (question: string, def: string) => Promise<string>;

export function defaultFileConfig(): PrismFileConfig {
  return {
    minScore: 6,
    failOn: 'critical',
    output: { format: 'cli' },
    suppressions: [],
  };
}

export function renderConfigJson(config: PrismFileConfig): string {
  return `${JSON.stringify(config, null, 2)}\n`;
}

async function askUntilValid(ask: Ask, question: string, def: string, valid: (a: string) => boolean): Promise<string> {
  // Bounded so a scripted/broken stdin can't loop forever.
  for (let i = 0; i < 5; i++) {
    const answer = (await ask(question, def)).trim() || def;
    if (valid(answer)) return answer;
  }
  return def;
}

export async function buildConfigViaWizard(ask: Ask): Promise<PrismFileConfig> {
  const config: PrismFileConfig = { suppressions: [] };

  const minScore = await askUntilValid(ask, 'Minimum overall score to pass (0-10)', '6', (a) => {
    const n = Number(a);
    return Number.isFinite(n) && n >= 0 && n <= 10;
  });
  config.minScore = Number(minScore);

  const failOn = await askUntilValid(
    ask,
    'Fail when any finding is at or above severity (critical/high/medium/low/none)',
    'critical',
    (a) => ['critical', 'high', 'medium', 'low', 'none'].includes(a.toLowerCase()),
  );
  if (failOn.toLowerCase() !== 'none') config.failOn = failOn.toLowerCase() as Severity;

  const categories = await askUntilValid(
    ask,
    `Analyzers to run (all, or comma-separated from: ${ANALYZER_CATEGORIES.join(', ')})`,
    'all',
    (a) =>
      a.toLowerCase() === 'all' ||
      a
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
        .every((c) => (ANALYZER_CATEGORIES as readonly string[]).includes(c)),
  );
  if (categories.toLowerCase() !== 'all') {
    config.categories = categories
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean) as AnalysisCategory[];
  }

  const provider = await askUntilValid(
    ask,
    'AI triage provider (none/anthropic/openrouter) — needs an API key at run time',
    'none',
    (a) => ['none', 'anthropic', 'openrouter'].includes(a.toLowerCase()),
  );
  if (provider.toLowerCase() !== 'none') {
    config.ai = { enabled: true, provider: provider.toLowerCase() as 'anthropic' | 'openrouter' };
    const model = (await ask('AI model (empty = provider default)', '')).trim();
    if (model) config.ai.model = model;
  }

  const format = await askUntilValid(ask, 'Default output format (cli/json/html)', 'cli', (a) =>
    ['cli', 'json', 'html'].includes(a.toLowerCase()),
  );
  config.output = { format: format.toLowerCase() as 'cli' | 'json' | 'html' };
  if (config.output.format !== 'cli') {
    const def = `reports/prism-report.${config.output.format}`;
    const file = (await ask('Output file path', def)).trim() || def;
    config.output.file = file;
  }

  return config;
}

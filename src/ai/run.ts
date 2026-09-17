import type { AuditReport, FileReader, PrismConfig } from '../core/types.js';
import type { LLMClient } from './types.js';
import type { VerdictCache } from './cache.js';
import { runTriage } from './triage.js';
import { runRemediation } from './remediate.js';
import { runSummary } from './summarize.js';

type AiConfig = Pick<
  PrismConfig,
  | 'aiModel'
  | 'aiProvider'
  | 'aiVerify'
  | 'aiSummary'
  | 'aiRemediate'
  | 'aiConcurrency'
  | 'aiVoteModels'
  | 'aiDryRun'
  | 'aiCache'
>;

/**
 * Resolve an LLM client and run the AI passes (triage + optional remediation
 * and summary), mutating `report.aiTriage` / `report.aiRemediation` /
 * `report.aiSummary`. Shared by the engine's `--ai` path and the standalone
 * `triage` command. Any failure is swallowed (reported via onProgress) so the
 * static report always survives.
 *
 * `cacheRoot` is the project the verdicts belong to; when given (and
 * `aiCache` is not false, and this is not a dry run) verdicts and fixes are
 * reused from / stored in the operator's cache for that project.
 */
export async function applyAiTriage(
  report: AuditReport,
  readFile: FileReader,
  config: AiConfig,
  onProgress?: (message: string) => void,
  injectedClient?: LLMClient,
  cacheRoot?: string,
): Promise<void> {
  try {
    let cache: VerdictCache | undefined;
    if (cacheRoot && config.aiCache !== false && !config.aiDryRun) {
      const { VerdictCache: Cache } = await import('./cache.js');
      cache = Cache.forProject(cacheRoot);
    }

    let client = injectedClient;
    let verifiers: LLMClient[] | undefined;
    if (!client && config.aiDryRun) {
      const { DryRunLLMClient } = await import('./dry-run-client.js');
      client = new DryRunLLMClient();
    }
    if (!client) {
      const provider = config.aiProvider ?? (process.env.ANTHROPIC_API_KEY ? 'anthropic' : 'openrouter');
      const makeClient =
        provider === 'openrouter'
          ? await import('./openrouter-client.js').then((m) => (model?: string) => new m.OpenRouterLLMClient(model))
          : await import('./client.js').then((m) => (model?: string) => new m.AnthropicLLMClient(model));
      client = makeClient(config.aiModel);
      if (config.aiVoteModels?.length) {
        verifiers = config.aiVoteModels.map((model) => makeClient(model));
      }
    }

    onProgress?.('Running AI triage...');
    report.aiTriage = await runTriage(report, readFile, client, {
      verify: config.aiVerify,
      concurrency: config.aiConcurrency,
      verifiers,
      cache,
    });
    const cachedNote = report.aiTriage.summary.cached ? ` (${report.aiTriage.summary.cached} from cache)` : '';
    onProgress?.(`AI triage complete${cachedNote}`);

    if (config.aiRemediate !== false) {
      onProgress?.('Proposing fixes for confirmed findings...');
      report.aiRemediation = await runRemediation(report, readFile, client, {
        concurrency: config.aiConcurrency,
        cache,
      });
    }

    if (config.aiSummary !== false) {
      onProgress?.('Writing AI executive summary...');
      report.aiSummary = await runSummary(report, client);
    }
  } catch (err) {
    onProgress?.(`AI triage failed: ${err instanceof Error ? err.message : 'unknown error'}`);
  }
}

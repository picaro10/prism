import type { AuditReport, FileReader, PrismConfig } from '../core/types.js';
import type { LLMClient } from './types.js';
import { runTriage } from './triage.js';
import { runRemediation } from './remediate.js';
import { runSummary } from './summarize.js';

type AiConfig = Pick<
  PrismConfig,
  'aiModel' | 'aiProvider' | 'aiVerify' | 'aiSummary' | 'aiRemediate' | 'aiConcurrency' | 'aiVoteModels' | 'aiDryRun'
>;

/**
 * Resolve an LLM client and run the AI passes (triage + optional remediation
 * and summary), mutating `report.aiTriage` / `report.aiRemediation` /
 * `report.aiSummary`. Shared by the engine's `--ai` path and the standalone
 * `triage` command. Any failure is swallowed (reported via onProgress) so the
 * static report always survives.
 */
export async function applyAiTriage(
  report: AuditReport,
  readFile: FileReader,
  config: AiConfig,
  onProgress?: (message: string) => void,
  injectedClient?: LLMClient,
): Promise<void> {
  try {
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
    });
    onProgress?.('AI triage complete');

    if (config.aiRemediate !== false) {
      onProgress?.('Proposing fixes for confirmed findings...');
      report.aiRemediation = await runRemediation(report, readFile, client, {
        concurrency: config.aiConcurrency,
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

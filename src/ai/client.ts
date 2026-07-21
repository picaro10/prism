import Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import type { LLMClient, TriageUnit, ProjectContext, Verdict, Remediation } from './types.js';
import {
  buildSystemPrompt,
  buildVerificationSystemPrompt,
  buildRemediationSystemPrompt,
  buildSummarySystemPrompt,
  buildProjectContextBlock,
  buildUserContent,
} from './prompt.js';

const VerdictSchema = z.object({
  findingKey: z.string(),
  classification: z.enum(['real', 'false-positive', 'uncertain']),
  confidence: z.number(),
  reasoning: z.string(),
});
const VerdictArraySchema = z.object({ verdicts: z.array(VerdictSchema) });

const RemediationSchema = z.object({
  findingKey: z.string(),
  fix: z.string(),
  effort: z.enum(['low', 'medium', 'high']),
});
const RemediationArraySchema = z.object({ remediations: z.array(RemediationSchema) });

export class AnthropicLLMClient implements LLMClient {
  private client: Anthropic;
  private model: string;

  constructor(model = 'claude-opus-4-8') {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error('AI triage requires an ANTHROPIC_API_KEY environment variable. Set it, or run without --ai.');
    }
    this.client = new Anthropic();
    this.model = model;
  }

  triage(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]> {
    return this.call(buildSystemPrompt(), unit, projectContext);
  }

  verify(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]> {
    return this.call(buildVerificationSystemPrompt(), unit, projectContext);
  }

  async remediate(unit: TriageUnit, projectContext: ProjectContext): Promise<Remediation[]> {
    try {
      const response = await this.client.messages.parse({
        model: this.model,
        max_tokens: 4096,
        thinking: { type: 'adaptive' },
        output_config: { effort: 'high', format: zodOutputFormat(RemediationArraySchema) },
        system: this.systemBlocks(buildRemediationSystemPrompt(), projectContext),
        messages: [{ role: 'user', content: buildUserContent(unit, 'Findings to fix:') }],
      });
      return response.parsed_output?.remediations ?? [];
    } catch (err) {
      this.rethrow(err);
    }
  }

  async summarize(digest: string, projectContext: ProjectContext): Promise<string> {
    try {
      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 1500,
        thinking: { type: 'adaptive' },
        output_config: { effort: 'high' },
        system: this.systemBlocks(buildSummarySystemPrompt(), projectContext),
        messages: [{ role: 'user', content: digest }],
      });
      return response.content
        .flatMap((b) => (b.type === 'text' ? [b.text] : []))
        .join('\n')
        .trim();
    } catch (err) {
      this.rethrow(err);
    }
  }

  private async call(systemText: string, unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]> {
    try {
      const response = await this.client.messages.parse({
        model: this.model,
        max_tokens: 4096,
        thinking: { type: 'adaptive' },
        output_config: { effort: 'high', format: zodOutputFormat(VerdictArraySchema) },
        system: this.systemBlocks(systemText, projectContext),
        messages: [{ role: 'user', content: buildUserContent(unit) }],
      });
      return response.parsed_output?.verdicts ?? [];
    } catch (err) {
      this.rethrow(err);
    }
  }

  /** System prompt + cacheable project-context block. */
  private systemBlocks(text: string, projectContext: ProjectContext): Anthropic.TextBlockParam[] {
    return [
      { type: 'text', text },
      {
        type: 'text',
        text: buildProjectContextBlock(projectContext),
        cache_control: { type: 'ephemeral' },
      },
    ];
  }

  /** Map SDK errors to the typed messages the CLI surfaces. */
  private rethrow(err: unknown): never {
    if (err instanceof Anthropic.AuthenticationError) {
      throw new Error('AI triage failed: invalid or unauthorized ANTHROPIC_API_KEY.');
    }
    if (err instanceof Anthropic.RateLimitError) {
      throw new Error('AI triage failed: rate limited by the Anthropic API — try again later.');
    }
    if (err instanceof Anthropic.APIError) {
      throw new Error(`AI triage failed: Anthropic API error (${err.status ?? '?'}): ${err.message}`);
    }
    throw err;
  }
}

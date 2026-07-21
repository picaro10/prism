import { z } from 'zod';
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

// Tolerant: a cheap model omitting/inventing the effort value must not cost
// us the fix text — coerce to 'medium' instead.
const RemediationSchema = z.object({
  findingKey: z.string(),
  fix: z.string(),
  effort: z.enum(['low', 'medium', 'high']).catch('medium'),
});

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

// OpenRouter is OpenAI-compatible and does not expose Anthropic structured
// outputs, so we ask for a JSON object and parse/validate it ourselves.
const VERDICT_JSON_INSTRUCTION = [
  'Return ONLY a JSON object, no prose, of this exact shape:',
  '{"verdicts":[{"findingKey":string,"classification":"real"|"false-positive"|"uncertain","confidence":number,"reasoning":string}]}',
  'Include exactly one verdict per finding, echoing back its findingKey EXACTLY as given,',
  "including any trailing '|' characters. confidence is 0.0–1.0.",
].join('\n');

const REMEDIATION_JSON_INSTRUCTION = [
  'Return ONLY a JSON object, no prose, of this exact shape:',
  '{"remediations":[{"findingKey":string,"fix":string,"effort":"low"|"medium"|"high"}]}',
  'Include exactly one remediation per finding, echoing back its findingKey EXACTLY as given,',
  "including any trailing '|' characters. effort must be its own field, not part of the fix text.",
].join('\n');

/** Strip an optional code fence and JSON.parse; null on failure. */
function parseJsonBlock(content: string): unknown {
  let text = content.trim();
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) text = fence[1].trim();
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Pull `field` out of the parsed JSON and validate each item individually —
 * one malformed item must not discard the whole batch (seen in production:
 * a single missing `effort` field used to drop every fix in the response).
 */
function parseItems<T>(content: string, field: string, schema: z.ZodType<T>): T[] {
  const obj = parseJsonBlock(content);
  const arr = obj && typeof obj === 'object' ? (obj as Record<string, unknown>)[field] : null;
  if (!Array.isArray(arr)) return [];
  const out: T[] = [];
  for (const item of arr) {
    const parsed = schema.safeParse(item);
    if (parsed.success) out.push(parsed.data);
  }
  return out;
}

/**
 * Parse the model's text response into verdicts. Tolerant of code fences and
 * per-item failures; the triage layer synthesizes `uncertain` for unmatched
 * findings.
 */
export function parseVerdicts(content: string): Verdict[] {
  return parseItems(content, 'verdicts', VerdictSchema);
}

/**
 * Parse the model's text response into remediations, salvaging valid items
 * from a partially malformed batch (a missing fix is simply absent — never
 * fabricated).
 */
export function parseRemediations(content: string): Remediation[] {
  return parseItems(content, 'remediations', RemediationSchema);
}

export class OpenRouterLLMClient implements LLMClient {
  private apiKey: string;
  private model: string;

  constructor(model = 'openai/gpt-4.1-mini') {
    const key = process.env.OPENROUTER_API_KEY;
    if (!key) {
      throw new Error(
        'AI triage with OpenRouter requires an OPENROUTER_API_KEY environment variable. Set it, or run without --ai.',
      );
    }
    this.apiKey = key;
    this.model = model;
  }

  async triage(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]> {
    return parseVerdicts(await this.verdictChat(buildSystemPrompt(), unit, projectContext));
  }

  async verify(unit: TriageUnit, projectContext: ProjectContext): Promise<Verdict[]> {
    return parseVerdicts(await this.verdictChat(buildVerificationSystemPrompt(), unit, projectContext));
  }

  async remediate(unit: TriageUnit, projectContext: ProjectContext): Promise<Remediation[]> {
    const system = [
      buildRemediationSystemPrompt(),
      buildProjectContextBlock(projectContext),
      REMEDIATION_JSON_INSTRUCTION,
    ].join('\n\n');
    const content = await this.chat(system, buildUserContent(unit, 'Findings to fix:'), true);
    return parseRemediations(content);
  }

  async summarize(digest: string, projectContext: ProjectContext): Promise<string> {
    const system = `${buildSummarySystemPrompt()}\n\n${buildProjectContextBlock(projectContext)}`;
    return (await this.chat(system, digest, false)).trim();
  }

  private verdictChat(systemBase: string, unit: TriageUnit, projectContext: ProjectContext): Promise<string> {
    const system = [systemBase, buildProjectContextBlock(projectContext), VERDICT_JSON_INSTRUCTION].join('\n\n');
    return this.chat(system, buildUserContent(unit), true);
  }

  /** One chat completion; returns the raw message content. */
  private async chat(system: string, user: string, jsonMode: boolean): Promise<string> {
    const res = await fetch(OPENROUTER_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: this.model,
        ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`AI triage failed: OpenRouter API error ${res.status}: ${body.slice(0, 200)}`);
    }

    const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    return data.choices?.[0]?.message?.content ?? '';
  }
}

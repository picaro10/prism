import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { parseVerdicts, parseRemediations, OpenRouterLLMClient } from '../../src/ai/openrouter-client.js';

describe('parseVerdicts', () => {
  const valid = JSON.stringify({
    verdicts: [{ findingKey: 'A|f|1', classification: 'real', confidence: 0.9, reasoning: 'r' }],
  });

  it('parses a plain JSON object', () => {
    const v = parseVerdicts(valid);
    expect(v).toHaveLength(1);
    expect(v[0].classification).toBe('real');
  });

  it('parses JSON wrapped in a code fence', () => {
    const fenced = ['```json', valid, '```'].join('\n');
    const v = parseVerdicts(fenced);
    expect(v).toHaveLength(1);
    expect(v[0].findingKey).toBe('A|f|1');
  });

  it('returns [] for non-JSON garbage', () => {
    expect(parseVerdicts('sorry, here are the results: none')).toEqual([]);
  });

  it('returns [] for JSON of the wrong shape', () => {
    expect(parseVerdicts(JSON.stringify({ results: [] }))).toEqual([]);
  });

  it('drops an invalid verdict but salvages the valid ones around it', () => {
    const mixed = JSON.stringify({
      verdicts: [
        { findingKey: 'A', classification: 'maybe', confidence: 1, reasoning: 'r' },
        { findingKey: 'B|f|1', classification: 'real', confidence: 0.8, reasoning: 'ok' },
      ],
    });
    const v = parseVerdicts(mixed);
    expect(v).toHaveLength(1);
    expect(v[0].findingKey).toBe('B|f|1');
  });
});

describe('parseRemediations', () => {
  const valid = JSON.stringify({
    remediations: [{ findingKey: 'A|f|1', fix: 'add a USER directive', effort: 'low' }],
  });

  it('parses a plain JSON object', () => {
    const r = parseRemediations(valid);
    expect(r).toHaveLength(1);
    expect(r[0].fix).toMatch(/USER directive/);
  });

  it('parses JSON wrapped in a code fence', () => {
    const fenced = ['```json', valid, '```'].join('\n');
    expect(parseRemediations(fenced)).toHaveLength(1);
  });

  it('returns [] for non-JSON garbage', () => {
    expect(parseRemediations('I suggest you fix it like this:')).toEqual([]);
  });

  it('coerces a missing or invalid effort to medium instead of dropping the fix', () => {
    const loose = JSON.stringify({
      remediations: [
        { findingKey: 'A|f|1', fix: 'f1', effort: 'trivial' },
        { findingKey: 'B|f|2', fix: 'f2' },
      ],
    });
    const r = parseRemediations(loose);
    expect(r).toHaveLength(2);
    expect(r[0].effort).toBe('medium');
    expect(r[1].effort).toBe('medium');
  });

  it('salvages valid remediations around a malformed item', () => {
    const mixed = JSON.stringify({
      remediations: [{ findingKey: 'A|f|1' }, { findingKey: 'B|f|2', fix: 'good fix', effort: 'low' }],
    });
    const r = parseRemediations(mixed);
    expect(r).toHaveLength(1);
    expect(r[0].fix).toBe('good fix');
  });
});

describe('OpenRouterLLMClient', () => {
  it('throws a clear error when OPENROUTER_API_KEY is missing', () => {
    vi.stubEnv('OPENROUTER_API_KEY', '');
    try {
      expect(() => new OpenRouterLLMClient()).toThrow(/OPENROUTER_API_KEY/);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe('OpenRouterLLMClient — HTTP layer (mocked fetch)', () => {
  const unit = {
    file: 'src/a.ts',
    content: 'const x = 1;',
    findings: [
      {
        id: 'SEC-001',
        category: 'security',
        severity: 'high' as const,
        title: 't',
        description: 'd',
        file: 'src/a.ts',
      },
    ],
  };
  const ctx = { projectName: 'demo', stack: 'typescript', overallScore: 7, categorySummaries: [] };

  const chatResponse = (content: unknown): Response =>
    new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(content) } }] }), { status: 200 });

  beforeEach(() => {
    vi.stubEnv('OPENROUTER_API_KEY', 'test-key');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('triage() posts to OpenRouter with auth and a timeout signal, and parses verdicts', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      chatResponse({
        verdicts: [{ findingKey: 'SEC-001|src/a.ts|', classification: 'real', confidence: 0.9, reasoning: 'r' }],
      }),
    );
    const verdicts = await new OpenRouterLLMClient().triage(unit, ctx);
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].classification).toBe('real');

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain('openrouter.ai');
    // The audit flagged a missing timeout — a hung connection blocked audits forever.
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(init.headers).toMatchObject({ Authorization: 'Bearer test-key' });
  });

  it('verify() and remediate() go through the same chat path', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockResolvedValueOnce(
      chatResponse({
        verdicts: [
          { findingKey: 'SEC-001|src/a.ts|', classification: 'false-positive', confidence: 0.7, reasoning: 'r' },
        ],
      }),
    );
    const client = new OpenRouterLLMClient();
    expect(await client.verify(unit, ctx)).toHaveLength(1);
    fetchSpy.mockResolvedValueOnce(
      chatResponse({ remediations: [{ findingKey: 'SEC-001|src/a.ts|', fix: 'do x', effort: 'low' }] }),
    );
    expect(await client.remediate(unit, ctx)).toHaveLength(1);
  });

  it('surfaces HTTP errors with the status code and body excerpt', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('quota exceeded', { status: 429 }));
    await expect(new OpenRouterLLMClient().triage(unit, ctx)).rejects.toThrow(/429.*quota exceeded/);
  });

  it('summarize() returns the trimmed raw text content', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ choices: [{ message: { content: '  An executive summary.  ' } }] }), {
        status: 200,
      }),
    );
    expect(await new OpenRouterLLMClient().summarize('digest', ctx)).toBe('An executive summary.');
  });
});

import { describe, it, expect, vi } from 'vitest';
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

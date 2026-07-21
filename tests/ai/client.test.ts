import { describe, it, expect, vi } from 'vitest';
import { AnthropicLLMClient } from '../../src/ai/client.js';

// Constructing the client without a key must throw a clear error BEFORE any
// network call. This is the only test that touches client.ts; it never makes
// an API request (the constructor throws first), so the suite stays offline.
describe('AnthropicLLMClient', () => {
  it('throws a clear error when ANTHROPIC_API_KEY is missing', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', ''); // empty → falsy → constructor must throw
    try {
      expect(() => new AnthropicLLMClient()).toThrow(/ANTHROPIC_API_KEY/);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

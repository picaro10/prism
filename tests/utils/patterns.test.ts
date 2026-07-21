import { describe, it, expect } from 'vitest';
import { SECRET_PATTERNS } from '../../src/utils/patterns.js';

function pattern(id: string): RegExp {
  const p = SECRET_PATTERNS.find((x) => x.id === id);
  if (!p) throw new Error(`pattern ${id} not found`);
  return p.pattern;
}

describe('SEC-OPENAI boundary guard', () => {
  const re = pattern('SEC-OPENAI');

  it('does not match "sk-" embedded inside a longer identifier', () => {
    // task-/desk-/risk- ... end in "sk-"; a 20+ alnum id after them must NOT flag
    expect(re.test('task-a1b2c3d4e5f6g7h8i9j0abc')).toBe(false);
    expect(re.test('desk-abcdefghij1234567890xyz')).toBe(false);
    expect(re.test('const flaskSessionId = "flask-a1b2c3d4e5f6g7h8i9j0"')).toBe(false);
  });

  it('still matches a real standalone OpenAI-style key', () => {
    expect(re.test('sk-abcdefghij1234567890ABCDEF')).toBe(true);
    expect(re.test('OPENAI_API_KEY=sk-abcdefghij1234567890ABCDEF')).toBe(true);
  });
});

describe('SEC-TELEGRAM boundary guard', () => {
  const re = pattern('SEC-TELEGRAM');

  it('matches a real bot-token shape', () => {
    expect(re.test('123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678')).toBe(true);
  });

  it('does not slice a sub-run out of a longer digit string', () => {
    // 13 digits before ':' — no valid 8-10 digit token boundary ends at ':'
    expect(re.test('9999123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678')).toBe(false);
    // sanity: a short/garbage tail does not match
    expect(re.test('123456789:short')).toBe(false);
  });
});

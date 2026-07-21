import { describe, it, expect } from 'vitest';

describe('good tests', () => {
  it('should validate input', () => {
    expect(1 + 1).toBe(2);
  });

  it('should handle errors', () => {
    expect(() => { throw new Error('fail'); }).toThrow('fail');
  });
});

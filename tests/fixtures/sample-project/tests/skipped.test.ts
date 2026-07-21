import { describe, it, expect } from 'vitest';

describe('skipped tests', () => {
  it('works', () => {
    expect(true).toBe(true);
  });

  // `process.exit(` must NOT count as a skipped test (regression: real FP on orion_new)
  it('references process.exit without being a skipped test', () => {
    const shutdown = () => process.exit(0);
    expect(shutdown).toBeTypeOf('function');
  });

  it.skip('needs fixing later', () => {
    expect(false).toBe(true);
  });

  it.todo('implement this feature');
});

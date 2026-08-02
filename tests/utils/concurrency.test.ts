import { describe, it, expect } from 'vitest';
import { mapWithConcurrency } from '../../src/utils/concurrency.js';

describe('mapWithConcurrency', () => {
  it('returns [] for an empty list', async () => {
    expect(await mapWithConcurrency([], 5, async (x) => x)).toEqual([]);
  });

  it('maps all items and preserves input order', async () => {
    const out = await mapWithConcurrency([1, 2, 3, 4], 2, async (n) => n * 10);
    expect(out).toEqual([10, 20, 30, 40]);
  });

  it('passes the index to the fn', async () => {
    const out = await mapWithConcurrency(['a', 'b', 'c'], 3, async (_v, i) => i);
    expect(out).toEqual([0, 1, 2]);
  });

  it('never exceeds the concurrency limit', async () => {
    let active = 0;
    let maxActive = 0;
    const items = Array.from({ length: 12 }, (_, i) => i);
    await mapWithConcurrency(items, 3, async (n) => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      return n;
    });
    expect(maxActive).toBeLessThanOrEqual(3);
    expect(maxActive).toBeGreaterThan(1); // actually ran in parallel
  });

  it('treats an invalid limit (NaN/0/negative) as sequential instead of ZERO workers', async () => {
    // NaN used to survive Math.max/Math.min and produce zero workers — every
    // result stayed undefined while the caller reported success.
    for (const bad of [Number.NaN, 0, -3, 0.4]) {
      const out = await mapWithConcurrency([1, 2, 3], bad, async (n) => n * 2);
      expect(out).toEqual([2, 4, 6]);
    }
  });
});

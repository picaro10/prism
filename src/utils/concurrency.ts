/**
 * Map over items with bounded concurrency, preserving input order in the result.
 * Runs at most `limit` async functions at a time. A `limit` of 1 is fully sequential.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  // NaN survives both Math.max and Math.min, and Array.from({length: NaN})
  // silently yields ZERO workers — every result stays undefined. Fall back
  // to sequential instead.
  const safeLimit = Number.isFinite(limit) && limit >= 1 ? Math.floor(limit) : 1;
  const workerCount = Math.max(1, Math.min(safeLimit, items.length));

  const worker = async (): Promise<void> => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  };

  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}

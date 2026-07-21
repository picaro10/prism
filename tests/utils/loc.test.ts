import { describe, it, expect } from 'vitest';
import { countLoc, classifyGodFile, computeSizeMetrics } from '../../src/utils/loc.js';

describe('countLoc', () => {
  it('counts an empty string as 1 line', () => {
    expect(countLoc('')).toBe(1);
  });

  it('counts a single line with no trailing newline', () => {
    expect(countLoc('const x = 1;')).toBe(1);
  });

  it('counts N lines', () => {
    expect(countLoc('a\nb\nc')).toBe(3);
  });

  it('counts a trailing newline as a final empty line', () => {
    expect(countLoc('a\nb\n')).toBe(3);
  });
});

describe('classifyGodFile', () => {
  it('returns null for zero lines', () => {
    expect(classifyGodFile(0)).toBeNull();
  });

  it('returns null below the info threshold', () => {
    expect(classifyGodFile(400)).toBeNull();
    expect(classifyGodFile(10)).toBeNull();
  });

  it('returns info above 400', () => {
    expect(classifyGodFile(401)).toBe('info');
    expect(classifyGodFile(600)).toBe('info');
  });

  it('returns low above 600', () => {
    expect(classifyGodFile(601)).toBe('low');
    expect(classifyGodFile(900)).toBe('low');
  });

  it('returns medium above 900', () => {
    expect(classifyGodFile(901)).toBe('medium');
    expect(classifyGodFile(1500)).toBe('medium');
  });

  it('returns high above 1500', () => {
    expect(classifyGodFile(1501)).toBe('high');
    expect(classifyGodFile(99999)).toBe('high');
  });
});

describe('computeSizeMetrics', () => {
  it('handles an empty list', () => {
    const m = computeSizeMetrics([]);
    expect(m).toEqual({ totalLoc: 0, fileCount: 0, median: 0, largest: null, top5Pct: 0 });
  });

  it('handles a single file', () => {
    const m = computeSizeMetrics([{ path: 'a.ts', loc: 100 }]);
    expect(m.totalLoc).toBe(100);
    expect(m.fileCount).toBe(1);
    expect(m.median).toBe(100);
    expect(m.largest).toEqual({ path: 'a.ts', loc: 100 });
    expect(m.top5Pct).toBe(100);
  });

  it('computes the median of an odd-length list', () => {
    const m = computeSizeMetrics([
      { path: 'a', loc: 10 },
      { path: 'b', loc: 30 },
      { path: 'c', loc: 20 },
    ]);
    expect(m.median).toBe(20);
  });

  it('computes the median of an even-length list as the average of the two middle values', () => {
    const m = computeSizeMetrics([
      { path: 'a', loc: 10 },
      { path: 'b', loc: 20 },
      { path: 'c', loc: 30 },
      { path: 'd', loc: 40 },
    ]);
    expect(m.median).toBe(25);
  });

  it('reports the largest file and top-5 concentration', () => {
    const files = [
      { path: 'big', loc: 1000 },
      { path: 'b', loc: 50 },
      { path: 'c', loc: 40 },
      { path: 'd', loc: 30 },
      { path: 'e', loc: 20 },
      { path: 'f', loc: 10 }, // not in top 5
    ];
    const m = computeSizeMetrics(files);
    expect(m.largest).toEqual({ path: 'big', loc: 1000 });
    expect(m.totalLoc).toBe(1150);
    expect(m.top5Pct).toBe(99);
  });
});

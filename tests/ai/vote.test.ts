import { describe, it, expect } from 'vitest';
import { tallyVerdicts } from '../../src/ai/vote.js';
import type { Verdict, Classification } from '../../src/ai/types.js';

function v(classification: Classification, confidence = 0.8, reasoning = 'r', findingKey = 'A|f|1'): Verdict {
  return { findingKey, classification, confidence, reasoning };
}

describe('tallyVerdicts', () => {
  it('passes a single voter through untouched', () => {
    const verdicts = [v('false-positive', 0.9, 'benign charset')];
    const out = tallyVerdicts([verdicts]);
    expect(out).toEqual(verdicts);
    expect(out[0].reasoning).not.toMatch(/panel/);
  });

  it('confirms a false-positive only when the panel is unanimous', () => {
    const out = tallyVerdicts([[v('false-positive')], [v('false-positive')], [v('false-positive')]]);
    expect(out[0].classification).toBe('false-positive');
    expect(out[0].reasoning).toMatch(/\[panel: 0 real · 3 fp · 0 uncertain\]/);
  });

  it('a single dissent blocks the false positive (2 fp / 1 real → uncertain)', () => {
    const out = tallyVerdicts([[v('false-positive')], [v('false-positive')], [v('real')]]);
    expect(out[0].classification).toBe('uncertain');
    expect(out[0].reasoning).toMatch(/did not unanimously confirm/);
    expect(out[0].reasoning).toMatch(/\[panel: 1 real · 2 fp · 0 uncertain\]/);
  });

  it('downgrades to real when the panel out-votes the false positive', () => {
    const out = tallyVerdicts([
      [v('false-positive', 1.0, 'looks fine')],
      [v('real', 0.7, 'port is exposed')],
      [v('real', 0.9, 'still exposed')],
    ]);
    expect(out[0].classification).toBe('real');
    // spokesman is the highest-confidence winning vote; confidence is the winners' mean
    expect(out[0].reasoning).toMatch(/still exposed/);
    expect(out[0].confidence).toBeCloseTo(0.8);
  });

  it('a 1/1/1 split (no fp majority, real ties uncertain) goes to uncertain', () => {
    const out = tallyVerdicts([[v('false-positive')], [v('real')], [v('uncertain', 0.5, 'cannot tell')]]);
    expect(out[0].classification).toBe('uncertain');
    expect(out[0].reasoning).toMatch(/cannot tell/);
  });

  it('a pure fp-vs-real deadlock (2/2) goes to uncertain even with zero uncertain votes', () => {
    const out = tallyVerdicts([[v('false-positive')], [v('false-positive')], [v('real')], [v('real')]]);
    expect(out[0].classification).toBe('uncertain');
    expect(out[0].confidence).toBe(0);
    expect(out[0].reasoning).toMatch(/did not unanimously confirm/);
  });

  it('an abstaining (uncertain) voter blocks the false positive too', () => {
    const out = tallyVerdicts([[v('false-positive')], [v('false-positive')], [v('uncertain', 0.5, 'no answer')]]);
    expect(out[0].classification).toBe('uncertain');
  });

  it('merges each finding independently across voters', () => {
    const voter1 = [v('false-positive', 0.9, 'a', 'A|f|1'), v('false-positive', 0.9, 'b', 'B|g|2')];
    const voter2 = [v('false-positive', 0.8, 'a2', 'A|f|1'), v('real', 0.8, 'b2', 'B|g|2')];
    const voter3 = [v('false-positive', 0.7, 'a3', 'A|f|1'), v('real', 0.7, 'b3', 'B|g|2')];
    const out = tallyVerdicts([voter1, voter2, voter3]);
    expect(out.map((x) => x.classification)).toEqual(['false-positive', 'real']); // unanimous fp · majority real
    expect(out.map((x) => x.findingKey)).toEqual(['A|f|1', 'B|g|2']);
  });

  it('returns [] for an empty panel', () => {
    expect(tallyVerdicts([])).toEqual([]);
  });
});

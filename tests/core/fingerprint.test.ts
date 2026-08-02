import { describe, it, expect } from 'vitest';
import { normalizeLine, computeFingerprint, assignFingerprints } from '../../src/core/fingerprint.js';
import type { Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}

describe('normalizeLine', () => {
  it('trims and collapses whitespace', () => {
    expect(normalizeLine('   const  x   =  1;  ')).toBe('const x = 1;');
  });
});

describe('computeFingerprint', () => {
  it('is stable across line-number changes (same code, different line)', () => {
    const a = computeFingerprint(finding({ id: 'SEC-1', file: 'a.ts', line: 5 }), 'exec(userInput)');
    const b = computeFingerprint(finding({ id: 'SEC-1', file: 'a.ts', line: 40 }), 'exec(userInput)');
    expect(a).toBe(b); // moving the code keeps the identity
  });

  it('is stable across re-indentation (whitespace-only change)', () => {
    const a = computeFingerprint(finding({ id: 'SEC-1', file: 'a.ts', line: 5 }), '  exec(userInput)');
    const b = computeFingerprint(finding({ id: 'SEC-1', file: 'a.ts', line: 5 }), '\t\texec(userInput)');
    expect(a).toBe(b);
  });

  it('differs when the code, rule, or file differs', () => {
    const base = computeFingerprint(finding({ id: 'SEC-1', file: 'a.ts', line: 5 }), 'exec(x)');
    expect(computeFingerprint(finding({ id: 'SEC-1', file: 'a.ts', line: 5 }), 'exec(y)')).not.toBe(base);
    expect(computeFingerprint(finding({ id: 'SEC-2', file: 'a.ts', line: 5 }), 'exec(x)')).not.toBe(base);
    expect(computeFingerprint(finding({ id: 'SEC-1', file: 'b.ts', line: 5 }), 'exec(x)')).not.toBe(base);
  });
});

describe('assignFingerprints', () => {
  it('reads each file once and assigns a fingerprint per finding', async () => {
    const reads: string[] = [];
    const reader = async (p: string) => {
      reads.push(p);
      return 'line1\nexec(userInput)\nline3';
    };
    const findings = [
      finding({ id: 'A', file: 'a.ts', line: 2 }),
      finding({ id: 'B', file: 'a.ts', line: 2 }),
      finding({ id: 'P' }), // project-level, no file
    ];
    await assignFingerprints(findings, reader);
    expect(reads).toEqual(['a.ts']); // one read for the shared file
    expect(findings.every((f) => typeof f.fingerprint === 'string' && f.fingerprint.length === 12)).toBe(true);
    expect(findings[0].fingerprint).not.toBe(findings[1].fingerprint); // different rule id
  });

  it('degrades to a line-less fingerprint on read failure', async () => {
    const findings = [finding({ id: 'A', file: 'gone.ts', line: 2 })];
    await assignFingerprints(findings, async () => {
      throw new Error('ENOENT');
    });
    expect(typeof findings[0].fingerprint).toBe('string');
  });

  it('disambiguates line-less findings sharing id+file (two wildcard deps → two identities)', async () => {
    // Two DEP-002 findings on package.json, no line: before the fix both
    // hashed to id+file only, so the baseline diff conflated them.
    const findings = [
      finding({ id: 'DEP-002', file: 'package.json', title: 'Wildcard version for lodash' }),
      finding({ id: 'DEP-002', file: 'package.json', title: 'Wildcard version for express' }),
    ];
    await assignFingerprints(findings, async () => 'irrelevant');
    expect(findings[0].fingerprint).not.toBe(findings[1].fingerprint);
  });

  it('keeps the first occurrence on the legacy fingerprint (baseline compatibility)', async () => {
    const solo = [finding({ id: 'DEP-002', file: 'package.json' })];
    await assignFingerprints(solo, async () => 'x');
    const pair = [finding({ id: 'DEP-002', file: 'package.json' }), finding({ id: 'DEP-002', file: 'package.json' })];
    await assignFingerprints(pair, async () => 'x');
    expect(pair[0].fingerprint).toBe(solo[0].fingerprint); // old baselines still match
    expect(pair[1].fingerprint).not.toBe(pair[0].fingerprint);
  });

  it('disambiguates identical flagged lines in the same file (duplicated code)', async () => {
    const reader = async () => 'exec(x)\nexec(x)';
    const findings = [finding({ id: 'SEC-1', file: 'a.ts', line: 1 }), finding({ id: 'SEC-1', file: 'a.ts', line: 2 })];
    await assignFingerprints(findings, reader);
    expect(findings[0].fingerprint).not.toBe(findings[1].fingerprint);
  });

  it('assigns ordinals deterministically across runs', async () => {
    const make = () => [
      finding({ id: 'DEP-002', file: 'package.json' }),
      finding({ id: 'DEP-002', file: 'package.json' }),
      finding({ id: 'DEP-002', file: 'package.json' }),
    ];
    const a = make();
    const b = make();
    await assignFingerprints(a, async () => 'x');
    await assignFingerprints(b, async () => 'x');
    expect(a.map((f) => f.fingerprint)).toEqual(b.map((f) => f.fingerprint));
    expect(new Set(a.map((f) => f.fingerprint)).size).toBe(3);
  });
});

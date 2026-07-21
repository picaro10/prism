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
});

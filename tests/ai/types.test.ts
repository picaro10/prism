import { describe, it, expect } from 'vitest';
import { findingKey, assignFindingInstances } from '../../src/ai/types.js';
import type { Finding } from '../../src/core/types.js';

function f(partial: Partial<Finding>): Finding {
  return {
    id: 'SEC-001',
    category: 'security',
    severity: 'high',
    title: 't',
    description: 'd',
    ...partial,
  };
}

describe('findingKey', () => {
  it('combines id, file and line', () => {
    expect(findingKey(f({ id: 'SEC-ENV', file: 'src/a.ts', line: 3 }))).toBe('SEC-ENV|src/a.ts|3');
  });

  it('handles a project-level finding with no file or line', () => {
    expect(findingKey(f({ id: 'TST-001' }))).toBe('TST-001||');
  });

  it('handles a file with no line', () => {
    expect(findingKey(f({ id: 'STR-011', file: 'src/big.ts' }))).toBe('STR-011|src/big.ts|');
  });

  it('appends an instance suffix when one is set', () => {
    expect(findingKey(f({ id: 'DEP-002', file: 'package.json', instance: 2 }))).toBe('DEP-002|package.json|#2');
  });
});

describe('assignFindingInstances', () => {
  it('disambiguates findings that would share a key, leaving unique ones bare', () => {
    const findings = [
      f({ id: 'DEP-002', file: 'package.json', title: 'lodash wildcard' }),
      f({ id: 'DEP-002', file: 'package.json', title: 'express wildcard' }),
      f({ id: 'DEP-002', file: 'package.json', title: 'chalk wildcard' }),
      f({ id: 'SEC-001', file: 'src/a.ts', line: 3 }), // unique — stays bare
    ];
    assignFindingInstances(findings);
    const keys = findings.map(findingKey);
    expect(keys).toEqual([
      'DEP-002|package.json|', // first keeps the bare key
      'DEP-002|package.json|#1',
      'DEP-002|package.json|#2',
      'SEC-001|src/a.ts|3',
    ]);
    expect(new Set(keys).size).toBe(4); // all unique
  });

  it('is idempotent on re-run (safe for a saved report re-triaged)', () => {
    const findings = [f({ id: 'DEP-002', file: 'package.json' }), f({ id: 'DEP-002', file: 'package.json' })];
    assignFindingInstances(findings);
    assignFindingInstances(findings);
    expect(findings.map(findingKey)).toEqual(['DEP-002|package.json|', 'DEP-002|package.json|#1']);
  });
});

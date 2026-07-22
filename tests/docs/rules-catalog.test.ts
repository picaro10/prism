import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = resolve(__dirname, '../..');

/** Every static rule id declared in the analyzers and the secret-pattern table. */
function ruleIdsInSource(): string[] {
  const sources = [
    ...readdirSync(join(ROOT, 'src/analyzers'))
      .filter((f) => f.endsWith('.ts'))
      .map((f) => join(ROOT, 'src/analyzers', f)),
    join(ROOT, 'src/utils/patterns.ts'),
  ];
  const ids = new Set<string>();
  for (const file of sources) {
    const src = readFileSync(file, 'utf-8');
    for (const m of src.matchAll(/id: '([A-Z]{2,4}-[A-Z0-9-]+)'/g)) ids.add(m[1]);
  }
  return [...ids].sort();
}

function catalogContent(): string {
  const dir = join(ROOT, 'docs/rules');
  return readdirSync(dir)
    .filter((f) => f.endsWith('.md'))
    .map((f) => readFileSync(join(dir, f), 'utf-8'))
    .join('\n');
}

describe('rule catalog (docs/rules) stays in sync with the analyzers', () => {
  it('documents every rule id that exists in source', () => {
    const catalog = catalogContent();
    const missing = ruleIdsInSource().filter((id) => !catalog.includes(id));
    // A rule that ships undocumented is a black box — add it to docs/rules/<category>.md.
    expect(missing).toEqual([]);
  });

  it('does not document rule ids that no longer exist (stale docs)', () => {
    const ids = new Set(ruleIdsInSource());
    const catalog = catalogContent();
    const documented = [...new Set([...catalog.matchAll(/`([A-Z]{2,4}-[A-Z0-9-]+)`/g)].map((m) => m[1]))];
    // SEC-AWS-SECRET is documented as REMOVED (its removal is itself a documented decision).
    const stale = documented.filter((id) => !ids.has(id) && id !== 'SEC-AWS-SECRET');
    expect(stale).toEqual([]);
  });

  it('sanity: the extractor sees a healthy number of rules', () => {
    expect(ruleIdsInSource().length).toBeGreaterThan(50);
  });
});

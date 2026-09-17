import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ruleIdsInSource } from '../helpers/rule-ids.js';

const ROOT = resolve(__dirname, '../..');

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

  it('every RULE_METADATA key refers to a rule that exists in source', async () => {
    const { RULE_METADATA } = await import('../../src/core/rule-metadata.js');
    const ids = new Set(ruleIdsInSource());
    const ghosts = Object.keys(RULE_METADATA).filter((id) => !ids.has(id));
    expect(ghosts).toEqual([]);
  });

  it('the CWE/OWASP page documents exactly the RULE_METADATA entries', async () => {
    const { RULE_METADATA } = await import('../../src/core/rule-metadata.js');
    const page = readFileSync(join(ROOT, 'docs/rules/cwe-owasp.md'), 'utf-8');
    const documented = new Set([...page.matchAll(/^\| `([A-Z]{2,4}-[A-Z0-9-]+)`/gm)].map((m) => m[1]));
    const keys = new Set(Object.keys(RULE_METADATA));
    expect([...keys].filter((id) => !documented.has(id))).toEqual([]); // mapped but not documented
    expect([...documented].filter((id) => !keys.has(id))).toEqual([]); // documented but not mapped
  });

  it('sanity: the extractor sees a healthy number of rules, both declaration styles', () => {
    const ids = ruleIdsInSource();
    expect(ids.length).toBeGreaterThan(60);
    expect(ids).toContain('SEC-STRIPE-SK'); // inline `id:` style
    expect(ids).toContain('WFL-001'); // finding(...) helper style
  });
});

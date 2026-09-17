import { describe, it, expect } from 'vitest';
import { parse } from 'yaml';
import { RULE_METADATA, ruleMetadataFor, CONTEXT_TIER, contextTierFor } from '../../src/core/rule-metadata.js';
import { ruleIdsInSource } from '../helpers/rule-ids.js';
import { SEMGREP_RULES_YAML } from '../../src/analyzers/semgrep-rules.js';

describe('RULE_METADATA', () => {
  it('every entry has well-formed CWE and OWASP identifiers', () => {
    for (const [rule, meta] of Object.entries(RULE_METADATA)) {
      expect(rule, rule).toMatch(/^[A-Z]{2,4}-[A-Z0-9-]+$/);
      expect(meta.cwe, rule).toMatch(/^CWE-\d+$/);
      expect(meta.owasp, rule).toMatch(/^A\d{2}:2021$/);
    }
  });

  it('maps the classic security rules', () => {
    expect(RULE_METADATA['SEC-AWS-KEY']).toEqual({ cwe: 'CWE-798', owasp: 'A07:2021' });
    expect(RULE_METADATA['SEC-PASSWORD']).toEqual({ cwe: 'CWE-259', owasp: 'A07:2021' });
    expect(RULE_METADATA['AGT-001']).toEqual({ cwe: 'CWE-78', owasp: 'A03:2021' });
    expect(RULE_METADATA['WFL-001']).toEqual({ cwe: 'CWE-829', owasp: 'A08:2021' });
    expect(RULE_METADATA['DOC-020']).toEqual({ cwe: 'CWE-250', owasp: 'A05:2021' });
    expect(RULE_METADATA['DEP-OSV-CRITICAL']).toEqual({ cwe: 'CWE-1395', owasp: 'A06:2021' });
  });

  it('deliberately leaves quality rules unmapped — no CWE theater', () => {
    for (const id of ['STR-011', 'CON-001', 'TST-001', 'WFL-007', 'DOC-013']) {
      expect(RULE_METADATA[id], id).toBeUndefined();
    }
  });

  it('stays in sync with the embedded semgrep rule pack (SG-* entries mirror the YAML metadata)', () => {
    const pack = parse(SEMGREP_RULES_YAML) as {
      rules: { id: string; metadata?: { cwe?: string; owasp?: string } }[];
    };
    for (const rule of pack.rules) {
      const sgId = `SG-${rule.id.replace(/^prism-/, '').toUpperCase()}`;
      const entry = RULE_METADATA[sgId];
      expect(entry, sgId).toBeDefined();
      expect(entry.cwe, sgId).toBe(rule.metadata?.cwe);
      // The YAML carries the long form ("A03:2021 - Injection"); the map keeps the code.
      expect(rule.metadata?.owasp, sgId).toContain(entry.owasp);
    }
  });

  it('ruleMetadataFor falls back to finding meta for engines that carry their own (semgrep)', () => {
    expect(ruleMetadataFor('SG-SQLI-TAINTED-QUERY', undefined)).toEqual({ cwe: 'CWE-89', owasp: 'A03:2021' });
    expect(ruleMetadataFor('UNKNOWN-RULE', { cwe: 'CWE-777', owasp: 'A01:2021 - Broken Access Control' })).toEqual({
      cwe: 'CWE-777',
      owasp: 'A01:2021',
    });
    expect(ruleMetadataFor('STR-011', undefined)).toBeUndefined();
  });
});

describe('CONTEXT_TIER (how much code the AI triage needs to judge a rule)', () => {
  it('every override names a rule id that exists in source (no tiers for dead rules)', () => {
    const known = new Set(ruleIdsInSource());
    const stale = Object.keys(CONTEXT_TIER).filter((id) => !known.has(id));
    expect(stale).toEqual([]);
  });

  it('every override is one of the three tiers', () => {
    for (const [id, tier] of Object.entries(CONTEXT_TIER)) {
      expect(['none', 'file', 'neighborhood'], id).toContain(tier);
    }
  });

  it('defaults to "file" for a rule without an override (the pre-tier behavior)', () => {
    expect(contextTierFor('UNKNOWN-RULE')).toBe('file');
    expect(contextTierFor('SEC-AWS-KEY')).toBe('file');
  });

  it('project-fact rules need no code: counts, graphs, external advisories, absent files', () => {
    for (const id of [
      'DEP-001',
      'DEP-002',
      'DEP-OSV-HIGH',
      'DEP-AUDIT-CRITICAL',
      'DEP-PY-001',
      'STR-001',
      'STR-011',
      'STR-012',
      'CON-001',
      'CON-002',
      'TST-001',
      'TST-002',
      'SEC-SEMGREP-MISSING',
    ]) {
      expect(contextTierFor(id), id).toBe('none');
    }
  });

  it('line-pattern rules need the file: the verdict can flip on what the line really is', () => {
    for (const id of ['SEC-DB-URL', 'SEC-ENTROPY', 'DOC-021', 'WFL-002', 'TST-011', 'TST-014', 'STR-013', 'AGT-002']) {
      expect(contextTierFor(id), id).toBe('file');
    }
  });

  it('cross-file rules are "neighborhood": a sanitizer or gate may live in another file', () => {
    for (const id of ['AGT-001', 'AGT-003', 'AGT-004', 'AGT-006', 'SG-SQLI-TAINTED-QUERY', 'SG-COMMAND-INJECTION-PY']) {
      expect(contextTierFor(id), id).toBe('neighborhood');
    }
  });

  it('every semgrep rule in the pack is neighborhood tier (taint crosses files)', () => {
    const pack = parse(SEMGREP_RULES_YAML) as { rules: { id: string }[] };
    for (const rule of pack.rules) {
      const sgId = `SG-${rule.id.replace(/^prism-/, '').toUpperCase()}`;
      expect(contextTierFor(sgId), sgId).toBe('neighborhood');
    }
  });
});

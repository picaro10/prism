import { describe, it, expect } from 'vitest';
import { parse } from 'yaml';
import { RULE_METADATA, ruleMetadataFor } from '../../src/core/rule-metadata.js';
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

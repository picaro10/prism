import { describe, it, expect } from 'vitest';
import { OsvAnalyzer, type OsvFetch } from '../../src/analyzers/osv.js';
import type { ProjectScan, FileReader } from '../../src/core/types.js';

function mkScan(files: string[]): ProjectScan {
  return {
    rootPath: '/project',
    files,
    fileTree: [],
    meta: {
      stack: { primary: 'Python', secondary: [] },
      totalLoc: 0,
      totalFiles: files.length,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
  };
}

const REQUIREMENTS = 'requests==2.19.0\n';
const readRequirements: FileReader = async (path) => {
  if (path === 'requirements.txt') return REQUIREMENTS;
  throw new Error(`unexpected read: ${path}`);
};

/** Fake OSV API: querybatch reports the given vuln ids, detail returns the severity. */
function fakeOsv(vulnIds: string[], severity: string): { fetch: OsvFetch; calls: string[] } {
  const calls: string[] = [];
  const fetch: OsvFetch = async (url, init) => {
    calls.push(url + (init?.body ? ` ${init.body}` : ''));
    if (url.endsWith('/v1/querybatch')) {
      const queries = (JSON.parse(init?.body ?? '{}') as { queries: unknown[] }).queries;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          results: queries.map((_, i) => (i === 0 ? { vulns: vulnIds.map((id) => ({ id })) } : {})),
        }),
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        id: url.split('/').pop(),
        summary: 'Something bad',
        database_specific: { severity },
      }),
    };
  };
  return { fetch, calls };
}

/**
 * Richer fake: per-advisory detail responses, so a test can mix classified,
 * unclassified and alias-only advisories the way osv.dev really does.
 */
function fakeOsvDetailed(details: Record<string, { severity?: string; aliases?: string[] }>): {
  fetch: OsvFetch;
  detailCalls: string[];
} {
  const detailCalls: string[] = [];
  const ids = Object.keys(details);
  const fetch: OsvFetch = async (url, init) => {
    if (url.endsWith('/v1/querybatch')) {
      const queries = (JSON.parse(init?.body ?? '{}') as { queries: unknown[] }).queries;
      return {
        ok: true,
        status: 200,
        json: async () => ({ results: queries.map((_, i) => (i === 0 ? { vulns: ids.map((id) => ({ id })) } : {})) }),
      };
    }
    const id = decodeURIComponent(url.split('/').pop() ?? '');
    detailCalls.push(id);
    const d = details[id];
    if (!d) return { ok: false, status: 404, json: async () => ({}) };
    return {
      ok: true,
      status: 200,
      json: async () => ({
        id,
        ...(d.severity ? { database_specific: { severity: d.severity } } : {}),
        ...(d.aliases ? { aliases: d.aliases } : {}),
      }),
    };
  };
  return { fetch, detailCalls };
}

describe('OsvAnalyzer — severity honesty (regression: criticals must never hide in a low bucket)', () => {
  it('reports advisories it could not classify as their OWN medium finding, not as "lower"', async () => {
    const { fetch } = fakeOsvDetailed({
      'GHSA-known-low': { severity: 'MODERATE' },
      'PYSEC-no-severity': {}, // osv.dev has no severity for it and no alias to follow
    });
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);

    const ids = res.findings.map((f) => f.id);
    expect(ids).toContain('DEP-OSV-UNKNOWN');
    expect(ids).toContain('DEP-OSV-LOWER');

    const unknown = res.findings.find((f) => f.id === 'DEP-OSV-UNKNOWN')!;
    // "known vulnerability of unknown severity" is NOT low news — same doctrine
    // as DEP-AUDIT-SKIP: an unclassified advisory can be a critical.
    expect(unknown.severity).toBe('medium');
    expect(unknown.description).toContain('PYSEC-no-severity');

    // and the lower bucket must contain ONLY genuinely-classified lower ones
    const lower = res.findings.find((f) => f.id === 'DEP-OSV-LOWER')!;
    expect(lower.description).toContain('GHSA-known-low');
    expect(lower.description).not.toContain('PYSEC-no-severity');
  });

  it('follows the aliases chain to classify a PYSEC advisory that mirrors a GHSA one', async () => {
    const { fetch, detailCalls } = fakeOsvDetailed({
      'PYSEC-2019-1': { aliases: ['CVE-2019-0001', 'GHSA-real-crit'] },
      'GHSA-real-crit': { severity: 'CRITICAL' },
    });
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);

    expect(detailCalls).toContain('GHSA-real-crit');
    const critical = res.findings.find((f) => f.id === 'DEP-OSV-CRITICAL');
    expect(critical).toBeDefined();
    expect(critical!.description).toContain('PYSEC-2019-1');
    expect(res.findings.map((f) => f.id)).not.toContain('DEP-OSV-UNKNOWN');
  });

  it('discloses when advisories exceeded the per-run classification budget', async () => {
    const many: Record<string, { severity?: string }> = {};
    for (let i = 0; i < 400; i++) many[`GHSA-x-${i}`] = { severity: 'CRITICAL' };
    const { fetch, detailCalls } = fakeOsvDetailed(many);
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);

    // budget is bounded (no 400 detail calls) …
    expect(detailCalls.length).toBeLessThan(400);
    // … but big enough that a realistic project gets classified
    expect(detailCalls.length).toBeGreaterThanOrEqual(300);
    // … and whatever fell outside is disclosed, not silently downgraded
    const unknown = res.findings.find((f) => f.id === 'DEP-OSV-UNKNOWN')!;
    expect(unknown.description).toMatch(/budget/i);
    expect(res.summary).toMatch(/unclassified/i);
  });

  it('penalizes an unclassified batch (unknown is not a clean bill of health)', async () => {
    const { fetch } = fakeOsvDetailed({ 'PYSEC-a': {}, 'PYSEC-b': {} });
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);
    expect(res.findings.map((f) => f.id)).toEqual(['DEP-OSV-UNKNOWN']);
    expect(res.score).toBe(9);
  });
});

describe('OsvAnalyzer', () => {
  it('is silent (and offline) when there are no supported lockfiles', async () => {
    const { fetch, calls } = fakeOsv([], 'HIGH');
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['package.json', 'src/a.ts']), readRequirements);

    expect(calls).toEqual([]);
    expect(res.category).toBe('dependencies');
    expect(res.findings).toEqual([]);
    expect(res.score).toBe(10);
  });

  it('ignores lockfiles in excluded contexts (fixtures)', async () => {
    const { fetch, calls } = fakeOsv(['GHSA-x'], 'CRITICAL');
    const res = await new OsvAnalyzer(fetch).analyze(
      mkScan(['tests/fixtures/requirements.txt']),
      async () => REQUIREMENTS,
    );

    expect(calls).toEqual([]);
    expect(res.findings).toEqual([]);
  });

  it('emits DEP-OSV-CRITICAL with the package named and a -2 penalty', async () => {
    const { fetch, calls } = fakeOsv(['GHSA-crit-1'], 'CRITICAL');
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);

    expect(calls.some((c) => c.includes('/v1/querybatch') && c.includes('"requests"') && c.includes('"PyPI"'))).toBe(
      true,
    );
    const critical = res.findings.find((f) => f.id === 'DEP-OSV-CRITICAL');
    expect(critical).toBeDefined();
    expect(critical!.severity).toBe('critical');
    expect(critical!.description).toContain('requests@2.19.0');
    expect(critical!.file).toBe('requirements.txt');
    expect(res.score).toBe(8);
  });

  it('emits DEP-OSV-HIGH with a -1 penalty', async () => {
    const { fetch } = fakeOsv(['GHSA-high-1'], 'HIGH');
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);

    expect(res.findings.map((f) => f.id)).toEqual(['DEP-OSV-HIGH']);
    expect(res.score).toBe(9);
  });

  it('groups lower severities into one low-severity advisory note', async () => {
    const { fetch } = fakeOsv(['GHSA-mod-1', 'GHSA-mod-2'], 'MODERATE');
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);

    expect(res.findings.map((f) => f.id)).toEqual(['DEP-OSV-LOWER']);
    expect(res.findings[0].severity).toBe('low');
    expect(res.findings[0].description).toContain('2');
    expect(res.score).toBe(9.8);
  });

  it('reports a clean pass with the audited package count', async () => {
    const { fetch } = fakeOsv([], 'HIGH');
    const res = await new OsvAnalyzer(fetch).analyze(mkScan(['requirements.txt']), readRequirements);

    expect(res.findings).toEqual([]);
    expect(res.score).toBe(10);
    expect(res.summary).toContain('1 package');
  });

  it('treats an unreachable OSV API as unknown, not clean', async () => {
    const failing: OsvFetch = async () => {
      throw new Error('network down');
    };
    const res = await new OsvAnalyzer(failing).analyze(mkScan(['requirements.txt']), readRequirements);

    expect(res.findings.map((f) => f.id)).toEqual(['DEP-OSV-SKIP']);
    expect(res.findings[0].severity).toBe('low');
    expect(res.score).toBe(9);
  });
});

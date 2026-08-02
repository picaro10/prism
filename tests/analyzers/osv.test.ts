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

import { describe, it, expect } from 'vitest';
import { runRemediation, selectRealFindings } from '../../src/ai/remediate.js';
import { findingKey } from '../../src/ai/types.js';
import type { LLMClient, TriageUnit, Verdict, Remediation, ProjectContext, TriageResult } from '../../src/ai/types.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

function finding(p: Partial<Finding>): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}

function report(findings: Finding[], aiTriage?: TriageResult): AuditReport {
  return {
    projectName: 'demo',
    projectPath: '/demo',
    startedAt: '',
    completedAt: '',
    durationMs: 0,
    overallScore: 7,
    categories: [{ category: 'security', score: 8, maxScore: 10, findings: [], summary: 'sec ok' }],
    findings,
    projectMeta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 0,
      totalFiles: 0,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
    prismVersion: '1.4.0',
    aiTriage,
  };
}

function triageOf(findings: Finding[], classify: (f: Finding) => Verdict['classification']): TriageResult {
  const verdicts = findings.map((f) => ({
    findingKey: findingKey(f),
    classification: classify(f),
    confidence: 0.9,
    reasoning: 'r',
  }));
  return {
    verdicts,
    summary: {
      real: verdicts.filter((v) => v.classification === 'real').length,
      falsePositive: verdicts.filter((v) => v.classification === 'false-positive').length,
      uncertain: verdicts.filter((v) => v.classification === 'uncertain').length,
    },
  };
}

class FakeClient implements LLMClient {
  remediateUnits: TriageUnit[] = [];
  constructor(private fn: (u: TriageUnit) => Remediation[]) {}
  async triage(unit: TriageUnit, _ctx: ProjectContext): Promise<Verdict[]> {
    return unit.findings.map((f) => ({
      findingKey: findingKey(f),
      classification: 'real',
      confidence: 1,
      reasoning: 'r',
    }));
  }
  async verify(unit: TriageUnit, ctx: ProjectContext): Promise<Verdict[]> {
    return this.triage(unit, ctx);
  }
  async summarize(_digest: string, _ctx: ProjectContext): Promise<string> {
    return 'summary';
  }
  async remediate(unit: TriageUnit, _ctx: ProjectContext): Promise<Remediation[]> {
    this.remediateUnits.push(unit);
    return this.fn(unit);
  }
}

const reader = async (p: string) => `// content of ${p}`;

const fixAll = (u: TriageUnit): Remediation[] =>
  u.findings.map((f) => ({ findingKey: findingKey(f), fix: `fix ${f.id}`, effort: 'low' as const }));

describe('selectRealFindings', () => {
  it('returns only findings whose final verdict is real', () => {
    const findings = [
      finding({ id: 'A', file: 'src/a.ts' }),
      finding({ id: 'B', file: 'src/b.ts' }),
      finding({ id: 'C', file: 'src/c.ts' }),
    ];
    const triage = triageOf(findings, (f) => (f.id === 'A' ? 'real' : f.id === 'B' ? 'false-positive' : 'uncertain'));
    const selected = selectRealFindings(report(findings, triage));
    expect(selected.map((f) => f.id)).toEqual(['A']);
  });

  it('returns nothing when the report has no triage verdicts', () => {
    expect(selectRealFindings(report([finding({ id: 'A' })]))).toEqual([]);
  });
});

describe('runRemediation', () => {
  it('groups real findings by file and reads each file once', async () => {
    const findings = [
      finding({ id: 'A', file: 'src/a.ts', line: 1 }),
      finding({ id: 'B', file: 'src/a.ts', line: 2 }),
      finding({ id: 'C', file: 'src/b.ts' }),
      finding({ id: 'D' }), // project-level
    ];
    const client = new FakeClient(fixAll);
    const fixes = await runRemediation(
      report(
        findings,
        triageOf(findings, () => 'real'),
      ),
      reader,
      client,
    );
    expect(client.remediateUnits).toHaveLength(3);
    const aUnit = client.remediateUnits.find((u) => u.file === 'src/a.ts')!;
    expect(aUnit.findings).toHaveLength(2);
    expect(aUnit.content).toBe('// content of src/a.ts');
    const projUnit = client.remediateUnits.find((u) => u.file === null)!;
    expect(projUnit.content).toBe('');
    expect(fixes).toHaveLength(4);
  });

  it('sends only confirmed-real findings (no FP, no uncertain)', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' }), finding({ id: 'B', file: 'src/a.ts' })];
    const triage = triageOf(findings, (f) => (f.id === 'A' ? 'real' : 'false-positive'));
    const client = new FakeClient(fixAll);
    const fixes = await runRemediation(report(findings, triage), reader, client);
    expect(client.remediateUnits).toHaveLength(1);
    expect(client.remediateUnits[0].findings.map((f) => f.id)).toEqual(['A']);
    expect(fixes).toHaveLength(1);
  });

  it('makes no calls when nothing is confirmed real', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const client = new FakeClient(fixAll);
    const fixes = await runRemediation(
      report(
        findings,
        triageOf(findings, () => 'uncertain'),
      ),
      reader,
      client,
    );
    expect(client.remediateUnits).toHaveLength(0);
    expect(fixes).toEqual([]);
  });

  it('discards fixes for keys it did not send and does not fabricate missing ones', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' }), finding({ id: 'B', file: 'src/a.ts' })];
    const client = new FakeClient((u) => [
      { findingKey: findingKey(u.findings[0]), fix: 'real fix', effort: 'low' },
      { findingKey: 'BOGUS|x|1', fix: 'noise', effort: 'high' },
      // no fix returned for finding B — must stay absent
    ]);
    const fixes = await runRemediation(
      report(
        findings,
        triageOf(findings, () => 'real'),
      ),
      reader,
      client,
    );
    expect(fixes).toHaveLength(1);
    expect(fixes[0].findingKey).toBe(findingKey(findings[0]));
  });

  it('keeps a fix whose echoed key lost its trailing pipes, restoring the canonical key', async () => {
    const findings = [finding({ id: 'STR-011', file: 'src/big.py' })];
    const client = new FakeClient(() => [
      { findingKey: 'STR-011|src/big.py', fix: 'split the module', effort: 'high' },
    ]);
    const fixes = await runRemediation(
      report(
        findings,
        triageOf(findings, () => 'real'),
      ),
      reader,
      client,
    );
    expect(fixes).toHaveLength(1);
    expect(fixes[0].findingKey).toBe('STR-011|src/big.py|');
  });

  it('dedupes repeated fixes for the same finding (first wins)', async () => {
    const findings = [finding({ id: 'A', file: 'src/a.ts' })];
    const client = new FakeClient((u) => [
      { findingKey: findingKey(u.findings[0]), fix: 'first', effort: 'low' },
      { findingKey: findingKey(u.findings[0]), fix: 'second', effort: 'high' },
    ]);
    const fixes = await runRemediation(
      report(
        findings,
        triageOf(findings, () => 'real'),
      ),
      reader,
      client,
    );
    expect(fixes).toHaveLength(1);
    expect(fixes[0].fix).toBe('first');
  });

  it('remediates a file even when reading it fails', async () => {
    const findings = [finding({ id: 'A', file: 'src/missing.ts' })];
    const failReader = async () => {
      throw new Error('ENOENT');
    };
    const client = new FakeClient(fixAll);
    const fixes = await runRemediation(
      report(
        findings,
        triageOf(findings, () => 'real'),
      ),
      failReader,
      client,
    );
    expect(client.remediateUnits[0].content).toBe('');
    expect(fixes).toHaveLength(1);
  });
});

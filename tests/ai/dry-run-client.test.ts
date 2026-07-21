import { describe, it, expect } from 'vitest';
import { DryRunLLMClient } from '../../src/ai/dry-run-client.js';
import { applyAiTriage } from '../../src/ai/run.js';
import { findingKey } from '../../src/ai/types.js';
import type { TriageUnit, ProjectContext } from '../../src/ai/types.js';
import type { AuditReport, Finding } from '../../src/core/types.js';

const ctx: ProjectContext = { projectName: 'p', stack: 'ts', overallScore: 5, categorySummaries: [] };
function finding(p: Partial<Finding>): Finding {
  return { id: 'X', category: 'security', severity: 'high', title: 't', description: 'd', ...p };
}
function unit(findings: Finding[]): TriageUnit {
  return { file: 'src/a.ts', content: '// code', findings };
}

describe('DryRunLLMClient', () => {
  const client = new DryRunLLMClient();

  it('returns a canned verdict per finding, echoing the findingKey', async () => {
    const fs = [finding({ id: 'A', file: 'src/a.ts', line: 1 }), finding({ id: 'B', file: 'src/a.ts', line: 2 })];
    const verdicts = await client.triage(unit(fs), ctx);
    expect(verdicts.map((v) => v.findingKey)).toEqual(fs.map(findingKey));
    expect(verdicts.every((v) => v.reasoning.includes('[dry-run]'))).toBe(true);
  });

  it('returns canned summary and remediation without any network', async () => {
    expect(await client.summarize('digest', ctx)).toContain('[dry-run]');
    const fixes = await client.remediate(unit([finding({ file: 'src/a.ts', line: 1 })]), ctx);
    expect(fixes[0].fix).toContain('[dry-run]');
    expect(fixes[0].effort).toBe('medium');
  });
});

describe('applyAiTriage with aiDryRun', () => {
  it('runs the full AI pipeline from config, no key, no network', async () => {
    const report: AuditReport = {
      projectName: 'p',
      projectPath: '/p',
      startedAt: '',
      completedAt: '',
      durationMs: 0,
      overallScore: 5,
      categories: [],
      findings: [finding({ id: 'A', file: 'src/a.ts', line: 1 })],
      projectMeta: {
        stack: { primary: 'typescript', secondary: [] },
        totalLoc: 0,
        totalFiles: 0,
        hasGit: true,
        hasDocker: false,
        hasCi: false,
        frameworks: [],
      },
      prismVersion: '1.10.0',
    };
    await applyAiTriage(report, async () => '// code', { aiDryRun: true });
    expect(report.aiTriage?.verdicts).toHaveLength(1);
    expect(report.aiSummary).toContain('[dry-run]');
    expect(report.aiRemediation).toHaveLength(1);
  });
});

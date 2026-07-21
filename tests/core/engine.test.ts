import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { runAudit } from '../../src/core/engine.js';
import type { PrismConfig } from '../../src/core/types.js';
import type { LLMClient, Verdict } from '../../src/ai/types.js';
import { findingKey } from '../../src/ai/types.js';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

describe('runAudit', () => {
  it('produces a complete audit report', async () => {
    const config: PrismConfig = { targetPath: FIXTURE_PATH };
    const report = await runAudit(config);

    expect(report.projectName).toBeTruthy();
    expect(report.projectPath).toBe(FIXTURE_PATH);
    expect(report.startedAt).toBeTruthy();
    expect(report.completedAt).toBeTruthy();
    expect(report.durationMs).toBeGreaterThan(0);
    expect(report.overallScore).toBeGreaterThanOrEqual(0);
    expect(report.overallScore).toBeLessThanOrEqual(10);
    expect(report.categories.length).toBeGreaterThan(0);
    expect(report.prismVersion).toBe('1.0.0');
  });

  it('includes all analyzer categories', async () => {
    const config: PrismConfig = { targetPath: FIXTURE_PATH };
    const report = await runAudit(config);

    const categories = report.categories.map((c) => c.category);
    expect(categories).toContain('structure');
    expect(categories).toContain('security');
    expect(categories).toContain('dependencies');
  });

  it('respects category filter', async () => {
    const config: PrismConfig = {
      targetPath: FIXTURE_PATH,
      analyzers: ['structure'],
    };
    const report = await runAudit(config);

    expect(report.categories.length).toBe(1);
    expect(report.categories[0].category).toBe('structure');
  });

  it('findings are sorted by severity', async () => {
    const config: PrismConfig = { targetPath: FIXTURE_PATH };
    const report = await runAudit(config);

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (let i = 1; i < report.findings.length; i++) {
      const prev = severityOrder[report.findings[i - 1].severity];
      const curr = severityOrder[report.findings[i].severity];
      expect(curr).toBeGreaterThanOrEqual(prev);
    }
  });

  it('calls onProgress callback', async () => {
    const messages: string[] = [];
    const config: PrismConfig = { targetPath: FIXTURE_PATH };

    await runAudit(config, (msg) => messages.push(msg));

    expect(messages.length).toBeGreaterThan(0);
    expect(messages.some((m) => m.includes('Scanning'))).toBe(true);
    expect(messages.some((m) => m.includes('Audit complete'))).toBe(true);
  });

  it('security category weighs heavier than structure', async () => {
    const config: PrismConfig = { targetPath: FIXTURE_PATH };
    const report = await runAudit(config);

    // The fixture has critical security issues, so overall score
    // should be pulled down by the security weight
    const securityScore = report.categories.find((c) => c.category === 'security')?.score || 10;
    const structureScore = report.categories.find((c) => c.category === 'structure')?.score || 0;

    // If security is bad and structure is decent, overall should lean toward security
    if (securityScore < structureScore) {
      expect(report.overallScore).toBeLessThan(structureScore);
    }
  });
});

describe('runAudit — AI triage integration', () => {
  it('attaches aiTriage when an LLM client is injected, without mutating findings or score', async () => {
    const fpVerdicts = (unit: { findings: { id: string; file?: string; line?: number }[] }): Verdict[] =>
      unit.findings.map((f) => ({
        findingKey: findingKey(f as Parameters<typeof findingKey>[0]),
        classification: 'false-positive' as const,
        confidence: 0.7,
        reasoning: 'fixture',
      }));
    const fake: LLMClient = {
      async triage(unit) {
        return fpVerdicts(unit);
      },
      async verify(unit) {
        return fpVerdicts(unit); // confirm the FP
      },
      async summarize() {
        return 'Executive summary text.';
      },
    };
    const baseline = await runAudit({ targetPath: FIXTURE_PATH, output: 'cli' });
    const withAi = await runAudit({ targetPath: FIXTURE_PATH, output: 'cli', ai: true }, undefined, fake);

    expect(withAi.aiTriage).toBeDefined();
    expect(withAi.aiTriage!.verdicts.length).toBe(withAi.findings.length);
    expect(withAi.overallScore).toBe(baseline.overallScore);
    expect(withAi.findings.length).toBe(baseline.findings.length);
  });

  it('does not run triage when ai is not set', async () => {
    const report = await runAudit({ targetPath: FIXTURE_PATH, output: 'cli' });
    expect(report.aiTriage).toBeUndefined();
  });

  it('survives a triage failure: static report intact, aiTriage undefined', async () => {
    const throwing: LLMClient = {
      async triage() {
        throw new Error('boom');
      },
      async verify() {
        throw new Error('boom');
      },
      async summarize() {
        throw new Error('boom');
      },
    };
    const messages: string[] = [];
    const report = await runAudit(
      { targetPath: FIXTURE_PATH, output: 'cli', ai: true },
      (m) => messages.push(m),
      throwing,
    );
    expect(report.aiTriage).toBeUndefined();
    expect(report.findings.length).toBeGreaterThan(0); // static report survived
    expect(messages.some((m) => m.startsWith('AI triage failed'))).toBe(true);
  });
});

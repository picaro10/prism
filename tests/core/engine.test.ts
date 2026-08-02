import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { runAudit, CATEGORY_WEIGHTS, mergeResultsByCategory } from '../../src/core/engine.js';
import type { AnalyzerResult } from '../../src/core/types.js';
import type { PrismConfig } from '../../src/core/types.js';
import type { LLMClient, Verdict } from '../../src/ai/types.js';
import { findingKey } from '../../src/ai/types.js';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

describe('runAudit', { timeout: 120_000 }, () => {
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
    expect(report.prismVersion).toBe('1.5.0');
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

  it('marks categories with nothing to analyze as N/A and excludes them from the overall score', async () => {
    // The fixture has no .github/workflows — workflow must be applicable:false
    // (not a perfect 10 inflating the average).
    const config: PrismConfig = { targetPath: FIXTURE_PATH };
    const report = await runAudit(config);

    const workflow = report.categories.find((c) => c.category === 'workflow');
    expect(workflow?.applicable).toBe(false);

    // Overall must equal the weighted average of APPLICABLE categories only.
    const applicable = report.categories.filter((c) => c.applicable !== false);
    expect(applicable.length).toBeLessThan(report.categories.length);
    let weightedSum = 0;
    let totalWeight = 0;
    for (const c of applicable) {
      const w = CATEGORY_WEIGHTS[c.category] || 1.0;
      weightedSum += c.score * w;
      totalWeight += w;
    }
    expect(report.overallScore).toBe(Math.round((weightedSum / totalWeight) * 10) / 10);
  });
});

describe('mergeResultsByCategory', () => {
  const mk = (
    category: AnalyzerResult['category'],
    score: number,
    ids: string[],
    applicable?: false,
  ): AnalyzerResult => ({
    category,
    score,
    findings: ids.map((id) => ({
      id,
      category,
      severity: 'high' as const,
      title: id,
      description: id,
    })),
    summary: `${category}:${score}`,
    ...(applicable === false ? { applicable: false as const } : {}),
  });

  it('leaves single-analyzer categories untouched', () => {
    const results = [mk('structure', 8, ['STR-001']), mk('security', 9, ['SEC-001'])];
    expect(mergeResultsByCategory(results)).toEqual(results);
  });

  it('merges same-category results: min score, concatenated findings, joined summary', () => {
    const merged = mergeResultsByCategory([
      mk('security', 9, ['SEC-001']),
      mk('security', 6, ['SG-SQLI-X']),
      mk('structure', 8, ['STR-001']),
    ]);

    expect(merged).toHaveLength(2);
    const security = merged.find((r) => r.category === 'security')!;
    expect(security.score).toBe(6);
    expect(security.findings.map((f) => f.id)).toEqual(['SEC-001', 'SG-SQLI-X']);
    expect(security.summary).toBe('security:9 · security:6');
  });

  it('a merged category is applicable when any member is applicable', () => {
    const merged = mergeResultsByCategory([mk('security', 10, [], false), mk('security', 7, ['SG-A'])]);
    expect(merged).toHaveLength(1);
    expect(merged[0].applicable).not.toBe(false);
  });

  it('a merged category stays N/A only when every member is N/A', () => {
    const merged = mergeResultsByCategory([mk('security', 10, [], false), mk('security', 10, [], false)]);
    expect(merged[0].applicable).toBe(false);
  });
});

describe('runAudit — category uniqueness', { timeout: 120_000 }, () => {
  it('never emits two CategoryScores for the same category', async () => {
    const report = await runAudit({ targetPath: FIXTURE_PATH });
    const cats = report.categories.map((c) => c.category);
    expect(new Set(cats).size).toBe(cats.length);
  });
});

describe('runAudit — AI triage integration', { timeout: 120_000 }, () => {
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

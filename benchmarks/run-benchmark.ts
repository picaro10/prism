/**
 * PRISM false-positive benchmark — reproducible from a clean checkout:
 *
 *   npm run bench
 *
 * Materializes each corpus case (benchmarks/cases.ts) into a temp project,
 * runs the real engine on it, and compares the findings in each expected file
 * against the exact expected rule-id set:
 *
 *   - a planted issue that is not found       → false negative (recall loss)
 *   - a finding where none is expected        → false positive (precision loss)
 *
 * Exits 1 on ANY miss in either direction: a rule change that widens coverage
 * at the cost of new noise fails here before it ever dirties a real report.
 * This encodes PRISM's core constraint — credibility over finding volume.
 */

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runAudit } from '../src/core/engine.js';
import type { AnalysisCategory } from '../src/core/types.js';
import { CASES } from './cases.js';

interface CaseResult {
  name: string;
  tp: number;
  fn: string[];
  fp: string[];
  ms: number;
}

async function runCase(c: (typeof CASES)[number]): Promise<CaseResult> {
  const dir = mkdtempSync(join(tmpdir(), 'prism-bench-'));
  try {
    for (const [rel, content] of Object.entries(c.files)) {
      mkdirSync(join(dir, dirname(rel)), { recursive: true });
      writeFileSync(join(dir, rel), content);
    }
    const started = performance.now();
    const report = await runAudit({ targetPath: dir, analyzers: c.categories as AnalysisCategory[] });
    const ms = Math.round(performance.now() - started);

    let tp = 0;
    const fn: string[] = [];
    const fp: string[] = [];
    for (const [rel, expectedIds] of Object.entries(c.expect)) {
      const actual = report.findings.filter((f) => f.file === rel).map((f) => f.id);
      for (const id of expectedIds) {
        if (actual.includes(id)) tp += 1;
        else fn.push(`${rel}: expected ${id}, not found`);
      }
      for (const id of actual) {
        if (!expectedIds.includes(id)) fp.push(`${rel}: unexpected ${id}`);
      }
    }
    return { name: c.name, tp, fn, fp, ms };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const results: CaseResult[] = [];
for (const c of CASES) results.push(await runCase(c));

const totalTp = results.reduce((n, r) => n + r.tp, 0);
const totalFn = results.flatMap((r) => r.fn);
const totalFp = results.flatMap((r) => r.fp);
const totalMs = results.reduce((n, r) => n + r.ms, 0);
const precision = totalTp + totalFp.length === 0 ? 1 : totalTp / (totalTp + totalFp.length);
const recall = totalTp + totalFn.length === 0 ? 1 : totalTp / (totalTp + totalFn.length);

console.log('\nPRISM FP benchmark');
console.log('──────────────────');
for (const r of results) {
  const status = r.fn.length + r.fp.length === 0 ? '✓' : '✗';
  console.log(`  ${status} ${r.name.padEnd(42)} ${String(r.ms).padStart(4)}ms`);
  for (const m of r.fn) console.log(`      FN ${m}`);
  for (const m of r.fp) console.log(`      FP ${m}`);
}
console.log('──────────────────');
console.log(`  cases ${results.length} · planted ${totalTp + totalFn.length} · found ${totalTp}`);
console.log(`  precision ${(precision * 100).toFixed(1)}% · recall ${(recall * 100).toFixed(1)}%`);
console.log(`  total ${totalMs}ms · heap ${(process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1)}MB\n`);

if (totalFn.length + totalFp.length > 0) {
  console.error(`  ✗ ${totalFn.length} false negative(s), ${totalFp.length} false positive(s) — regression.\n`);
  process.exit(1);
}
console.log('  ✓ No regressions.\n');

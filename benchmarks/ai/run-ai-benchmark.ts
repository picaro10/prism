/**
 * PRISM AI-triage benchmark — measures the JUDGE, not the rules:
 *
 *   npm run bench:ai                       # live model from ANTHROPIC_API_KEY / OPENROUTER_API_KEY
 *   npm run bench:ai -- --dry-run          # canned client: exercises the corpus and plumbing at zero cost
 *   npm run bench:ai -- --model <id>       # override the triage model
 *   npm run bench:ai -- --vote a,b         # verification panel (same semantics as --ai-vote)
 *   npm run bench:ai -- --only <substr>    # run a subset by name
 *
 * Every case is a finding the static layer really emits, with the verdict a
 * careful reviewer reaches. Exit 1 only when a REAL issue was excused as a
 * false positive (hidden risk) or a case could not be judged (broken corpus
 * or client). Missed false positives and `uncertain` verdicts are reported
 * as rates, not gated: a live model is not deterministic, and this runs
 * before releases, not on every push.
 *
 * Without an API key and without --dry-run the run is SKIPPED loudly with
 * exit 0 — the judge cannot be measured, and that must never read as green.
 */

import { AI_CASES } from './cases.js';
import { runAiCase, summarize, type AiCaseResult } from './lib.js';
import type { LLMClient } from '../../src/ai/types.js';

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const dryRun = args.includes('--dry-run');
const model = flag('--model');
const only = flag('--only');
const vote = flag('--vote')
  ?.split(',')
  .map((s) => s.trim())
  .filter(Boolean);

async function makeClients(): Promise<{ client: LLMClient; verifiers?: LLMClient[]; label: string } | null> {
  if (dryRun) {
    const { DryRunLLMClient } = await import('../../src/ai/dry-run-client.js');
    return { client: new DryRunLLMClient(), label: 'dry-run (canned verdicts)' };
  }
  const provider = process.env.ANTHROPIC_API_KEY ? 'anthropic' : process.env.OPENROUTER_API_KEY ? 'openrouter' : null;
  if (!provider) return null;
  const make =
    provider === 'openrouter'
      ? await import('../../src/ai/openrouter-client.js').then((m) => (id?: string) => new m.OpenRouterLLMClient(id))
      : await import('../../src/ai/client.js').then((m) => (id?: string) => new m.AnthropicLLMClient(id));
  return {
    client: make(model),
    verifiers: vote?.length ? vote.map((id) => make(id)) : undefined,
    label: `${provider}${model ? ` · ${model}` : ''}${vote?.length ? ` · panel ${vote.join(',')}` : ''}`,
  };
}

const clients = await makeClients();
if (!clients) {
  console.log('\nPRISM AI-triage benchmark');
  console.log('─────────────────────────');
  console.log('  SKIPPED — no ANTHROPIC_API_KEY / OPENROUTER_API_KEY in the environment and no --dry-run.');
  console.log('  The judge was NOT measured. Set a key, or pass --dry-run to exercise the corpus offline.\n');
  process.exit(0);
}

const selected = only ? AI_CASES.filter((c) => c.name.includes(only)) : AI_CASES;
const results: AiCaseResult[] = [];
for (const c of selected) {
  const r = await runAiCase(c, { client: clients.client, verifiers: clients.verifiers });
  results.push(r);
  const mark = r.broken ? '!' : r.outcome === 'hit' ? '✓' : r.outcome === 'excused-real' ? '✗' : '~';
  const detail = r.broken ? `BROKEN: ${r.broken}` : `${r.expected} → ${r.got} (${r.outcome})`;
  console.log(`  ${mark} ${c.name.padEnd(52)} ${detail}`);
  if (!r.broken && r.outcome !== 'hit' && r.reasoning) console.log(`      judge: ${r.reasoning.slice(0, 220)}`);
}

const s = summarize(results);
const pct = (n: number) => `${(n * 100).toFixed(0)}%`;
console.log('\nPRISM AI-triage benchmark');
console.log('─────────────────────────');
console.log(`  judge ${clients.label}`);
console.log(
  `  cases ${s.cases} · hit ${s.hit} · escalated ${s.escalated} · noise kept ${s.noiseKept} · excused real ${s.excusedReal}${s.broken ? ` · BROKEN ${s.broken}` : ''}`,
);
console.log(
  `  real confirmed ${pct(s.realHitRate)} · same-file FPs caught ${pct(s.fpCatchRate)} · cross-file FPs caught ${pct(s.crossFileCatchRate)} (neighborhood baseline)`,
);
console.log(
  `  calls ${s.calls} · file content ${(s.contentBytes / 1024).toFixed(1)} KB · ${(s.ms / 1000).toFixed(1)}s\n`,
);

if (!s.ok) {
  if (s.excusedReal > 0)
    console.error(`  ✗ ${s.excusedReal} real issue(s) excused as false positives — the judge hid risk.`);
  if (s.broken > 0) console.error(`  ✗ ${s.broken} case(s) could not be judged — corpus or client broken.`);
  console.error('');
  process.exit(1);
}
console.log('  ✓ No real issue was excused.\n');

import type { LLMClient, TriageUnit, Verdict, Remediation, ProjectContext } from './types.js';
import { findingKey } from './types.js';

/**
 * An LLMClient that returns canned responses without any network call or API
 * key. Used by `--dry-run` to exercise the full report pipeline (triage →
 * remediation → summary) for demos and tests at zero token cost. Verdicts are
 * marked clearly as canned so a dry-run report is never mistaken for a real one.
 */
export class DryRunLLMClient implements LLMClient {
  async triage(unit: TriageUnit, _ctx: ProjectContext): Promise<Verdict[]> {
    return unit.findings.map((f) => ({
      findingKey: findingKey(f),
      classification: 'real',
      confidence: 0.5,
      reasoning: '[dry-run] canned verdict — no LLM was called.',
    }));
  }

  async verify(unit: TriageUnit, ctx: ProjectContext): Promise<Verdict[]> {
    return this.triage(unit, ctx);
  }

  async summarize(_digest: string, _ctx: ProjectContext): Promise<string> {
    return '[dry-run] This is a canned executive summary. Run without --dry-run for a real AI assessment.';
  }

  async remediate(unit: TriageUnit, _ctx: ProjectContext): Promise<Remediation[]> {
    return unit.findings.map((f) => ({
      findingKey: findingKey(f),
      fix: '[dry-run] canned fix suggestion — run without --dry-run for a real remediation.',
      effort: 'medium',
    }));
  }
}

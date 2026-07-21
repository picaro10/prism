import type { Verdict, Classification } from './types.js';

/**
 * Merge the verdicts of an N-model verification panel by majority vote.
 *
 * Why: a single cheap model makes *judgment* errors with full confidence —
 * seen twice on orion_new (a disconnected test excused as "testing style",
 * a real exposed port flipping real→FP between identical runs). A skeptical
 * re-check by the same model shares the same blind spots; models from
 * different families are unlikely to mis-judge the same way.
 *
 * Rules (these run on findings a first pass called false-positive, so the
 * stakes are "does the FP survive"):
 * - `false-positive` survives only if the panel is UNANIMOUS. This is the
 *   N-voter generalization of the v1.1.0 rule ("the skeptical re-check must
 *   confirm the FP") — any skeptic's dissent blocks the excusal. Empirical
 *   basis: on orion_new a 2/3 lenient majority out-voted the one model that
 *   correctly called a disconnected test real; with majority rule the panel
 *   reduced variance but kept the models' shared lenient bias.
 * - `real` needs a strict majority to be asserted.
 * - Anything less decisive is `uncertain` — surface it for the human.
 *   Demoting a true FP to uncertain costs a human a look; confirming a
 *   false FP hides a real issue. The asymmetry favors unanimity.
 *
 * Input: one aligned verdict array per voter (same findings, same order —
 * the caller aligns each voter with alignVerdicts, so an unresponsive voter
 * abstains as `uncertain`). A single-voter panel passes its verdicts through
 * untouched (the pre-panel behavior).
 */
export function tallyVerdicts(perVoter: Verdict[][]): Verdict[] {
  if (perVoter.length === 0) return [];
  if (perVoter.length === 1) return perVoter[0];

  const findingCount = perVoter[0].length;
  const merged: Verdict[] = [];
  for (let i = 0; i < findingCount; i++) {
    merged.push(mergeVotes(perVoter.map((voter) => voter[i])));
  }
  return merged;
}

function mergeVotes(votes: Verdict[]): Verdict {
  const count = (c: Classification) => votes.filter((v) => v.classification === c).length;
  const fp = count('false-positive');
  const real = count('real');
  const uncertain = count('uncertain');

  let winner: Classification;
  if (fp === votes.length) {
    winner = 'false-positive';
  } else if (real * 2 > votes.length) {
    winner = 'real';
  } else {
    winner = 'uncertain';
  }

  const tally = `[panel: ${real} real · ${fp} fp · ${uncertain} uncertain]`;
  const winning = votes.filter((v) => v.classification === winner);

  if (winning.length === 0) {
    // `uncertain` won without any uncertain votes — e.g. 2 fp / 1 real:
    // the FP is not unanimous and real has no majority.
    return {
      findingKey: votes[0].findingKey,
      classification: winner,
      confidence: 0,
      reasoning: `panel did not unanimously confirm the false positive ${tally}`,
    };
  }

  const spokesman = winning.reduce((a, b) => (b.confidence > a.confidence ? b : a));
  const confidence = winning.reduce((sum, v) => sum + v.confidence, 0) / winning.length;
  return {
    findingKey: spokesman.findingKey,
    classification: winner,
    confidence,
    reasoning: `${spokesman.reasoning} ${tally}`,
  };
}

import { parse } from 'yaml';
import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding, Severity } from '../core/types.js';
import { localBranches } from '../utils/git-refs.js';

/**
 * WorkflowAnalyzer — CI/CD risks in GitHub Actions workflows.
 *
 * Deliberately NOT an actionlint/zizmor rebuild: syntax validation and deep
 * Actions security auditing already have excellent dedicated tools. PRISM's
 * angle is what a linter that sees the YAML in isolation cannot do:
 * cross-checks against the actual repository (do the filtered branches exist?
 * is there a lockfile the cache setting ignores?), an integrated project
 * score, and the same credibility machinery (suppressions, baseline, AI
 * triage) every other category gets. Several rules encode field lessons this
 * project paid for: a CI that never triggers is worse than no CI; a gate that
 * continues on error fails open.
 */
export class WorkflowAnalyzer implements Analyzer {
  readonly name = 'workflow';
  readonly category = 'workflow' as const;
  readonly description =
    'Detects CI/CD workflow risks in GitHub Actions: pwn requests, script injection, unpinned actions, dead triggers, fail-open gates';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const workflowFiles = scan.files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f));
    if (workflowFiles.length === 0) {
      return {
        category: 'workflow',
        score: 10,
        findings: [],
        summary: 'No GitHub Actions workflows found (N/A — absence is not a defect).',
      };
    }

    const findings: Finding[] = [];
    let score = 10;
    // Unpinned-action hits usually share one root cause (no pinning
    // convention), so their aggregate penalty is capped like AGT-003's.
    let unpinnedPenalty = 0;

    const branches = localBranches(scan.rootPath);
    const hasLockfile = scan.files.some((f) =>
      ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'].includes(f.split('/').pop() ?? ''),
    );

    for (const file of workflowFiles) {
      let raw: string;
      try {
        raw = await readFile(file);
      } catch {
        continue;
      }

      let doc: unknown;
      try {
        doc = parse(raw);
      } catch {
        findings.push(
          finding(
            'WFL-PARSE',
            'medium',
            file,
            1,
            'Workflow YAML could not be parsed',
            'The file is not valid YAML — the workflow will fail at load time on GitHub.',
            'Fix the YAML syntax; actionlint or `yamllint` will pinpoint the error.',
          ),
        );
        score -= 0.5;
        continue;
      }
      if (typeof doc !== 'object' || doc === null) continue;
      const wf = doc as Record<string, unknown>;

      for (const f of checkWorkflow(wf, raw, file, { branches, hasLockfile })) {
        findings.push(f);
        if (f.id === 'WFL-003') unpinnedPenalty += PENALTY[f.severity];
        else score -= PENALTY[f.severity];
      }
    }

    score -= Math.min(unpinnedPenalty, MAX_UNPINNED_PENALTY);
    const capped = Math.max(0, Math.round(score * 10) / 10);
    return {
      category: 'workflow',
      score: capped,
      findings,
      summary:
        findings.length === 0
          ? `${workflowFiles.length} workflow(s) checked — no CI/CD risks detected.`
          : `${findings.length} CI/CD risk(s) across ${workflowFiles.length} workflow(s).`,
    };
  }
}

const PENALTY: Record<Severity, number> = { critical: 1.5, high: 1.0, medium: 0.5, low: 0.2, info: 0 };
const MAX_UNPINNED_PENALTY = 2.0;

function finding(
  id: string,
  severity: Severity,
  file: string,
  line: number | undefined,
  title: string,
  description: string,
  suggestion: string,
): Finding {
  return { id, category: 'workflow', severity, title, description, suggestion, file, line };
}

/** 1-based line of the first occurrence of a marker substring, or undefined. */
function lineOf(raw: string, marker: string): number | undefined {
  const idx = raw.indexOf(marker);
  if (idx < 0) return undefined;
  return raw.slice(0, idx).split('\n').length;
}

interface RepoContext {
  branches: string[];
  hasLockfile: boolean;
}

/** Normalize the `on:` trigger section into a set of event names. */
function triggerEvents(wf: Record<string, unknown>): Set<string> {
  const on = wf.on ?? (wf as Record<string, unknown>)[String(true)]; // YAML 1.1 parses bare `on` as boolean true in some configs
  if (typeof on === 'string') return new Set([on]);
  if (Array.isArray(on)) return new Set(on.map(String));
  if (typeof on === 'object' && on !== null) return new Set(Object.keys(on));
  return new Set();
}

function jobs(wf: Record<string, unknown>): Record<string, Record<string, unknown>> {
  const j = wf.jobs;
  if (typeof j !== 'object' || j === null) return {};
  return j as Record<string, Record<string, unknown>>;
}

function steps(job: Record<string, unknown>): Record<string, unknown>[] {
  return Array.isArray(job.steps) ? (job.steps as Record<string, unknown>[]) : [];
}

/** Expressions whose content an outsider controls (issue titles, PR bodies, branch names…). */
const UNTRUSTED_EXPR =
  /\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|discussion|commits|head_commit)|head_ref)[^}]*\}\}/;

/** Job/step names that mean "this is a quality or security gate". */
const GATE_NAME = /test|lint|audit|security|scan|check|verify|gate/i;

export function checkWorkflow(wf: Record<string, unknown>, raw: string, file: string, ctx: RepoContext): Finding[] {
  const out: Finding[] = [];
  const events = triggerEvents(wf);
  const allJobs = jobs(wf);

  // WFL-001 — pwn request: pull_request_target + checkout of the PR's head.
  // The workflow runs with secrets and a write token; checking out attacker
  // code hands both over.
  if (events.has('pull_request_target')) {
    for (const job of Object.values(allJobs)) {
      for (const step of steps(job)) {
        const uses = typeof step.uses === 'string' ? step.uses : '';
        const ref =
          typeof (step.with as Record<string, unknown>)?.ref === 'string'
            ? String((step.with as Record<string, unknown>).ref)
            : '';
        if (uses.startsWith('actions/checkout') && /github\.event\.pull_request\.head/.test(ref)) {
          out.push(
            finding(
              'WFL-001',
              'critical',
              file,
              lineOf(raw, 'pull_request_target'),
              'pull_request_target checks out the PR head (pwn request)',
              'The workflow runs in the base-repo context (secrets + write token) while executing code from the fork — the classic GitHub Actions takeover.',
              'Use the plain pull_request trigger, or never check out the PR head under pull_request_target (split privileged and unprivileged jobs).',
            ),
          );
        }
      }
    }
  }

  // WFL-002 — script injection: an outsider-controlled expression interpolated
  // straight into a run: script (the AGT-001 of workflows).
  for (const line of raw.split('\n').map((l, i) => ({ l, n: i + 1 }))) {
    if (UNTRUSTED_EXPR.test(line.l) && /run:|`|\$\(/.test(line.l)) {
      out.push(
        finding(
          'WFL-002',
          'high',
          file,
          line.n,
          'Untrusted event data interpolated into a run script (script injection)',
          'Issue titles, PR bodies, and branch names are attacker-controlled; interpolating them into a shell script lets a crafted value execute commands in the runner.',
          'Pass the value through an env: variable and reference it as "$VAR" in the script — the shell then treats it as data, not code.',
        ),
      );
    }
  }

  // WFL-003 — third-party action not pinned to a commit SHA. Tags and
  // branches are mutable: a compromised action repo becomes your compromise.
  for (const m of raw.matchAll(/^\s*(?:-\s+)?uses:\s*([\w.-]+)\/([\w.\/-]+)@([\w.\/-]+)/gm)) {
    const [full, owner, , ref] = m;
    if (owner === 'actions' || owner === 'github') continue; // first-party, tag-pinning is accepted practice
    if (/^[0-9a-f]{40}$/.test(ref)) continue;
    const mutable = ['master', 'main', 'latest'].includes(ref);
    out.push(
      finding(
        'WFL-003',
        mutable ? 'high' : 'medium',
        file,
        lineOf(raw, full.trim()),
        `Third-party action not pinned to a commit SHA (@${ref})`,
        `${owner}'s action is referenced by a mutable ${mutable ? 'branch' : 'tag'}; if that repo is compromised, the workflow executes the attacker's code with its permissions.`,
        'Pin third-party actions to a full commit SHA (uses: owner/action@<40-hex-sha> # vX.Y.Z).',
      ),
    );
  }

  // WFL-004 — no permissions block anywhere: the default GITHUB_TOKEN can be
  // write-broad depending on repo settings; explicit least privilege is free.
  const hasTopPermissions = 'permissions' in wf;
  const hasJobPermissions = Object.values(allJobs).some((j) => 'permissions' in j);
  if (!hasTopPermissions && !hasJobPermissions) {
    out.push(
      finding(
        'WFL-004',
        'medium',
        file,
        1,
        'No permissions block (GITHUB_TOKEN defaults apply)',
        'Neither the workflow nor any job restricts the GITHUB_TOKEN; depending on repository settings the default is broad write access.',
        'Add a top-level `permissions:` block with the least privilege needed (often just `contents: read`).',
      ),
    );
  }

  // WFL-005 — write-all: explicitly requesting everything.
  if (/permissions:\s*write-all/.test(raw)) {
    out.push(
      finding(
        'WFL-005',
        'high',
        file,
        lineOf(raw, 'write-all'),
        'permissions: write-all',
        'The workflow explicitly grants the token every write scope — one compromised step can push code, edit releases, and rewrite issues.',
        'Grant individual scopes (contents, issues, pull-requests…) at the job level, read-only where possible.',
      ),
    );
  }

  // WFL-006 — the trigger filters name only branches that don't exist: the
  // workflow NEVER runs (the exact bug this project shipped with — a CI that
  // doesn't run is worse than none, its badge lies). Cross-check against the
  // real repo; globs and unknown repos are skipped, silence over guessing.
  if (ctx.branches.length > 0) {
    const on = wf.on;
    if (typeof on === 'object' && on !== null && !Array.isArray(on)) {
      for (const [event, cfg] of Object.entries(on as Record<string, unknown>)) {
        if (!['push', 'pull_request'].includes(event)) continue;
        const list = (cfg as Record<string, unknown>)?.branches;
        if (!Array.isArray(list) || list.length === 0) continue;
        const names = list.map(String);
        if (names.some((b) => /[*?[]/.test(b))) continue; // glob — can't judge statically
        if (names.every((b) => !ctx.branches.includes(b))) {
          out.push(
            finding(
              'WFL-006',
              'high',
              file,
              lineOf(raw, `${event}:`),
              `The ${event} trigger only filters branches that do not exist (${names.join(', ')})`,
              'None of the filtered branches exist in this repository — the workflow never runs, and a CI that never runs is worse than none: its badge and its checks are fiction.',
              `Point the branches filter at a real branch (local branches: ${ctx.branches.slice(0, 5).join(', ')}).`,
            ),
          );
        }
      }
    }
  }

  // WFL-007 — no timeout on any job: a hung step holds the runner for GitHub's
  // 6-hour default. One finding per workflow.
  const jobsWithoutTimeout = Object.entries(allJobs).filter(([, j]) => !('timeout-minutes' in j));
  if (Object.keys(allJobs).length > 0 && jobsWithoutTimeout.length === Object.keys(allJobs).length) {
    out.push(
      finding(
        'WFL-007',
        'low',
        file,
        lineOf(raw, 'jobs:'),
        'No job sets timeout-minutes',
        'A hung step keeps the runner busy for the 6-hour default — slow feedback and burned minutes.',
        'Set `timeout-minutes` on each job (10–20 covers most builds).',
      ),
    );
  }

  // WFL-008 — push/PR workflow without a concurrency group: every push stacks
  // a redundant run. One finding per workflow.
  if ((events.has('push') || events.has('pull_request')) && !('concurrency' in wf)) {
    out.push(
      finding(
        'WFL-008',
        'low',
        file,
        1,
        'No concurrency group (redundant runs stack up)',
        'Rapid pushes queue full runs of outdated commits, wasting minutes and delaying the run that matters.',
        'Add `concurrency: { group: "${{ github.workflow }}-${{ github.ref }}", cancel-in-progress: true }`.',
      ),
    );
  }

  // WFL-009 — a gate that continues on error fails OPEN (the WFL cousin of
  // AGT-006): the badge is green exactly when the check is broken.
  for (const [jobName, job] of Object.entries(allJobs)) {
    const jobGate = GATE_NAME.test(jobName) || GATE_NAME.test(String(job.name ?? ''));
    if (job['continue-on-error'] === true && jobGate) {
      out.push(
        finding(
          'WFL-009',
          'high',
          file,
          lineOf(raw, 'continue-on-error'),
          `Gate job '${jobName}' has continue-on-error: true (fails open)`,
          'The job is a quality/security gate but its failures are swallowed — the workflow stays green exactly when the check breaks.',
          'Remove continue-on-error from gate jobs; if a step is genuinely advisory, isolate it in its own non-gate job.',
        ),
      );
    }
    for (const step of steps(job)) {
      const stepGate = GATE_NAME.test(String(step.name ?? '')) || GATE_NAME.test(String(step.run ?? '').slice(0, 60));
      if (step['continue-on-error'] === true && stepGate) {
        out.push(
          finding(
            'WFL-009',
            'high',
            file,
            lineOf(raw, 'continue-on-error'),
            `Gate step in '${jobName}' has continue-on-error: true (fails open)`,
            'A check step whose failure is swallowed reports success exactly when it is broken.',
            'Remove continue-on-error from checking steps.',
          ),
        );
      }
    }
  }

  // WFL-010 — setup-node without cache while the repo has a lockfile: every
  // run re-downloads the dependency tree. Cross-check with the real repo.
  if (ctx.hasLockfile) {
    for (const [jobName, job] of Object.entries(allJobs)) {
      for (const step of steps(job)) {
        const uses = typeof step.uses === 'string' ? step.uses : '';
        if (!uses.startsWith('actions/setup-node')) continue;
        const withBlock = (step.with ?? {}) as Record<string, unknown>;
        if (!('cache' in withBlock)) {
          out.push(
            finding(
              'WFL-010',
              'low',
              file,
              lineOf(raw, 'setup-node'),
              `setup-node in '${jobName}' has no cache despite a committed lockfile`,
              'The repository has a lockfile, so npm dependencies are cacheable — without `cache`, every run re-downloads the whole tree.',
              "Add `with: { cache: 'npm' }` (or yarn/pnpm) to actions/setup-node.",
            ),
          );
        }
      }
    }
  }

  // WFL-011 — self-hosted runner on a PR-triggered workflow: fork PRs can
  // execute code on your own infrastructure.
  if (events.has('pull_request') || events.has('pull_request_target')) {
    if (/runs-on:.*self-hosted/.test(raw)) {
      out.push(
        finding(
          'WFL-011',
          'medium',
          file,
          lineOf(raw, 'self-hosted'),
          'Self-hosted runner on a PR-triggered workflow',
          'If the repository is public (or accepts fork PRs), outside code runs on your own machine — persistence, secrets, and lateral movement are all in play.',
          'Use GitHub-hosted runners for PR triggers, or require approval for outside collaborators and isolate the runner.',
        ),
      );
    }
  }

  return out;
}

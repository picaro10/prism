#!/usr/bin/env node

import { Command } from 'commander';
import { resolve, join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { readFile as fsReadFile } from 'node:fs/promises';
import ora from 'ora';
import chalk from 'chalk';
import { runAudit, ANALYZER_CATEGORIES } from '../core/engine.js';
import { resolveTarget, isGitUrl, type ResolvedTarget } from '../core/input.js';
import { applyAiTriage } from '../ai/run.js';
import { renderCliReport } from '../reporters/cli.js';
import { writeJsonReport } from '../reporters/json.js';
import type { AnalysisCategory, PrismConfig, AuditReport, FileReader } from '../core/types.js';

// Load a .env from the current working directory if present (zero-dep, Node 20.12+).
// This is the operator's .env (cwd), NOT the analyzed project's — we never load
// the target repo's .env into PRISM's process.
try {
  if (existsSync('.env')) process.loadEnvFile('.env');
} catch {
  /* malformed .env — ignore and rely on the real environment */
}

/** Parse the --ai-vote value ("model-a,model-b,...") into model IDs. */
function parseVoteModels(value: string | boolean | undefined): string[] | undefined {
  if (!value || typeof value !== 'string') return undefined;
  const models = value
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean);
  return models.length > 0 ? models : undefined;
}

/**
 * Semantic exit codes — a stable contract for CI and coding agents:
 *   0 the audit ran and the score met the threshold
 *   1 the audit ran but the score is below the threshold (findings to fix)
 *   2 usage/config error — bad flag, missing key, unresolvable target (your fault)
 *   3 internal error — the audit threw and could not complete (our fault)
 */
const EXIT = { OK: 0, FINDINGS: 1, USAGE: 2, INTERNAL: 3 } as const;

const DEFAULT_MIN_SCORE = 6;
const CLI_VERSION = '1.0.0';

const program = new Command();

program.name('prism').description('🔍 PRISM — AI-powered project auditor by LatenciaTech').version(CLI_VERSION);

program
  .command('analyze')
  .alias('a')
  .description('Run a full audit on a project (local path, git URL, or .zip archive)')
  .argument('<target>', 'Project to analyze: local path, git URL (https/ssh), or .zip file')
  .option('--keep', 'Keep the temporary clone/extraction instead of deleting it', false)
  .option('-o, --output <format>', 'Output format: cli, json, html', 'cli')
  .option('-f, --file <path>', 'Output file path (for json output)')
  .option('--only <categories>', 'Run only specific analyzers (comma-separated)', '')
  .option('--min-score <n>', `Fail (exit 1) when the overall score is below this (default ${DEFAULT_MIN_SCORE})`)
  .option('-v, --verbose', 'Verbose output', false)
  .option(
    '--ai',
    'Run the AI triage layer — sends file snippets to an external LLM provider (requires an API key)',
    false,
  )
  .option('--ai-model <id>', 'Override the AI triage model (provider-specific default)')
  .option('--ai-provider <name>', 'AI provider: anthropic | openrouter (auto-detected from env if omitted)')
  .option('--no-ai-verify', 'Skip the adversarial re-check of false-positive verdicts')
  .option('--ai-vote <models>', 'Comma-separated model IDs that verify false positives by majority vote')
  .option('--no-ai-summary', 'Skip the AI executive summary')
  .option('--no-ai-remediate', 'Skip the AI fix proposals for confirmed-real findings')
  .option('--ai-concurrency <n>', 'Max concurrent triage calls (default 5)')
  .option('--dry-run', 'Run the AI layer with canned responses — no network, no API key (demos/tests)', false)
  .option('--junit <path>', 'Also write a JUnit XML report (findings as failed test cases) for CI')
  .action(async (target: string, options: Record<string, string | boolean>) => {
    const targetStr = String(target);

    // Local targets (paths and .zip files) must exist; git URLs are validated by the clone.
    if (!isGitUrl(targetStr) && !existsSync(resolve(targetStr))) {
      console.error(chalk.red(`\n  ✗ Path not found: ${resolve(targetStr)}\n`));
      process.exit(EXIT.USAGE);
    }

    // Validate --min-score early (usage error before doing any work).
    const minScore = options.minScore !== undefined ? Number(String(options.minScore)) : DEFAULT_MIN_SCORE;
    if (!Number.isFinite(minScore) || minScore < 0 || minScore > 10) {
      console.error(chalk.red(`\n  ✗ --min-score must be a number between 0 and 10 (got: ${options.minScore})\n`));
      process.exit(EXIT.USAGE);
    }

    // Resolve git URLs / zip archives to a local directory before scanning.
    let resolved: ResolvedTarget;
    const fetchSpinner = isGitUrl(targetStr)
      ? ora({ text: `Cloning ${targetStr}...`, prefixText: '  ' }).start()
      : /\.zip$/i.test(targetStr)
        ? ora({ text: `Extracting ${targetStr}...`, prefixText: '  ' }).start()
        : null;
    try {
      resolved = await resolveTarget(targetStr);
      fetchSpinner?.succeed(
        resolved.source === 'git'
          ? chalk.green(`Cloned to ${resolved.path}`)
          : resolved.source === 'zip'
            ? chalk.green(`Extracted to ${resolved.path}`)
            : '',
      );
      if (fetchSpinner && resolved.source === 'local') fetchSpinner.stop();
    } catch (error) {
      fetchSpinner?.fail(chalk.red(error instanceof Error ? error.message : 'Could not resolve target'));
      process.exit(EXIT.USAGE);
    }
    const absolutePath = resolved.path;

    // Fail fast on --ai without the right key, before spending the static analysis.
    // --dry-run needs no key (canned responses), so skip the check for it.
    if (options.ai && !options.dryRun) {
      const provider = options.aiProvider
        ? String(options.aiProvider)
        : process.env.ANTHROPIC_API_KEY
          ? 'anthropic'
          : 'openrouter';
      const keyVar = provider === 'openrouter' ? 'OPENROUTER_API_KEY' : 'ANTHROPIC_API_KEY';
      if (!process.env[keyVar]) {
        console.error(
          chalk.red(
            `\n  ✗ --ai with provider '${provider}' requires a ${keyVar} environment variable. Set it, or run without --ai.\n`,
          ),
        );
        process.exit(EXIT.USAGE);
      }
    }

    // Parse + validate the categories filter. An unknown value (e.g. a typo, or
    // an analyzer NAME like "secrets" instead of its category "security") would
    // otherwise silently run zero analyzers and report a false 0/10.
    const onlyStr = String(options.only || '');
    let analyzers: AnalysisCategory[] | undefined;
    if (onlyStr) {
      const requested = onlyStr
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const unknown = requested.filter((c) => !ANALYZER_CATEGORIES.includes(c as (typeof ANALYZER_CATEGORIES)[number]));
      if (unknown.length > 0) {
        console.error(
          chalk.red(
            `\n  ✗ Unknown --only categor${unknown.length > 1 ? 'ies' : 'y'}: ${unknown.join(', ')}` +
              `\n    Valid categories: ${ANALYZER_CATEGORIES.join(', ')}\n`,
          ),
        );
        process.exit(EXIT.USAGE);
      }
      analyzers = requested as AnalysisCategory[];
    }

    const config: PrismConfig = {
      targetPath: absolutePath,
      analyzers,
      output: String(options.output || 'cli') as PrismConfig['output'],
      outputPath: options.file ? String(options.file) : undefined,
      verbose: Boolean(options.verbose),
      ai: Boolean(options.ai || options.dryRun), // --dry-run implies running the AI layer (canned)
      aiDryRun: Boolean(options.dryRun),
      aiModel: options.aiModel ? String(options.aiModel) : undefined,
      aiProvider: options.aiProvider ? (String(options.aiProvider) as PrismConfig['aiProvider']) : undefined,
      aiVerify: options.aiVerify !== false, // commander sets false only on --no-ai-verify
      aiVoteModels: parseVoteModels(options.aiVote),
      aiSummary: options.aiSummary !== false, // commander sets false only on --no-ai-summary
      aiRemediate: options.aiRemediate !== false, // commander sets false only on --no-ai-remediate
      aiConcurrency: options.aiConcurrency ? Number(String(options.aiConcurrency)) : undefined,
    };

    // When JSON goes to stdout, stdout must be ONLY the JSON (so it can be piped
    // to jq / a file). Suppress the decorative banner in that case; keep it for
    // cli/html output and json-to-file.
    const jsonToStdout = config.output === 'json' && !config.outputPath;
    if (!jsonToStdout) {
      console.log('');
      console.log(chalk.bold.white('  🔍 PRISM'));
      console.log(chalk.dim('  AI-powered project auditor by LatenciaTech'));
      console.log('');
    }

    // Dispose of any temporary clone/extraction, then exit. process.exit
    // skips finally blocks, so every exit in the audit path goes through here.
    const finish = async (code: number): Promise<never> => {
      if (resolved.source !== 'local') {
        if (options.keep) {
          console.log(chalk.dim(`  Temporary copy kept at ${resolved.path}\n`));
        } else {
          await resolved.cleanup();
        }
      }
      process.exit(code);
    };

    const spinner = ora({
      text: 'Initializing audit...',
      prefixText: '  ',
    }).start();

    let aiMessage: string | undefined;
    try {
      const report = await runAudit(config, (msg) => {
        if (msg.startsWith('AI triage')) aiMessage = msg;
        if (config.verbose) {
          spinner.text = msg;
        } else {
          // Just show the main phases
          if (msg.startsWith('Scanning') || msg.startsWith('Running') || msg.startsWith('Audit complete')) {
            spinner.text = msg;
          }
        }
      });

      spinner.succeed(chalk.green(`Audit complete in ${report.durationMs}ms`));

      // Surface AI triage status when --ai was requested. To stderr so it never
      // mixes into a JSON document written to stdout.
      if (config.ai && !report.aiTriage) {
        console.error(chalk.yellow(`\n  ⚠ ${aiMessage ?? 'AI triage did not run.'}`));
      }

      // Output results
      if (config.output === 'json') {
        if (config.outputPath) {
          await writeJsonReport(report, config.outputPath);
          console.log(chalk.green(`\n  ✓ Report saved to ${config.outputPath}\n`));
        } else {
          const { formatJsonReport } = await import('../reporters/json.js');
          console.log(formatJsonReport(report));
        }
      } else if (config.output === 'html') {
        const { writeHtmlReport } = await import('../reporters/html.js');
        const outPath = config.outputPath ?? 'prism-report.html';
        await writeHtmlReport(report, outPath);
        console.log(chalk.green(`\n  ✓ HTML report saved to ${outPath}\n`));
      } else {
        renderCliReport(report);
      }

      // Optional JUnit sidecar (independent of --output). To stderr so it never
      // mixes into a JSON document on stdout.
      if (options.junit) {
        const { writeJunitReport } = await import('../reporters/junit.js');
        await writeJunitReport(report, String(options.junit));
        console.error(chalk.green(`  ✓ JUnit report saved to ${options.junit}`));
      }

      // Non-blocking update check (once/24h, opt-out via PRISM_NO_UPDATE_CHECK).
      // To stderr so it never mixes into JSON on stdout; failure is silent.
      try {
        const { checkForUpdate, defaultDeps } = await import('../core/update-check.js');
        const upd = await checkForUpdate(CLI_VERSION, defaultDeps());
        if (upd?.hasUpdate) {
          console.error(
            chalk.dim(
              `\n  ▲ PRISM ${upd.latest} is available (you have ${upd.current}) — npm i -g @latenciatech/prism`,
            ),
          );
        }
      } catch {
        /* update check must never affect the run */
      }

      // Exit code: the audit ran, so this reflects the RESULT (not an error).
      // Below the threshold → 1 (findings to fix); otherwise → 0.
      await finish(report.overallScore < minScore ? EXIT.FINDINGS : EXIT.OK);
    } catch (error) {
      spinner.fail(chalk.red('Audit failed'));
      console.error(chalk.red(`\n  ${error instanceof Error ? error.message : 'Unknown error'}\n`));
      await finish(EXIT.INTERNAL);
    }
  });

program
  .command('scan')
  .description('Quick scan — show project metadata without full audit')
  .argument('<path>', 'Path to scan')
  .action(async (targetPath: string) => {
    const absolutePath = resolve(String(targetPath));

    if (!existsSync(absolutePath)) {
      console.error(chalk.red(`\n  ✗ Path not found: ${absolutePath}\n`));
      process.exit(EXIT.USAGE);
    }

    const { scanProject } = await import('../core/scanner.js');
    const scan = await scanProject(absolutePath);

    console.log('');
    console.log(chalk.bold('  📂 Quick Scan'));
    console.log(chalk.dim('  ─────────────'));
    console.log(`  Path:       ${chalk.white(scan.rootPath)}`);
    console.log(`  Files:      ${chalk.white(String(scan.files.length))}`);
    console.log(`  Stack:      ${chalk.white(scan.meta.stack.primary)}`);
    console.log(`  Runtime:    ${chalk.white(scan.meta.stack.runtime || 'unknown')}`);
    console.log(`  Package:    ${chalk.white(scan.meta.packageManager || 'none')}`);
    console.log(`  Git:        ${scan.meta.hasGit ? chalk.green('✓') : chalk.red('✗')}`);
    console.log(`  Docker:     ${scan.meta.hasDocker ? chalk.green('✓') : chalk.red('✗')}`);
    console.log(`  CI/CD:      ${scan.meta.hasCi ? chalk.green('✓') : chalk.red('✗')}`);
    if (scan.meta.frameworks.length > 0) {
      console.log(`  Frameworks: ${chalk.white(scan.meta.frameworks.join(', '))}`);
    }
    console.log('');
  });

program
  .command('triage')
  .description('Re-run AI triage on a saved JSON report (no re-scan)')
  .argument('<reportPath>', 'Path to a JSON report produced by `analyze -o json`')
  .option('-o, --output <format>', 'Output format: cli, json, html', 'cli')
  .option('-f, --file <path>', 'Output file path (for json output)')
  .option('--ai-model <id>', 'Override the AI triage model (provider-specific default)')
  .option('--ai-provider <name>', 'AI provider: anthropic | openrouter (auto-detected from env if omitted)')
  .option('--no-ai-verify', 'Skip the adversarial re-check of false-positive verdicts')
  .option('--ai-vote <models>', 'Comma-separated model IDs that verify false positives by majority vote')
  .option('--no-ai-summary', 'Skip the AI executive summary')
  .option('--no-ai-remediate', 'Skip the AI fix proposals for confirmed-real findings')
  .option('--ai-concurrency <n>', 'Max concurrent triage calls (default 5)')
  .option('--dry-run', 'Re-triage with canned responses — no network, no API key (demos/tests)', false)
  .action(async (reportPath: string, options: Record<string, string | boolean>) => {
    const absolutePath = resolve(String(reportPath));
    if (!existsSync(absolutePath)) {
      console.error(chalk.red(`\n  ✗ Report not found: ${absolutePath}\n`));
      process.exit(EXIT.USAGE);
    }

    let report: AuditReport;
    try {
      report = JSON.parse(readFileSync(absolutePath, 'utf-8'));
    } catch {
      console.error(chalk.red('\n  ✗ Could not parse the report as JSON.\n'));
      process.exit(EXIT.USAGE);
    }
    if (!report || !Array.isArray(report.findings) || !report.projectPath) {
      console.error(chalk.red('\n  ✗ Not a valid PRISM report (missing findings/projectPath).\n'));
      process.exit(EXIT.USAGE);
    }

    // --dry-run needs no key (canned responses); otherwise require the provider key.
    if (!options.dryRun) {
      const provider = options.aiProvider
        ? String(options.aiProvider)
        : process.env.ANTHROPIC_API_KEY
          ? 'anthropic'
          : 'openrouter';
      const keyVar = provider === 'openrouter' ? 'OPENROUTER_API_KEY' : 'ANTHROPIC_API_KEY';
      if (!process.env[keyVar]) {
        console.error(
          chalk.red(`\n  ✗ triage with provider '${provider}' requires a ${keyVar} environment variable.\n`),
        );
        process.exit(EXIT.USAGE);
      }
    }

    const reader: FileReader = async (rel) => fsReadFile(join(report.projectPath, rel), 'utf-8');
    const aiConfig: Pick<
      PrismConfig,
      | 'aiModel'
      | 'aiProvider'
      | 'aiVerify'
      | 'aiSummary'
      | 'aiRemediate'
      | 'aiConcurrency'
      | 'aiVoteModels'
      | 'aiDryRun'
    > = {
      aiModel: options.aiModel ? String(options.aiModel) : undefined,
      aiProvider: options.aiProvider ? (String(options.aiProvider) as PrismConfig['aiProvider']) : undefined,
      aiVerify: options.aiVerify !== false,
      aiVoteModels: parseVoteModels(options.aiVote),
      aiSummary: options.aiSummary !== false,
      aiRemediate: options.aiRemediate !== false,
      aiDryRun: Boolean(options.dryRun),
      aiConcurrency: options.aiConcurrency ? Number(String(options.aiConcurrency)) : undefined,
    };

    console.log('');
    console.log(chalk.bold.white('  🔍 PRISM triage'));
    console.log(chalk.dim(`  ${report.projectName} · ${report.findings.length} findings`));
    console.log('');

    const spinner = ora({ text: 'Running AI triage...', prefixText: '  ' }).start();
    let aiMessage: string | undefined;
    await applyAiTriage(report, reader, aiConfig, (msg) => {
      if (msg.startsWith('AI triage')) aiMessage = msg;
      spinner.text = msg;
    });

    if (!report.aiTriage) {
      spinner.fail(chalk.red(aiMessage ?? 'AI triage did not run.'));
      process.exit(1);
    }
    spinner.succeed(chalk.green('AI triage complete'));

    if (String(options.output) === 'json') {
      if (options.file) {
        await writeJsonReport(report, String(options.file));
        console.log(chalk.green(`\n  ✓ Report saved to ${options.file}\n`));
      } else {
        const { formatJsonReport } = await import('../reporters/json.js');
        console.log(formatJsonReport(report));
      }
    } else if (String(options.output) === 'html') {
      const { writeHtmlReport } = await import('../reporters/html.js');
      const outPath = options.file ? String(options.file) : 'prism-report.html';
      await writeHtmlReport(report, outPath);
      console.log(chalk.green(`\n  ✓ HTML report saved to ${outPath}\n`));
    } else {
      renderCliReport(report);
    }
    process.exit(0);
  });

program
  .command('diff')
  .description('Compare two saved JSON reports; exit 1 if new findings appeared (regression)')
  .argument('<baseline>', 'Baseline report JSON (the "before")')
  .argument('<current>', 'Current report JSON (the "after")')
  .action(async (baselinePath: string, currentPath: string) => {
    const { diffReports } = await import('../core/diff.js');
    const { isPrismReport } = await import('../dashboard/server.js');

    const load = (p: string): AuditReport => {
      const abs = resolve(String(p));
      if (!existsSync(abs)) {
        console.error(chalk.red(`\n  ✗ Report not found: ${abs}\n`));
        process.exit(EXIT.USAGE);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(readFileSync(abs, 'utf-8'));
      } catch {
        console.error(chalk.red(`\n  ✗ Could not parse ${p} as JSON.\n`));
        process.exit(EXIT.USAGE);
      }
      if (!isPrismReport(parsed)) {
        console.error(chalk.red(`\n  ✗ ${p} is not a valid PRISM report.\n`));
        process.exit(EXIT.USAGE);
      }
      return parsed;
    };

    const baseline = load(baselinePath);
    const current = load(currentPath);
    const d = diffReports(baseline, current);

    console.log('');
    console.log(chalk.bold.white('  🔍 PRISM diff'));
    const arrow =
      d.scoreDelta > 0
        ? chalk.green(`▲ +${d.scoreDelta}`)
        : d.scoreDelta < 0
          ? chalk.red(`▼ ${d.scoreDelta}`)
          : chalk.dim('no change');
    console.log(chalk.dim(`  score ${d.baselineScore} → ${d.currentScore} (${arrow}${chalk.dim(')')}`));
    console.log('');

    if (d.added.length > 0) {
      console.log(chalk.red(`  ✗ ${d.added.length} new finding${d.added.length === 1 ? '' : 's'} (regression):`));
      for (const f of d.added) {
        console.log(
          `    ${chalk.red('+')} ${chalk.bold(f.id)} ${f.title}${f.file ? chalk.dim(` — ${f.file}${f.line ? `:${f.line}` : ''}`) : ''}`,
        );
      }
      console.log('');
    }
    if (d.removed.length > 0) {
      console.log(chalk.green(`  ✓ ${d.removed.length} resolved finding${d.removed.length === 1 ? '' : 's'}:`));
      for (const f of d.removed) {
        console.log(
          `    ${chalk.green('-')} ${chalk.bold(f.id)} ${f.title}${f.file ? chalk.dim(` — ${f.file}${f.line ? `:${f.line}` : ''}`) : ''}`,
        );
      }
      console.log('');
    }
    if (d.added.length === 0 && d.removed.length === 0) {
      console.log(chalk.dim('  No change in findings.\n'));
    }

    // Exit 1 only on a regression (new findings) — the CI-gate semantics.
    process.exit(d.added.length > 0 ? EXIT.FINDINGS : EXIT.OK);
  });

program
  .command('dashboard')
  .description('Serve a local dashboard over saved JSON reports')
  .argument('[dir]', 'Directory containing PRISM JSON reports', 'reports')
  .option('-p, --port <n>', 'Port to listen on (127.0.0.1 only)', '4180')
  .action(async (dir: string, options: Record<string, string | boolean>) => {
    const absoluteDir = resolve(String(dir));
    if (!existsSync(absoluteDir)) {
      console.error(chalk.red(`\n  ✗ Directory not found: ${absoluteDir}\n`));
      process.exit(1);
    }
    const { createDashboardServer } = await import('../dashboard/server.js');
    const { loadReports } = await import('../dashboard/server.js');
    const port = Number(String(options.port)) || 4180;
    const server = createDashboardServer(absoluteDir);
    server.listen(port, '127.0.0.1', async () => {
      const count = (await loadReports(absoluteDir)).length;
      console.log('');
      console.log(chalk.bold.white('  🔍 PRISM Dashboard'));
      console.log(chalk.dim(`  ${count} report${count === 1 ? '' : 's'} in ${absoluteDir}`));
      console.log(`\n  ${chalk.green('▸')} http://127.0.0.1:${port}\n`);
      console.log(chalk.dim('  Ctrl+C to stop. New reports in the directory appear on refresh.'));
    });
    server.on('error', (err) => {
      console.error(chalk.red(`\n  ✗ ${err.message}\n`));
      process.exit(1);
    });
  });

program
  .command('doctor')
  .description('Check the environment: Node version, git, AI keys, writable cwd')
  .action(async () => {
    const { runDoctorChecks } = await import('../core/doctor.js');
    const checks = await runDoctorChecks(process.env, process.version, process.cwd());

    console.log('');
    console.log(chalk.bold.white('  🔍 PRISM doctor'));
    console.log('');
    const icon = { ok: chalk.green('✓'), warn: chalk.yellow('⚠'), fail: chalk.red('✗') };
    for (const c of checks) {
      console.log(`  ${icon[c.status]} ${chalk.bold(c.name)} ${chalk.dim(`— ${c.detail}`)}`);
    }
    console.log('');

    const failed = checks.filter((c) => c.status === 'fail');
    if (failed.length > 0) {
      console.log(chalk.red(`  Environment not ready: ${failed.length} blocking issue(s).\n`));
      process.exit(EXIT.FINDINGS);
    }
    const warned = checks.some((c) => c.status === 'warn');
    console.log(warned ? chalk.yellow('  Usable, with warnings above.\n') : chalk.green('  All good.\n'));
    process.exit(EXIT.OK);
  });

const agent = program.command('agent').description('Integrate PRISM into a coding agent');
agent
  .command('install')
  .description('Install the PRISM verification skill into an agent rule file (CLAUDE.md, AGENTS.md, .cursorrules)')
  .argument('<target>', 'Agent: claude | cursor | codex | agents')
  .option('-d, --dir <path>', 'Project directory to install into', '.')
  .option('--min-score <n>', `Score threshold the skill instructs the agent to meet (default ${DEFAULT_MIN_SCORE})`)
  .action(async (target: string, options: Record<string, string>) => {
    const { installAgentSkill, AGENT_TARGETS } = await import('../agent/install.js');
    if (!AGENT_TARGETS[String(target)]) {
      console.error(chalk.red(`\n  ✗ Unknown agent '${target}'. Valid: ${Object.keys(AGENT_TARGETS).join(', ')}\n`));
      process.exit(EXIT.USAGE);
    }
    const minScore = options.minScore !== undefined ? Number(String(options.minScore)) : DEFAULT_MIN_SCORE;
    if (!Number.isFinite(minScore) || minScore < 0 || minScore > 10) {
      console.error(chalk.red(`\n  ✗ --min-score must be a number between 0 and 10 (got: ${options.minScore})\n`));
      process.exit(EXIT.USAGE);
    }
    try {
      const result = await installAgentSkill(String(target), String(options.dir ?? '.'), minScore);
      console.log('');
      console.log(chalk.green(`  ✓ ${result.action === 'created' ? 'Created' : 'Updated'} ${result.file}`));
      console.log(chalk.dim(`  ${result.label} will now run PRISM before finishing a task.\n`));
    } catch (err) {
      console.error(chalk.red(`\n  ✗ ${err instanceof Error ? err.message : 'install failed'}\n`));
      process.exit(EXIT.INTERNAL);
    }
  });

const finding = program.command('finding').description('Work with individual findings from a saved report');
finding
  .command('get')
  .description('Print a self-contained JSON bundle for one finding (for a coding agent to auto-fix)')
  .argument('<reportPath>', 'Path to a JSON report produced by `analyze -o json`')
  .argument('<findingKey>', 'The finding key, e.g. "SEC-ENV-VALUE|src/config.ts|4"')
  .option('--context <n>', 'Lines of code context around the flagged line (default 3)', '3')
  .action(async (reportPath: string, key: string, options: Record<string, string>) => {
    const abs = resolve(String(reportPath));
    if (!existsSync(abs)) {
      console.error(chalk.red(`\n  ✗ Report not found: ${abs}\n`));
      process.exit(EXIT.USAGE);
    }
    const { isPrismReport } = await import('../dashboard/server.js');
    let report: AuditReport;
    try {
      const parsed = JSON.parse(readFileSync(abs, 'utf-8'));
      if (!isPrismReport(parsed)) {
        console.error(chalk.red('\n  ✗ Not a valid PRISM report.\n'));
        process.exit(EXIT.USAGE);
      }
      report = parsed;
    } catch {
      console.error(chalk.red('\n  ✗ Could not parse the report as JSON.\n'));
      process.exit(EXIT.USAGE);
    }

    const parsedContext = Number.parseInt(String(options.context ?? '3'), 10);
    const context = Number.isFinite(parsedContext) && parsedContext >= 0 ? parsedContext : 3;
    const { buildFindingBundle, findByKey } = await import('../core/finding-bundle.js');

    const match = findByKey(report, String(key));
    if (!match) {
      console.error(chalk.red(`\n  ✗ No finding with key '${key}' in this report.\n`));
      process.exit(EXIT.USAGE);
    }
    // Read the flagged file (best effort — a report moved off its machine may
    // not have it). The bundle degrades to a null snippet rather than failing.
    let fileContent: string | null = null;
    if (match.file) {
      try {
        fileContent = await fsReadFile(join(report.projectPath, match.file), 'utf-8');
      } catch {
        fileContent = null;
      }
    }

    const bundle = buildFindingBundle(report, String(key), fileContent, context);
    if (!bundle) {
      console.error(chalk.red(`\n  ✗ No finding with key '${key}' in this report.\n`));
      process.exit(EXIT.USAGE);
    }
    // JSON only on stdout so an agent can pipe it straight to a parser.
    console.log(JSON.stringify(bundle, null, 2));
    process.exit(EXIT.OK);
  });

program.parse();

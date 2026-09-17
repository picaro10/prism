import type { Command } from 'commander';
import { resolve, join } from 'node:path';
import { existsSync } from 'node:fs';
import ora from 'ora';
import chalk from 'chalk';
import { runAudit, ANALYZER_CATEGORIES } from '../../core/engine.js';
import { resolveTarget, isGitUrl, type ResolvedTarget } from '../../core/input.js';
import { renderCliReport } from '../../reporters/cli.js';
import { writeJsonReport } from '../../reporters/json.js';
import type { PrismConfig } from '../../core/types.js';
import { EXIT, DEFAULT_MIN_SCORE, CLI_VERSION, usageError } from '../shared.js';

export function registerAnalyzeCommand(program: Command): void {
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
    .option('--fail-on <severity>', 'Fail when any finding is at or above this severity (critical|high|medium|low)')
    .option('--max-critical <n>', 'Fail when there are more than N critical findings')
    .option('--max-high <n>', 'Fail when there are more than N high findings')
    .option(
      '--baseline <ref>',
      'New-code gate: apply severity rules only to findings NOT in this baseline (a git ref like origin/main, or a saved .json report)',
    )
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
    .option('--no-ai-cache', 'Judge every finding again instead of reusing cached verdicts for unchanged code')
    .option('--dry-run', 'Run the AI layer with canned responses — no network, no API key (demos/tests)', false)
    .option('--junit <path>', 'Also write a JUnit XML report (findings as failed test cases) for CI')
    .option('--sarif <path>', 'Also write a SARIF 2.1.0 report (for GitHub Code Scanning, VS Code, etc.)')
    .option('--config <path>', 'Explicit config file (default: prism.config.json / .prismrc.json in the target root)')
    .option('--no-config', 'Ignore any config file')
    .action(async (target: string, options: Record<string, string | boolean>, command: Command) => {
      const targetStr = String(target);

      // Local targets (paths and .zip files) must exist; git URLs are validated by the clone.
      if (!isGitUrl(targetStr) && !existsSync(resolve(targetStr))) {
        usageError(`Path not found: ${resolve(targetStr)}`);
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

      // Load the persistent config file (prism.config.json / .prismrc.json).
      // Explicit --config always wins; --no-config skips discovery. Discovery
      // only trusts LOCAL targets: a cloned/extracted third-party repo must not
      // get to pick its own gates or suppress its own findings.
      const { loadConfigFile, resolveEffectiveOptions, validateEffectiveOptions, CONFIG_FILENAMES } = await import(
        '../../core/config-file.js'
      );
      let fileConfig: import('../../core/config-file.js').PrismFileConfig | null = null;
      let fileConfigPath: string | undefined;
      if (options.config !== false) {
        try {
          if (typeof options.config === 'string') {
            const loaded = loadConfigFile(process.cwd(), options.config);
            fileConfig = loaded?.config ?? null;
            fileConfigPath = loaded?.path;
          } else if (resolved.source === 'local') {
            const loaded = loadConfigFile(absolutePath);
            fileConfig = loaded?.config ?? null;
            fileConfigPath = loaded?.path;
          } else if (CONFIG_FILENAMES.some((name) => existsSync(join(resolved.path, name)))) {
            console.error(
              chalk.dim(
                '  A config file inside the cloned/extracted target was ignored (remote targets cannot set their own gates); pass --config to use one.',
              ),
            );
          }
        } catch (err) {
          usageError(err instanceof Error ? err.message : 'could not load config file');
        }
      }

      // Effective options: explicit CLI flag > config file > built-in default.
      const isCliSet = (name: string): boolean => command.getOptionValueSource(name) === 'cli';
      const eff = resolveEffectiveOptions(fileConfig, options, isCliSet);

      // Validate the effective values (CLI-origin ones are unchecked strings; the
      // file side was already schema-validated, so these double as flag checks).
      const optionErrors = validateEffectiveOptions(eff);
      const { SEVERITIES } = await import('../../core/quality-gate.js');
      const failOn = eff.failOn;
      if (failOn && !SEVERITIES.includes(failOn)) {
        optionErrors.push(`--fail-on must be one of: ${SEVERITIES.join(', ')} (got: ${failOn})`);
      }
      if (optionErrors.length > 0) {
        usageError(...optionErrors);
      }
      const minScore = eff.minScore;
      // An unknown category (e.g. a typo, or an analyzer NAME like "secrets"
      // instead of its category "security") would otherwise silently run zero
      // analyzers and report a false 0/10.
      if (eff.categories) {
        const unknown = eff.categories.filter(
          (c) => !ANALYZER_CATEGORIES.includes(c as (typeof ANALYZER_CATEGORIES)[number]),
        );
        if (unknown.length > 0) {
          usageError(
            `Unknown --only categor${unknown.length > 1 ? 'ies' : 'y'}: ${unknown.join(', ')}`,
            `Valid categories: ${ANALYZER_CATEGORIES.join(', ')}`,
          );
        }
      }

      // Fail fast on --ai without the right key, before spending the static analysis.
      // --dry-run needs no key (canned responses), so skip the check for it.
      if (eff.ai && !options.dryRun) {
        const provider = eff.aiProvider ?? (process.env.ANTHROPIC_API_KEY ? 'anthropic' : 'openrouter');
        const keyVar = provider === 'openrouter' ? 'OPENROUTER_API_KEY' : 'ANTHROPIC_API_KEY';
        if (!process.env[keyVar]) {
          usageError(
            `--ai with provider '${provider}' requires a ${keyVar} environment variable. Set it, or run without --ai.`,
          );
        }
      }

      const config: PrismConfig = {
        targetPath: absolutePath,
        analyzers: eff.categories,
        output: eff.output,
        outputPath: eff.outputFile,
        verbose: eff.verbose,
        ai: Boolean(eff.ai || options.dryRun), // --dry-run implies running the AI layer (canned)
        aiDryRun: Boolean(options.dryRun),
        aiModel: eff.aiModel,
        aiProvider: eff.aiProvider,
        aiVerify: eff.aiVerify,
        aiVoteModels: eff.aiVoteModels,
        aiSummary: eff.aiSummary,
        aiRemediate: eff.aiRemediate,
        aiConcurrency: eff.aiConcurrency,
        // A clone or an extracted zip is a throwaway directory: verdicts keyed
        // by its path would never be reused, so only local targets get the cache.
        aiCache: eff.aiCache && resolved.source === 'local',
        suppressions: eff.suppressions,
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
      if (fileConfigPath) {
        console.error(chalk.dim(`  Using config ${fileConfigPath}`));
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

        // Expired/stale suppression notices — the whole point of `expires` is
        // that exceptions resurface instead of rotting silently. Stderr only.
        for (const w of report.suppressionWarnings ?? []) {
          console.error(chalk.yellow(`  ⚠ ${w}`));
        }

        // Output results
        if (config.output === 'json') {
          if (config.outputPath) {
            await writeJsonReport(report, config.outputPath);
            console.log(chalk.green(`\n  ✓ Report saved to ${config.outputPath}\n`));
          } else {
            const { formatJsonReport } = await import('../../reporters/json.js');
            console.log(formatJsonReport(report));
          }
        } else if (config.output === 'html') {
          const { writeHtmlReport } = await import('../../reporters/html.js');
          const outPath = config.outputPath ?? 'prism-report.html';
          await writeHtmlReport(report, outPath);
          console.log(chalk.green(`\n  ✓ HTML report saved to ${outPath}\n`));
        } else {
          renderCliReport(report);
        }

        // Optional JUnit sidecar (independent of --output). To stderr so it never
        // mixes into a JSON document on stdout.
        if (eff.junit) {
          const { writeJunitReport } = await import('../../reporters/junit.js');
          await writeJunitReport(report, eff.junit);
          console.error(chalk.green(`  ✓ JUnit report saved to ${eff.junit}`));
        }
        if (eff.sarif) {
          const { writeSarifReport } = await import('../../reporters/sarif.js');
          await writeSarifReport(report, eff.sarif);
          console.error(chalk.green(`  ✓ SARIF report saved to ${eff.sarif}`));
        }

        // Non-blocking update check (once/24h, opt-out via PRISM_NO_UPDATE_CHECK).
        // To stderr so it never mixes into JSON on stdout; failure is silent.
        try {
          const { checkForUpdate, defaultDeps } = await import('../../core/update-check.js');
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

        // New-code gate: when --baseline is set, severity rules apply only to
        // findings NOT already in the baseline (old debt doesn't gate; new code
        // must not add). --min-score still applies to the whole project's score.
        let gateReport = report;
        if (eff.baseline) {
          try {
            const { resolveBaselineReport } = await import('../../core/baseline.js');
            const { diffByFingerprint, reportOfFindings } = await import('../../core/new-code-gate.js');
            const baseline = await resolveBaselineReport(eff.baseline, absolutePath);
            const d = diffByFingerprint(baseline, report);
            console.error(
              chalk.dim(
                `\n  Baseline '${eff.baseline}': ${report.findings.length} total · ${d.existingCount} existing · ` +
                  `${chalk.bold(`${d.newFindings.length} new`)} · ${d.fixedFindings.length} fixed`,
              ),
            );
            gateReport = reportOfFindings(report, d.newFindings);
          } catch (err) {
            console.error(chalk.red(`\n  ✗ ${err instanceof Error ? err.message : 'baseline resolution failed'}\n`));
            await finish(EXIT.USAGE);
          }
        }

        // Exit code: the audit ran, so this reflects the RESULT (not an error).
        // Evaluate the quality gate — score AND per-severity rules, so a single
        // new critical can't hide behind a good average.
        const { evaluateQualityGate } = await import('../../core/quality-gate.js');
        const gate = evaluateQualityGate(gateReport, {
          minScore,
          failOn,
          maxCritical: eff.maxCritical,
          maxHigh: eff.maxHigh,
        });
        if (!gate.passed) {
          console.error(chalk.red('\n  ✗ Quality gate failed:'));
          for (const r of gate.reasons) console.error(chalk.red(`    · ${r}`));
          console.error('');
          await finish(EXIT.FINDINGS);
        }
        await finish(EXIT.OK);
      } catch (error) {
        spinner.fail(chalk.red('Audit failed'));
        console.error(chalk.red(`\n  ${error instanceof Error ? error.message : 'Unknown error'}\n`));
        await finish(EXIT.INTERNAL);
      }
    });
}

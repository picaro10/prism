import type { Command } from 'commander';
import ora from 'ora';
import chalk from 'chalk';
import { applyAiTriage } from '../../ai/run.js';
import { renderCliReport } from '../../reporters/cli.js';
import { writeJsonReport } from '../../reporters/json.js';
import type { PrismConfig, FileReader } from '../../core/types.js';
import { parseVoteModels, usageError, loadReportOrExit, checkReportRoot } from '../shared.js';

export function registerTriageCommand(program: Command): void {
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
    .option('--no-ai-cache', 'Judge every finding again instead of reusing cached verdicts for unchanged code')
    .option('--dry-run', 'Re-triage with canned responses — no network, no API key (demos/tests)', false)
    .option(
      '--root <path>',
      'Project root to read code from (required when the path recorded in the report is outside the current directory)',
    )
    .action(async (reportPath: string, options: Record<string, string | boolean>) => {
      const report = await loadReportOrExit(String(reportPath));

      // Same flag validation as analyze — commander passes any string through.
      const { OUTPUT_FORMATS, AI_PROVIDERS } = await import('../../core/config-file.js');
      const triageErrors: string[] = [];
      if (!OUTPUT_FORMATS.includes(String(options.output) as (typeof OUTPUT_FORMATS)[number])) {
        triageErrors.push(`--output must be one of: ${OUTPUT_FORMATS.join(', ')} (got: ${options.output})`);
      }
      if (options.aiProvider && !AI_PROVIDERS.includes(String(options.aiProvider) as (typeof AI_PROVIDERS)[number])) {
        triageErrors.push(`--ai-provider must be one of: ${AI_PROVIDERS.join(', ')} (got: ${options.aiProvider})`);
      }
      const triageConcurrency = options.aiConcurrency ? Number(String(options.aiConcurrency)) : undefined;
      if (triageConcurrency !== undefined && (!Number.isInteger(triageConcurrency) || triageConcurrency < 1)) {
        triageErrors.push(`--ai-concurrency must be an integer ≥ 1 (got: ${options.aiConcurrency})`);
      }
      if (triageErrors.length > 0) {
        usageError(...triageErrors);
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
          usageError(`triage with provider '${provider}' requires a ${keyVar} environment variable.`);
        }
      }

      // The report is untrusted input: reads are confined to the project root
      // (no absolute paths, no ../ escapes) — but the report also NAMES that
      // root, so it is only honored inside the current directory; anything
      // else needs an explicit --root. Snippets go to the AI provider, so say
      // out loud which directory is about to be read.
      const rootCheck = checkReportRoot(report.projectPath, options.root ? String(options.root) : undefined);
      if ('reason' in rootCheck) {
        usageError(
          `Refusing to read code: ${rootCheck.reason}`,
          'A saved report is untrusted input — PRISM only follows its recorded path into the current directory.',
          'Run triage from inside the project, or assert the root explicitly with --root <path>.',
        );
      }
      const { confinedReader } = await import('../../utils/safe-read.js');
      console.error(chalk.dim(`  Reading code from ${rootCheck.root}`));
      const reader: FileReader = confinedReader(rootCheck.root);
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
        | 'aiCache'
      > = {
        aiModel: options.aiModel ? String(options.aiModel) : undefined,
        aiProvider: options.aiProvider ? (String(options.aiProvider) as PrismConfig['aiProvider']) : undefined,
        aiVerify: options.aiVerify !== false,
        aiVoteModels: parseVoteModels(options.aiVote),
        aiSummary: options.aiSummary !== false,
        aiRemediate: options.aiRemediate !== false,
        aiDryRun: Boolean(options.dryRun),
        aiConcurrency: triageConcurrency,
        aiCache: options.aiCache !== false,
      };

      console.log('');
      console.log(chalk.bold.white('  🔍 PRISM triage'));
      console.log(chalk.dim(`  ${report.projectName} · ${report.findings.length} findings`));
      console.log('');

      const spinner = ora({ text: 'Running AI triage...', prefixText: '  ' }).start();
      let aiMessage: string | undefined;
      await applyAiTriage(
        report,
        reader,
        aiConfig,
        (msg) => {
          if (msg.startsWith('AI triage')) aiMessage = msg;
          spinner.text = msg;
        },
        undefined,
        rootCheck.root,
      );

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
          const { formatJsonReport } = await import('../../reporters/json.js');
          console.log(formatJsonReport(report));
        }
      } else if (String(options.output) === 'html') {
        const { writeHtmlReport } = await import('../../reporters/html.js');
        const outPath = options.file ? String(options.file) : 'prism-report.html';
        await writeHtmlReport(report, outPath);
        console.log(chalk.green(`\n  ✓ HTML report saved to ${outPath}\n`));
      } else {
        renderCliReport(report);
      }
      process.exit(0);
    });
}

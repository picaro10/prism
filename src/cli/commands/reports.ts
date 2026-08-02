import type { Command } from 'commander';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import chalk from 'chalk';
import { EXIT, loadReportOrExit } from '../shared.js';

/** `scan` — quick project metadata without a full audit. */
export function registerScanCommand(program: Command): void {
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

      const { scanProject } = await import('../../core/scanner.js');
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
}

/** `diff` — compare two saved reports; exit 1 on regression. */
export function registerDiffCommand(program: Command): void {
  program
    .command('diff')
    .description('Compare two saved JSON reports; exit 1 if new findings appeared (regression)')
    .argument('<baseline>', 'Baseline report JSON (the "before")')
    .argument('<current>', 'Current report JSON (the "after")')
    .action(async (baselinePath: string, currentPath: string) => {
      const { diffReports } = await import('../../core/diff.js');

      const baseline = await loadReportOrExit(baselinePath);
      const current = await loadReportOrExit(currentPath);
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
}

/** `finding get` — a self-contained JSON bundle for one finding. */
export function registerFindingCommand(program: Command): void {
  const finding = program.command('finding').description('Work with individual findings from a saved report');
  finding
    .command('get')
    .description('Print a self-contained JSON bundle for one finding (for a coding agent to auto-fix)')
    .argument('<reportPath>', 'Path to a JSON report produced by `analyze -o json`')
    .argument('<findingKey>', 'The finding key, e.g. "SEC-ENV-VALUE|src/config.ts|4"')
    .option('--context <n>', 'Lines of code context around the flagged line (default 3)', '3')
    .action(async (reportPath: string, key: string, options: Record<string, string>) => {
      const report = await loadReportOrExit(reportPath);

      const parsedContext = Number.parseInt(String(options.context ?? '3'), 10);
      const context = Number.isFinite(parsedContext) && parsedContext >= 0 ? parsedContext : 3;
      const { buildFindingBundle, findByKey } = await import('../../core/finding-bundle.js');

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
          // Confined read — the report (and the file paths inside it) is
          // untrusted input and must not reach outside its own projectPath.
          const { confinedReader } = await import('../../utils/safe-read.js');
          fileContent = await confinedReader(report.projectPath)(match.file);
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
}

/** `dashboard` — local server over saved reports. */
export function registerDashboardCommand(program: Command): void {
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
      const { createDashboardServer, loadReports } = await import('../../dashboard/server.js');
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
}

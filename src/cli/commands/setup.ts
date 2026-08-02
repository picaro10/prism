import type { Command } from 'commander';
import { resolve, join } from 'node:path';
import { existsSync } from 'node:fs';
import chalk from 'chalk';
import { EXIT, DEFAULT_MIN_SCORE, usageError } from '../shared.js';

/** `doctor` — environment checks. */
export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Check the environment: Node version, git, semgrep, AI keys, writable cwd')
    .action(async () => {
      const { runDoctorChecks } = await import('../../core/doctor.js');
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
}

/** `init` — write a prism.config.json (wizard on a TTY). */
export function registerInitCommand(program: Command): void {
  program
    .command('init')
    .description('Create a prism.config.json — interactive wizard on a TTY, sensible defaults otherwise')
    .option('-d, --dir <path>', 'Directory to write the config into', '.')
    .option('-y, --yes', 'Skip the wizard and write the default config', false)
    .option('--force', 'Overwrite an existing config file', false)
    .action(async (options: Record<string, string | boolean>) => {
      const dir = resolve(String(options.dir ?? '.'));
      if (!existsSync(dir)) {
        usageError(`Directory not found: ${dir}`);
      }
      const outPath = join(dir, 'prism.config.json');
      if (existsSync(outPath) && !options.force) {
        usageError(`${outPath} already exists. Use --force to overwrite.`);
      }

      const { defaultFileConfig, buildConfigViaWizard, renderConfigJson } = await import('../init.js');

      let config: import('../../core/config-file.js').PrismFileConfig;
      const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY && !options.yes);
      if (interactive) {
        console.log('');
        console.log(chalk.bold.white('  🔍 PRISM init'));
        console.log(
          chalk.dim('  Enter accepts the [default]. The file is prism.config.json; flags always override it.'),
        );
        console.log('');
        const { createInterface } = await import('node:readline/promises');
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        try {
          config = await buildConfigViaWizard(async (q, def) =>
            rl.question(`  ${q}${def ? chalk.dim(` [${def}]`) : ''}: `),
          );
        } finally {
          rl.close();
        }
      } else {
        config = defaultFileConfig();
      }

      const { writeFile } = await import('node:fs/promises');
      await writeFile(outPath, renderConfigJson(config), 'utf-8');
      console.log('');
      console.log(chalk.green(`  ✓ Wrote ${outPath}`));
      console.log(chalk.dim('  From now on `prism analyze .` uses it; any CLI flag still wins.'));
      console.log(
        chalk.dim(
          '  Accept a reviewed finding with a justified suppression: {"rule": "SEC-001", "file": "tests/**", "reason": "why", "expires": "YYYY-MM-DD"}\n',
        ),
      );
      process.exit(EXIT.OK);
    });
}

/** `agent install` — install the PRISM skill into an agent rule file. */
export function registerAgentCommand(program: Command): void {
  const agent = program.command('agent').description('Integrate PRISM into a coding agent');
  agent
    .command('install')
    .description('Install the PRISM verification skill into an agent rule file (CLAUDE.md, AGENTS.md, .cursorrules)')
    .argument('<target>', 'Agent: claude | cursor | codex | agents')
    .option('-d, --dir <path>', 'Project directory to install into', '.')
    .option('--min-score <n>', `Score threshold the skill instructs the agent to meet (default ${DEFAULT_MIN_SCORE})`)
    .action(async (target: string, options: Record<string, string>) => {
      const { installAgentSkill, AGENT_TARGETS } = await import('../../agent/install.js');
      if (!AGENT_TARGETS[String(target)]) {
        usageError(`Unknown agent '${target}'. Valid: ${Object.keys(AGENT_TARGETS).join(', ')}`);
      }
      const minScore = options.minScore !== undefined ? Number(String(options.minScore)) : DEFAULT_MIN_SCORE;
      if (!Number.isFinite(minScore) || minScore < 0 || minScore > 10) {
        usageError(`--min-score must be a number between 0 and 10 (got: ${options.minScore})`);
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
}

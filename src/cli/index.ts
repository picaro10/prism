#!/usr/bin/env node

import { Command } from 'commander';
import { existsSync } from 'node:fs';
import { CLI_VERSION } from './shared.js';
import { registerAnalyzeCommand } from './commands/analyze.js';
import { registerTriageCommand } from './commands/triage.js';
import {
  registerScanCommand,
  registerDiffCommand,
  registerFindingCommand,
  registerDashboardCommand,
} from './commands/reports.js';
import { registerDoctorCommand, registerInitCommand, registerAgentCommand } from './commands/setup.js';

// Load a .env from the current working directory if present (zero-dep, Node 20.12+).
// This is the operator's .env (cwd), NOT the analyzed project's — we never load
// the target repo's .env into PRISM's process.
try {
  if (existsSync('.env')) process.loadEnvFile('.env');
} catch {
  /* malformed .env — ignore and rely on the real environment */
}

const program = new Command();

program.name('prism').description('🔍 PRISM — AI-powered project auditor by LatenciaTech').version(CLI_VERSION);

registerAnalyzeCommand(program);
registerScanCommand(program);
registerTriageCommand(program);
registerDiffCommand(program);
registerDashboardCommand(program);
registerDoctorCommand(program);
registerInitCommand(program);
registerAgentCommand(program);
registerFindingCommand(program);

program.parse();

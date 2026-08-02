#!/usr/bin/env node

import { Command } from 'commander';
import { CLI_VERSION, loadAllowlistedEnv } from './shared.js';
import { registerAnalyzeCommand } from './commands/analyze.js';
import { registerTriageCommand } from './commands/triage.js';
import {
  registerScanCommand,
  registerDiffCommand,
  registerFindingCommand,
  registerDashboardCommand,
} from './commands/reports.js';
import { registerDoctorCommand, registerInitCommand, registerAgentCommand } from './commands/setup.js';

// Pick up API keys from a .env in the current working directory. In the most
// common invocation (`cd project && prism analyze .`) that file IS the
// analyzed project's .env — untrusted input — so it is NOT loaded wholesale:
// only the variables PRISM itself consumes are imported (AI provider keys and
// PRISM_* settings), and the real environment always wins over the file.
loadAllowlistedEnv('.env');

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

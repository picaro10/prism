import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';

/** Rule-file targets PRISM can install its verification skill into. */
export const AGENT_TARGETS: Record<string, { file: string; label: string }> = {
  claude: { file: 'CLAUDE.md', label: 'Claude Code' },
  cursor: { file: '.cursorrules', label: 'Cursor' },
  codex: { file: 'AGENTS.md', label: 'Codex' },
  agents: { file: 'AGENTS.md', label: 'AGENTS.md (generic)' },
};

const MARK_START = '<!-- prism:start -->';
const MARK_END = '<!-- prism:end -->';

/**
 * The verification skill body (between the managed markers). Instructs a coding
 * agent to gate task completion on PRISM's exit code. Pure — depends only on
 * the threshold so the same input always yields the same block.
 */
export function buildSkillBlock(minScore: number): string {
  return [
    MARK_START,
    '## Verify with PRISM before finishing',
    '',
    'Before considering any coding task complete, audit the project and resolve regressions:',
    '',
    '```sh',
    `prism analyze . --output json --min-score ${minScore}`,
    '```',
    '',
    '- **Exit 0** — the project meets the quality bar; you may finish.',
    '- **Exit 1** — the score is below the bar. Read the JSON, fix the *real* findings',
    '  (PRISM hunts false positives, but verify), and re-run until it exits 0.',
    '- **Exit 2 or 3** — you invoked PRISM wrong, or it errored; fix the invocation.',
    '',
    'Do not mark a task done while `prism analyze` reports a regression you introduced.',
    MARK_END,
  ].join('\n');
}

/**
 * Insert or replace the managed PRISM block in an existing file's content,
 * leaving everything else untouched. If no managed block exists yet, the block
 * is appended (with a blank-line separator when the file is non-empty).
 */
export function upsertManagedBlock(existing: string, block: string): string {
  const start = existing.indexOf(MARK_START);
  const end = existing.indexOf(MARK_END);
  if (start !== -1 && end !== -1 && end > start) {
    const before = existing.slice(0, start);
    const after = existing.slice(end + MARK_END.length);
    return `${before}${block}${after}`;
  }
  if (existing.trim() === '') return `${block}\n`;
  return `${existing.replace(/\s*$/, '')}\n\n${block}\n`;
}

export interface InstallResult {
  file: string;
  label: string;
  action: 'created' | 'updated';
}

/**
 * Install (or refresh) the PRISM verification skill into a target agent's rule
 * file within `dir`. Returns the file written and whether it was created or
 * updated. Throws on an unknown target.
 */
export async function installAgentSkill(target: string, dir: string, minScore: number): Promise<InstallResult> {
  const spec = AGENT_TARGETS[target];
  if (!spec) {
    throw new Error(`Unknown agent target '${target}'. Valid: ${Object.keys(AGENT_TARGETS).join(', ')}`);
  }
  const filePath = resolve(join(dir, spec.file));
  const existed = existsSync(filePath);
  const existing = existed ? await readFile(filePath, 'utf-8') : '';
  const next = upsertManagedBlock(existing, buildSkillBlock(minScore));
  await writeFile(filePath, next, 'utf-8');
  return { file: spec.file, label: spec.label, action: existed ? 'updated' : 'created' };
}

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSkillBlock, upsertManagedBlock, installAgentSkill, AGENT_TARGETS } from '../../src/agent/install.js';

const dirs: string[] = [];
afterEach(async () => {
  while (dirs.length) await rm(dirs.pop()!, { recursive: true, force: true }).catch(() => {});
});
async function tmp(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), 'prism-agent-'));
  dirs.push(d);
  return d;
}

describe('buildSkillBlock', () => {
  it('wraps the skill in managed markers and includes the threshold', () => {
    const block = buildSkillBlock(7);
    expect(block.startsWith('<!-- prism:start -->')).toBe(true);
    expect(block.trimEnd().endsWith('<!-- prism:end -->')).toBe(true);
    expect(block).toContain('--min-score 7');
  });
});

describe('upsertManagedBlock', () => {
  it('appends the block to a non-empty file, preserving existing content', () => {
    const out = upsertManagedBlock('# My rules\n\nBe nice.', buildSkillBlock(6));
    expect(out).toContain('# My rules');
    expect(out).toContain('Be nice.');
    expect(out).toContain('<!-- prism:start -->');
  });

  it('replaces an existing managed block without touching user content', () => {
    const first = upsertManagedBlock('# Rules\n\nKeep this.', buildSkillBlock(6));
    const second = upsertManagedBlock(first, buildSkillBlock(9));
    expect(second).toContain('Keep this.');
    expect(second).toContain('--min-score 9');
    expect(second).not.toContain('--min-score 6');
    // exactly one managed block after re-install
    expect(second.split('<!-- prism:start -->').length - 1).toBe(1);
  });

  it('handles an empty file cleanly', () => {
    const out = upsertManagedBlock('', buildSkillBlock(6));
    expect(out.startsWith('<!-- prism:start -->')).toBe(true);
  });
});

describe('installAgentSkill', () => {
  it('creates the rule file for a fresh project', async () => {
    const dir = await tmp();
    const result = await installAgentSkill('claude', dir, 6);
    expect(result).toMatchObject({ file: 'CLAUDE.md', action: 'created' });
    const content = await readFile(join(dir, 'CLAUDE.md'), 'utf-8');
    expect(content).toContain('Verify with PRISM');
  });

  it('updates an existing file and preserves user content', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'AGENTS.md'), '# Team rules\n\nUse tabs.', 'utf-8');
    const result = await installAgentSkill('codex', dir, 8);
    expect(result.action).toBe('updated');
    const content = await readFile(join(dir, 'AGENTS.md'), 'utf-8');
    expect(content).toContain('Use tabs.');
    expect(content).toContain('--min-score 8');
  });

  it('maps each known target to its rule file', () => {
    expect(AGENT_TARGETS.claude.file).toBe('CLAUDE.md');
    expect(AGENT_TARGETS.cursor.file).toBe('.cursorrules');
    expect(AGENT_TARGETS.codex.file).toBe('AGENTS.md');
  });

  it('rejects an unknown target', async () => {
    const dir = await tmp();
    await expect(installAgentSkill('emacs', dir, 6)).rejects.toThrow(/Unknown agent target/);
  });
});

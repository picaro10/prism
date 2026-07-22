import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfigFile, resolveEffectiveOptions, DEFAULT_MIN_SCORE } from '../../src/core/config-file.js';
import type { PrismFileConfig } from '../../src/core/config-file.js';

function tempDirWith(name: string, content: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'prism-config-'));
  writeFileSync(join(dir, name), typeof content === 'string' ? content : JSON.stringify(content));
  return dir;
}

describe('loadConfigFile', () => {
  it('returns null when no config file exists', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-config-'));
    try {
      expect(loadConfigFile(dir)).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('loads and validates prism.config.json', () => {
    const dir = tempDirWith('prism.config.json', {
      minScore: 8,
      categories: ['security', 'tests'],
      ai: { enabled: true, provider: 'openrouter', model: 'openai/gpt-4.1-mini' },
      output: { format: 'html', file: './reports/prism.html' },
      suppressions: [{ rule: 'SEC-001', file: 'tests/**', reason: 'fixture', expires: '2027-01-01' }],
    });
    try {
      const loaded = loadConfigFile(dir);
      expect(loaded).not.toBeNull();
      expect(loaded!.path.endsWith('prism.config.json')).toBe(true);
      expect(loaded!.config.minScore).toBe(8);
      expect(loaded!.config.categories).toEqual(['security', 'tests']);
      expect(loaded!.config.ai?.provider).toBe('openrouter');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('falls back to .prismrc.json when prism.config.json is absent', () => {
    const dir = tempDirWith('.prismrc.json', { minScore: 7 });
    try {
      const loaded = loadConfigFile(dir);
      expect(loaded!.path.endsWith('.prismrc.json')).toBe(true);
      expect(loaded!.config.minScore).toBe(7);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects malformed JSON with a descriptive error', () => {
    const dir = tempDirWith('prism.config.json', '{ nope ');
    try {
      expect(() => loadConfigFile(dir)).toThrow(/not valid JSON/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects unknown keys (typo protection)', () => {
    const dir = tempDirWith('prism.config.json', { minscore: 8 });
    try {
      expect(() => loadConfigFile(dir)).toThrow(/minscore/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects invalid values: bad category, bad severity, out-of-range score', () => {
    for (const bad of [
      { categories: ['secrets'] }, // analyzer NAME, not a category
      { failOn: 'catastrophic' },
      { minScore: 11 },
      { suppressions: [{ rule: 'SEC-001', reason: '' }] }, // empty reason
      { suppressions: [{ rule: 'SEC-001', reason: 'r', expires: 'someday' }] },
    ]) {
      const dir = tempDirWith('prism.config.json', bad);
      try {
        expect(() => loadConfigFile(dir)).toThrow();
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it('loads an explicit path and throws if it is missing', () => {
    const dir = tempDirWith('custom.json', { minScore: 9 });
    try {
      const loaded = loadConfigFile(dir, join(dir, 'custom.json'));
      expect(loaded!.config.minScore).toBe(9);
      expect(() => loadConfigFile(dir, join(dir, 'missing.json'))).toThrow(/not found/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('resolveEffectiveOptions', () => {
  const file: PrismFileConfig = {
    minScore: 8,
    categories: ['security'],
    failOn: 'critical',
    output: { format: 'json', file: 'out.json', sarif: 'out.sarif' },
    ai: { enabled: true, provider: 'openrouter', model: 'm-file', verify: false, concurrency: 3, vote: ['a', 'b'] },
    verbose: true,
    suppressions: [{ rule: 'SEC-001', reason: 'r' }],
  };

  it('uses file values when the CLI did not set the flag', () => {
    const eff = resolveEffectiveOptions(file, {}, () => false);
    expect(eff.minScore).toBe(8);
    expect(eff.categories).toEqual(['security']);
    expect(eff.failOn).toBe('critical');
    expect(eff.output).toBe('json');
    expect(eff.outputFile).toBe('out.json');
    expect(eff.sarif).toBe('out.sarif');
    expect(eff.ai).toBe(true);
    expect(eff.aiProvider).toBe('openrouter');
    expect(eff.aiModel).toBe('m-file');
    expect(eff.aiVerify).toBe(false);
    expect(eff.aiConcurrency).toBe(3);
    expect(eff.aiVoteModels).toEqual(['a', 'b']);
    expect(eff.verbose).toBe(true);
    expect(eff.suppressions).toHaveLength(1);
  });

  it('lets an explicit CLI flag beat the file', () => {
    const cli = { minScore: '5', output: 'cli', only: 'tests,docker', aiModel: 'm-cli' };
    const set = (name: string) => ['minScore', 'output', 'only', 'aiModel'].includes(name);
    const eff = resolveEffectiveOptions(file, cli, set);
    expect(eff.minScore).toBe(5);
    expect(eff.output).toBe('cli');
    expect(eff.categories).toEqual(['tests', 'docker']);
    expect(eff.aiModel).toBe('m-cli');
    // untouched flags still come from the file
    expect(eff.failOn).toBe('critical');
    expect(eff.ai).toBe(true);
  });

  it('applies built-in defaults with no file and no flags', () => {
    const eff = resolveEffectiveOptions(null, {}, () => false);
    expect(eff.minScore).toBe(DEFAULT_MIN_SCORE);
    expect(eff.output).toBe('cli');
    expect(eff.ai).toBe(false);
    expect(eff.aiVerify).toBe(true);
    expect(eff.aiSummary).toBe(true);
    expect(eff.aiRemediate).toBe(true);
    expect(eff.categories).toBeUndefined();
    expect(eff.suppressions).toEqual([]);
  });

  it('lets --no-ai-verify beat ai.verify=true in the file', () => {
    const f: PrismFileConfig = { ai: { enabled: true, verify: true } };
    const eff = resolveEffectiveOptions(f, { aiVerify: false }, (n) => n === 'aiVerify');
    expect(eff.aiVerify).toBe(false);
  });
});

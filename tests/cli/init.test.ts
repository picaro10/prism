import { describe, it, expect } from 'vitest';
import { buildConfigViaWizard, defaultFileConfig, renderConfigJson } from '../../src/cli/init.js';
import { loadConfigFile } from '../../src/core/config-file.js';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Drive the wizard with a scripted list of answers ('' = accept default). */
function scripted(answers: string[]): (q: string, def: string) => Promise<string> {
  let i = 0;
  return async (_q, def) => {
    const a = answers[i] ?? '';
    i += 1;
    return a === '' ? def : a;
  };
}

describe('defaultFileConfig', () => {
  it('produces a config that validates against the file schema', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-init-'));
    try {
      writeFileSync(join(dir, 'prism.config.json'), renderConfigJson(defaultFileConfig()));
      const loaded = loadConfigFile(dir);
      expect(loaded!.config.minScore).toBe(6);
      expect(loaded!.config.failOn).toBe('critical');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('buildConfigViaWizard', () => {
  it('accepting every default yields the minimal config', async () => {
    const config = await buildConfigViaWizard(scripted([]));
    expect(config.minScore).toBe(6);
    expect(config.failOn).toBe('critical');
    expect(config.categories).toBeUndefined();
    expect(config.ai).toBeUndefined();
    expect(config.output).toEqual({ format: 'cli' });
    expect(config.suppressions).toEqual([]);
  });

  it('captures custom answers: categories, AI provider+model, html output with file', async () => {
    const config = await buildConfigViaWizard(
      scripted(['8', 'high', 'security,tests', 'openrouter', 'openai/gpt-4.1-mini', 'html', 'reports/audit.html']),
    );
    expect(config.minScore).toBe(8);
    expect(config.failOn).toBe('high');
    expect(config.categories).toEqual(['security', 'tests']);
    expect(config.ai).toEqual({ enabled: true, provider: 'openrouter', model: 'openai/gpt-4.1-mini' });
    expect(config.output).toEqual({ format: 'html', file: 'reports/audit.html' });
  });

  it('"none" answers omit failOn and ai', async () => {
    const config = await buildConfigViaWizard(scripted(['6', 'none', 'all', 'none', 'cli']));
    expect(config.failOn).toBeUndefined();
    expect(config.ai).toBeUndefined();
  });

  it('re-asks on an invalid answer and takes the next valid one', async () => {
    const config = await buildConfigViaWizard(scripted(['15', '9', 'nope', 'critical', 'all', 'none', 'cli']));
    expect(config.minScore).toBe(9);
    expect(config.failOn).toBe('critical');
  });

  it('the wizard result validates against the file schema', async () => {
    const config = await buildConfigViaWizard(scripted(['8', 'high', 'security', 'anthropic', '', 'json', '']));
    const dir = mkdtempSync(join(tmpdir(), 'prism-init-'));
    try {
      writeFileSync(join(dir, 'prism.config.json'), renderConfigJson(config));
      const loaded = loadConfigFile(dir);
      expect(loaded!.config.ai?.provider).toBe('anthropic');
      expect(loaded!.config.output?.file).toBe('reports/prism-report.json');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

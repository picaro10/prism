import { describe, it, expect } from 'vitest';
import { parseNodeMajor, checkNodeVersion, checkApiKeys, runDoctorChecks } from '../../src/core/doctor.js';

describe('parseNodeMajor', () => {
  it('extracts the major version', () => {
    expect(parseNodeMajor('v22.1.0')).toBe(22);
    expect(parseNodeMajor('24.0.0')).toBe(24);
    expect(Number.isNaN(parseNodeMajor('garbage'))).toBe(true);
  });
});

describe('checkNodeVersion', () => {
  it('passes for a supported version', () => {
    expect(checkNodeVersion('v22.0.0', 22).status).toBe('ok');
  });
  it('fails for an unsupported version', () => {
    expect(checkNodeVersion('v18.0.0', 22).status).toBe('fail');
  });
  it('warns on an unparseable version', () => {
    expect(checkNodeVersion('weird', 22).status).toBe('warn');
  });
});

describe('checkApiKeys', () => {
  it('is ok when a provider key is present', () => {
    expect(checkApiKeys({ OPENROUTER_API_KEY: 'x' }).status).toBe('ok');
    expect(checkApiKeys({ ANTHROPIC_API_KEY: 'x' }).status).toBe('ok');
  });
  it('warns (not fails) when no key is set — static analysis still works', () => {
    expect(checkApiKeys({}).status).toBe('warn');
  });
});

describe('runDoctorChecks', () => {
  it('returns a check per environment concern', async () => {
    const checks = await runDoctorChecks({ OPENROUTER_API_KEY: 'x' }, 'v22.0.0', process.cwd());
    const names = checks.map((c) => c.name);
    expect(names).toContain('Node.js');
    expect(names).toContain('git');
    expect(names).toContain('AI provider key');
    expect(names).toContain('writable cwd');
    expect(checks.every((c) => ['ok', 'warn', 'fail'].includes(c.status))).toBe(true);
  });
});

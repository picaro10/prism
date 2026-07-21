import { describe, it, expect } from 'vitest';
import { classifyFile, isSecurityTool, adjustSeverity, isExcludedContext } from '../../src/utils/file-context.js';

describe('classifyFile', () => {
  it('classifies normal source files as source', () => {
    expect(classifyFile('src/index.ts')).toBe('source');
    expect(classifyFile('src/core/engine.ts')).toBe('source');
    expect(classifyFile('lib/utils.py')).toBe('source');
  });

  it('classifies test files as test', () => {
    expect(classifyFile('tests/core/engine.test.ts')).toBe('test');
    expect(classifyFile('src/__tests__/utils.spec.js')).toBe('test');
    expect(classifyFile('test/unit/auth_test.py')).toBe('test');
  });

  it('classifies fixtures as fixture', () => {
    expect(classifyFile('tests/fixtures/sample-project/config.ts')).toBe('fixture');
    expect(classifyFile('tests/__fixtures__/data.json')).toBe('fixture');
    expect(classifyFile('testdata/input.json')).toBe('fixture');
  });

  it('classifies template/example/asset files as template', () => {
    expect(classifyFile('skills/tdd-guide/assets/sample_input.json')).toBe('template');
    expect(classifyFile('examples/basic-usage.ts')).toBe('template');
    expect(classifyFile('templates/email.html')).toBe('template');
    expect(classifyFile('src/sample_config.ts')).toBe('template');
  });

  it('classifies documentation as documentation', () => {
    expect(classifyFile('README.md')).toBe('documentation');
    expect(classifyFile('CHANGELOG.md')).toBe('documentation');
    expect(classifyFile('docs/setup.md')).toBe('documentation');
  });

  it('classifies config templates correctly', () => {
    expect(classifyFile('.env.example')).toBe('config-template');
    expect(classifyFile('.env.template')).toBe('config-template');
    expect(classifyFile('.env.sample')).toBe('config-template');
  });

  it('classifies vendor directories as vendor', () => {
    expect(classifyFile('vendor/lib/something.js')).toBe('vendor');
    expect(classifyFile('third-party/lodash.js')).toBe('vendor');
    expect(classifyFile('node_modules/some-pkg/index.js')).toBe('vendor');
  });

  it('classifies generated directories as generated', () => {
    expect(classifyFile('dist/index.js')).toBe('generated');
    expect(classifyFile('.next/server/page.js')).toBe('generated');
    expect(classifyFile('build/output.js')).toBe('generated');
  });

  it('classifies __generated__ directories as generated (GraphQL / Prisma / Apollo codegen)', () => {
    expect(classifyFile('src/graphql/__generated__/operations.ts')).toBe('generated');
  });

  // ORION-specific: skills with assets should be classified as template
  it('classifies skill assets as template (ORION pattern)', () => {
    expect(classifyFile('skills/engineering-skills/tdd-guide/assets/sample_input_typescript.json')).toBe('template');
    expect(classifyFile('skills/docx/scripts/templates/comments.xml')).toBe('template');
  });
});

describe('isSecurityTool', () => {
  it('detects a file with multiple security detection patterns', () => {
    const content = `
      const patterns = [
        r"-----BEGIN PRIVATE KEY-----",
        r"AKIA[0-9A-Z]{16}",
        r"password\\s*[:=]",
        r"api_key\\s*[:=]",
        r"secret\\s*[:=]",
      ];
    `;
    expect(isSecurityTool(content)).toBe(true);
  });

  it('does not flag normal source code', () => {
    const content = `
      const config = {
        port: 3000,
        host: 'localhost',
      };
      export function startServer() {
        console.log('Starting...');
      }
    `;
    expect(isSecurityTool(content)).toBe(false);
  });

  it('does not flag a file with just one security-related word', () => {
    const content = `
      // Check the user's password
      if (password !== expected) throw new Error('Invalid');
    `;
    expect(isSecurityTool(content)).toBe(false);
  });

  it('does not flag an auth file whose secret words are plain error messages (would hide a real leak)', () => {
    // Three secret-related words, all as prose in error strings, plus a REAL
    // hardcoded key. Must NOT be treated as a security tool, or the secret scan
    // gets skipped on exactly this kind of file.
    const content = `
      export async function login(user, pass) {
        if (!user) throw new Error('Invalid token');
        if (!pass) throw new Error('missing password');
        const API_KEY = 'sk-proj-REALSECRETabcdef1234567890';
        const res = await fetch(url, { headers: { Authorization: 'Bearer secret not found' } });
        return res;
      }
    `;
    expect(isSecurityTool(content)).toBe(false);
  });
});

describe('adjustSeverity', () => {
  it('keeps full severity for source files', () => {
    expect(adjustSeverity('critical', 'source')).toBe('critical');
    expect(adjustSeverity('high', 'source')).toBe('high');
  });

  it('downgrades severity for test files', () => {
    expect(adjustSeverity('critical', 'test')).toBe('medium');
    expect(adjustSeverity('high', 'test')).toBe('low');
    expect(adjustSeverity('medium', 'test')).toBe('info');
  });

  it('returns null (skip) for fixtures, templates, security tools', () => {
    expect(adjustSeverity('critical', 'fixture')).toBeNull();
    expect(adjustSeverity('critical', 'template')).toBeNull();
    expect(adjustSeverity('critical', 'security-tool')).toBeNull();
    expect(adjustSeverity('critical', 'documentation')).toBeNull();
    expect(adjustSeverity('critical', 'generated')).toBeNull();
    expect(adjustSeverity('critical', 'vendor')).toBeNull();
  });
});

describe('isExcludedContext', () => {
  it('excludes non-user-authored contexts', () => {
    expect(isExcludedContext('fixture')).toBe(true);
    expect(isExcludedContext('template')).toBe(true);
    expect(isExcludedContext('config-template')).toBe(true);
    expect(isExcludedContext('documentation')).toBe(true);
    expect(isExcludedContext('generated')).toBe(true);
    expect(isExcludedContext('vendor')).toBe(true);
    expect(isExcludedContext('security-tool')).toBe(true);
  });

  it('does NOT exclude real source or test code', () => {
    expect(isExcludedContext('source')).toBe(false);
    expect(isExcludedContext('test')).toBe(false);
  });
});

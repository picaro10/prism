import { describe, it, expect } from 'vitest';
import { resolve, join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { scanProject } from '../../src/core/scanner.js';
import {
  ConsistencyAnalyzer,
  classifyNamingConvention,
  detectSpanishTokens,
  detectIndentation,
} from '../../src/analyzers/consistency.js';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

describe('classifyNamingConvention', () => {
  it('classifies kebab-case', () => {
    expect(classifyNamingConvention('user-service')).toBe('kebab');
  });
  it('classifies snake_case', () => {
    expect(classifyNamingConvention('user_service')).toBe('snake');
  });
  it('classifies camelCase', () => {
    expect(classifyNamingConvention('userService')).toBe('camel');
  });
  it('classifies PascalCase', () => {
    expect(classifyNamingConvention('UserService')).toBe('pascal');
  });
  it('classifies a single lowercase word as lower', () => {
    expect(classifyNamingConvention('index')).toBe('lower');
  });
});

describe('detectSpanishTokens', () => {
  it('finds Spanish words in camelCase identifiers', () => {
    const tokens = detectSpanishTokens('function guardarUsuario(datos) {}');
    expect(tokens).toContain('guardar');
    expect(tokens).toContain('usuario');
    expect(tokens).toContain('datos');
  });

  it('finds Spanish words in comments', () => {
    const tokens = detectSpanishTokens('// guarda el archivo en el servidor');
    expect(tokens).toContain('archivo');
    expect(tokens).toContain('servidor');
  });

  it('returns empty for purely English code', () => {
    expect(detectSpanishTokens('function saveUser(data) { return data; }')).toEqual([]);
  });

  it('does not match English/Spanish homographs like "error" or "total"', () => {
    expect(detectSpanishTokens('const total = error;')).toEqual([]);
  });
});

describe('detectIndentation', () => {
  it('detects space indentation', () => {
    expect(detectIndentation('function f() {\n    return 1;\n}')).toBe('spaces');
  });
  it('detects tab indentation', () => {
    expect(detectIndentation('function f() {\n\treturn 1;\n}')).toBe('tabs');
  });
  it('detects mixed indentation', () => {
    expect(detectIndentation('function f() {\n    a();\n\tb();\n}')).toBe('mixed');
  });
  it('returns none when there is no indentation', () => {
    expect(detectIndentation('const a = 1;\nconst b = 2;')).toBe('none');
  });
});

describe('ConsistencyAnalyzer', () => {
  const analyzer = new ConsistencyAnalyzer();

  async function runAnalysis() {
    const scan = await scanProject(FIXTURE_PATH);
    const fileReader = async (p: string) => readFile(join(FIXTURE_PATH, p), 'utf-8');
    return analyzer.analyze(scan, fileReader);
  }

  it('returns the consistency category', async () => {
    const result = await runAnalysis();
    expect(result.category).toBe('consistency');
  });

  it('returns a score between 0 and 10', async () => {
    const result = await runAnalysis();
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(10);
  });

  it('all findings have required fields and the consistency category', async () => {
    const result = await runAnalysis();
    for (const finding of result.findings) {
      expect(finding.id).toBeTruthy();
      expect(finding.category).toBe('consistency');
      expect(finding.severity).toBeTruthy();
      expect(finding.title).toBeTruthy();
      expect(finding.description).toBeTruthy();
    }
  });

  it('produces a summary', async () => {
    const result = await runAnalysis();
    expect(result.summary).toBeTruthy();
  });

  it('reports mixed-language (CON-002) at low severity — it may be an intentional localized domain', async () => {
    const files = ['a.ts', 'b.ts', 'c.ts'];
    const scan = {
      rootPath: '/fake',
      files,
      fileTree: [],
      meta: {} as never,
    };
    // Every file mixes Spanish domain words with English keywords.
    const reader = async () => 'export function guardarUsuario(datos) { const archivo = datos; return archivo; }';
    const result = await analyzer.analyze(scan as never, reader);
    const con002 = result.findings.find((f) => f.id === 'CON-002');
    expect(con002).toBeDefined();
    expect(con002?.severity).toBe('low');
  });
});

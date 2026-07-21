import { describe, it, expect } from 'vitest';
import {
  buildSystemPrompt,
  buildRemediationSystemPrompt,
  buildProjectContextBlock,
  buildUserContent,
} from '../../src/ai/prompt.js';
import type { TriageUnit, ProjectContext } from '../../src/ai/types.js';

const ctx: ProjectContext = {
  projectName: 'demo',
  stack: 'typescript',
  overallScore: 7.5,
  categorySummaries: ['security: 8.0 — clean', 'tests: 6.0 — low ratio'],
};

describe('buildSystemPrompt', () => {
  it('states the triage job and the three classifications', () => {
    const p = buildSystemPrompt();
    expect(p).toMatch(/false-positive/);
    expect(p).toMatch(/real/);
    expect(p).toMatch(/uncertain/);
    expect(p.toLowerCase()).toMatch(/fixture|generated|test/);
    expect(p.toLowerCase()).toMatch(/findingkey|finding key/);
  });
});

describe('buildRemediationSystemPrompt', () => {
  it('asks for concrete fixes with effort levels and findingKey echo', () => {
    const p = buildRemediationSystemPrompt();
    expect(p.toLowerCase()).toMatch(/fix/);
    expect(p).toMatch(/"low"/);
    expect(p).toMatch(/"medium"/);
    expect(p).toMatch(/"high"/);
    expect(p.toLowerCase()).toMatch(/findingkey/);
    expect(p.toLowerCase()).toMatch(/do not invent|not supported by the code/);
  });
});

describe('buildProjectContextBlock', () => {
  it('includes project name, stack, score and category summaries', () => {
    const b = buildProjectContextBlock(ctx);
    expect(b).toMatch(/demo/);
    expect(b).toMatch(/typescript/);
    expect(b).toMatch(/7\.5/);
    expect(b).toMatch(/low ratio/);
  });
});

describe('buildUserContent', () => {
  it('includes the file path, content, and each finding with its key', () => {
    const unit: TriageUnit = {
      file: 'src/a.ts',
      content: 'const SECRET = "abc";',
      findings: [
        {
          id: 'SEC-001',
          category: 'security',
          severity: 'high',
          title: 'Hardcoded secret',
          description: 'd',
          file: 'src/a.ts',
          line: 1,
        },
      ],
    };
    const c = buildUserContent(unit);
    expect(c).toMatch(/src\/a\.ts/);
    expect(c).toMatch(/const SECRET/);
    expect(c).toMatch(/SEC-001\|src\/a\.ts\|1/);
    expect(c).toMatch(/Hardcoded secret/);
  });

  it('quotes the exact flagged line next to its finding', () => {
    const unit: TriageUnit = {
      file: 'docker-compose.yml',
      content: 'services:\n  app:\n    ports:\n      - "3000:3000"',
      findings: [
        {
          id: 'DOC-024',
          category: 'docker',
          severity: 'medium',
          title: 'Port exposed on all interfaces',
          description: 'd',
          file: 'docker-compose.yml',
          line: 4,
        },
      ],
    };
    const c = buildUserContent(unit);
    expect(c).toMatch(/flagged line 4 reads exactly: "- \\"3000:3000\\""/);
  });

  it('omits the flagged-line quote when content is missing or the line is blank', () => {
    const f = {
      id: 'X',
      category: 'docker' as const,
      severity: 'low' as const,
      title: 't',
      description: 'd',
      file: 'a.yml',
      line: 3,
    };
    const noContent = buildUserContent({ file: 'a.yml', content: '', findings: [f] });
    expect(noContent).not.toMatch(/reads exactly/);
    const blankLine = buildUserContent({ file: 'a.yml', content: 'a\nb\n   \nc', findings: [f] });
    expect(blankLine).not.toMatch(/reads exactly/);
  });

  it('handles a project-level unit with no file', () => {
    const unit: TriageUnit = {
      file: null,
      content: '',
      findings: [{ id: 'TST-001', category: 'tests', severity: 'critical', title: 'No tests', description: 'd' }],
    };
    const c = buildUserContent(unit);
    expect(c).toMatch(/TST-001/);
    expect(c).toMatch(/project-level|no file/i);
  });

  it('truncates very large file content', () => {
    const big = 'x\n'.repeat(40000); // 80k chars > 60k MAX_CONTENT_CHARS
    const unit: TriageUnit = { file: 'big.ts', content: big, findings: [] };
    const c = buildUserContent(unit);
    expect(c.length).toBeLessThan(big.length);
    expect(c).toMatch(/truncated/i);
  });
});

import type { TriageUnit, ProjectContext } from './types.js';
import { findingKey } from './types.js';

/** Max characters of file content sent per triage call (bounds token cost). */
const MAX_CONTENT_CHARS = 60_000;

export function buildSystemPrompt(): string {
  return [
    'You are a senior security and code-quality reviewer triaging the findings of a static',
    'analyzer (PRISM). The static layer flags patterns; your job is to judge each finding in',
    'context by reading the actual code.',
    '',
    'For each finding, classify it as exactly one of:',
    '- "real": a genuine issue worth a human\'s attention.',
    '- "false-positive": the pattern matched but, given the code and project context, it is not',
    '  a real problem (e.g. a Docker mount path mistaken for a hardcoded secret; a finding on a',
    '  test fixture, generated file, or template; an intentional, documented choice).',
    '- "uncertain": you cannot tell from the available context.',
    '',
    'Guidance: findings on fixtures, generated code, templates, or vendored code are almost',
    'always false positives. A value that is a file path or env-var reference is not a hardcoded',
    'secret. Be skeptical but fair — do not call a genuine issue a false positive just because',
    'it is low severity.',
    '',
    'For every finding you are given, return one verdict object. Echo back the exact findingKey',
    'string you were given for that finding. Keep reasoning to one or two sentences.',
  ].join('\n');
}

export function buildVerificationSystemPrompt(): string {
  return [
    'You are double-checking findings that a first reviewer flagged as FALSE POSITIVES.',
    'First reviewers are sometimes too lenient and occasionally invent a justification, so do',
    'not trust the prior call. Re-examine each finding against the actual code below.',
    '',
    'A finding is "false-positive" ONLY if you can point to concrete, specific evidence in the',
    'code that it is benign (quote the exact line or construct). If you cannot cite such',
    'evidence — or the evidence is ambiguous — do NOT confirm the false positive:',
    '- classify it "real" if the underlying issue genuinely applies, or',
    '- classify it "uncertain" if you cannot tell.',
    '',
    'Do not fabricate details (e.g. claiming a port is bound to localhost when the line does not',
    'say so). For every finding, return one verdict, echoing back its findingKey, with reasoning',
    'that cites the concrete evidence for your call.',
  ].join('\n');
}

export function buildRemediationSystemPrompt(): string {
  return [
    'You are a senior engineer writing a remediation guide. Every finding below was confirmed',
    'as a REAL issue by a prior triage that read the code — do not re-judge it, fix it.',
    '',
    'For each finding, propose ONE concrete fix: what to change, where, and how. Be specific',
    'to the actual code below — name the file, line, directive, or config key, and include a',
    'short snippet of the corrected line when it helps. Prefer the minimal change that resolves',
    'the issue; mention a deeper refactor only if the minimal fix is a dead end. Do not invent',
    'APIs, flags, or file contents not supported by the code you were given.',
    '',
    'Rate the effort honestly: "low" (minutes, mechanical), "medium" (an hour or two, needs',
    'local understanding), "high" (a refactor or design change).',
    '',
    'For every finding, return one remediation object, echoing back the exact findingKey string',
    'you were given. Keep each fix to a few sentences plus an optional short snippet.',
  ].join('\n');
}

export function buildSummarySystemPrompt(): string {
  return [
    'You are a senior engineer writing a short executive assessment of a project for its',
    'maintainer, based on a static audit and its AI triage. Write 1–2 tight paragraphs (plain',
    'prose, no headings, no bullet lists).',
    '',
    'Lead with the overall health and the single most important thing to address. Focus on the',
    'findings confirmed as real — do NOT dwell on false positives. Be honest and specific',
    '(name the concrete issues that matter); do not pad, flatter, or invent problems. If the',
    'project is in good shape, say so plainly. Write for a busy human who wants the verdict fast.',
  ].join('\n');
}

export function buildProjectContextBlock(ctx: ProjectContext): string {
  return [
    `Project: ${ctx.projectName}`,
    `Stack: ${ctx.stack}`,
    `Overall static score: ${ctx.overallScore}/10`,
    'Category summaries:',
    ...ctx.categorySummaries.map((s) => `  - ${s}`),
  ].join('\n');
}

export function buildUserContent(unit: TriageUnit, heading = 'Findings to triage:'): string {
  const parts: string[] = [];

  if (unit.file) {
    parts.push(`File: ${unit.file}`);
    let content = unit.content;
    if (content.length > MAX_CONTENT_CHARS) {
      content = `${content.slice(0, MAX_CONTENT_CHARS)}\n… [content truncated]`;
    }
    parts.push('```');
    parts.push(content);
    parts.push('```');
  } else {
    parts.push('These are project-level findings (no specific file).');
  }

  parts.push('');
  parts.push(heading);
  const contentLines = unit.content ? unit.content.split('\n') : [];
  for (const f of unit.findings) {
    parts.push(`- findingKey: ${findingKey(f)}`);
    parts.push(`  id: ${f.id} | severity: ${f.severity} | title: ${f.title}`);
    parts.push(`  description: ${f.description}`);
    if (f.line !== undefined) {
      parts.push(`  line: ${f.line}`);
      // Quote the exact flagged line so the model judges THIS line, not a
      // similar-looking one elsewhere in the file (seen in production: a
      // verdict citing another service's port binding to excuse this one).
      const text = contentLines[f.line - 1];
      if (text !== undefined && text.trim() !== '') {
        parts.push(`  flagged line ${f.line} reads exactly: ${JSON.stringify(text.trim().slice(0, 200))}`);
      }
    }
    if (f.meta) parts.push(`  meta: ${JSON.stringify(f.meta)}`);
  }

  return parts.join('\n');
}

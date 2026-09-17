import { extname } from 'node:path';
import type { FileReader, Finding } from '../core/types.js';
import { contextTierFor } from '../core/rule-metadata.js';
import {
  GRAPH_SOURCE_EXTS,
  extractImports,
  resolveAliasSpecifier,
  resolveSpecifier,
  stripComments,
  type AliasConfig,
} from '../utils/import-graph.js';
import { parseTsconfigAliases } from '../utils/dead-files.js';

/**
 * Neighborhood context — the evidence a per-file judge cannot see.
 *
 * A line-level rule fires inside one file, but the thing that makes the
 * finding benign often lives in another: the executor that gates every
 * destructive tool, the validator whose body rejects shell metacharacters,
 * the assertion helper that calls expect(). Measured on the AI benchmark,
 * the judge caught 1 of 3 such cases with the file alone — and said why:
 * "without seeing validate.js we cannot confirm".
 *
 * This module picks those related files DETERMINISTICALLY — no model in the
 * loop — from the import graph, in two directions:
 *
 * - IMPORTS of the flagged file: a module is relevant when one of the names
 *   imported from it is used within a window around a flagged line (the
 *   validator called three lines above the exec, the helper called inside
 *   the test).
 * - IMPORTERS of the flagged file: a module is relevant when it imports the
 *   flagged file AND mentions an anchor token from a flagged line (the tool
 *   name string, the exported function) — the executor that gates the tool
 *   table it imports.
 *
 * Bounded on every axis (neighbors per unit, chars per neighbor, chars in
 * total), ordered by evidence strength then path, and silent when nothing
 * qualifies: a finding with no usable neighbors is judged exactly as before.
 * TS/JS only — the import resolver is; other languages fall back to the file.
 */

export interface Neighbor {
  file: string;
  content: string;
  /** Why this file was brought in — shown to the judge so the link is explicit. */
  reason: string;
}

/** Lines above/below a flagged line in which an imported name counts as "used here". */
export const NEIGHBOR_WINDOW_LINES = 40;
export const MAX_NEIGHBORS = 4;
export const MAX_NEIGHBOR_CHARS = 12_000;
export const MAX_NEIGHBORHOOD_CHARS = 30_000;

/** One import statement of the flagged file: the local names it binds and where they come from. */
export interface ImportBinding {
  names: string[];
  specifier: string;
}

/**
 * Extract import bindings with their local names. Handles `import a from`,
 * `import { a, b as c } from`, `import * as ns from`, mixed default+named,
 * and `const { a } = require('x')` / `const x = require('x')`. Type-only
 * statements are skipped (a type cannot gate anything at runtime).
 */
export function extractImportBindings(source: string): ImportBinding[] {
  const src = stripComments(source);
  const out: ImportBinding[] = [];
  const esm = /\bimport\s+(type\s+)?([^'";]*?)\s*from\s*['"]([^'"]+)['"]/g;
  for (const m of src.matchAll(esm)) {
    if (m[1]) continue;
    const names = clauseNames(m[2]);
    if (names.length > 0) out.push({ names, specifier: m[3] });
  }
  const cjs = /\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of src.matchAll(cjs)) {
    const names = clauseNames(m[1]);
    if (names.length > 0) out.push({ names, specifier: m[2] });
  }
  return out;
}

function clauseNames(clause: string): string[] {
  const names: string[] = [];
  let rest = clause.trim();
  const star = /\*\s+as\s+([A-Za-z_$][\w$]*)/.exec(rest);
  if (star) {
    names.push(star[1]);
    rest = rest.replace(star[0], '');
  }
  const braces = /\{([^}]*)\}/.exec(rest);
  if (braces) {
    for (const part of braces[1].split(',')) {
      const p = part.trim().replace(/^type\s+/, '');
      if (!p) continue;
      const as = /\bas\s+([A-Za-z_$][\w$]*)$/.exec(p);
      names.push(as ? as[1] : p.replace(/^[^A-Za-z_$]*/, '').split(/[^\w$]/)[0]);
    }
    rest = rest.replace(braces[0], '');
  }
  for (const piece of rest.split(',')) {
    const p = piece.trim();
    if (/^[A-Za-z_$][\w$]*$/.test(p)) names.push(p);
  }
  return names.filter(Boolean);
}

const STOP_WORDS = new Set([
  'const',
  'let',
  'var',
  'function',
  'return',
  'await',
  'async',
  'export',
  'import',
  'from',
  'default',
  'this',
  'true',
  'false',
  'null',
  'undefined',
  'string',
  'number',
  'boolean',
  'object',
  'name',
  'type',
  'description',
  'parameters',
  'properties',
  'required',
  'value',
  'data',
  'error',
  'result',
  'console',
  'process',
]);

/**
 * Anchor tokens of a flagged line: string literals (≥ 3 chars) and
 * identifiers (≥ 4 chars, not keywords/boilerplate). An importer that
 * mentions one of them is talking about the flagged thing.
 */
export function anchorTokens(line: string): string[] {
  const tokens = new Set<string>();
  for (const m of line.matchAll(/['"`]([^'"`]{3,80})['"`]/g)) tokens.add(m[1]);
  for (const m of line.matchAll(/\b[A-Za-z_$][\w$]{3,}\b/g)) {
    if (!STOP_WORDS.has(m[0])) tokens.add(m[0]);
  }
  return [...tokens];
}

/**
 * Code with comments and string contents removed but template-literal
 * interpolations KEPT: `git log ${ref}` must not make a module named `log`
 * look used, while `${sanitize(cmd)}` must still count as a use of sanitize.
 */
export function codeOnly(text: string): string {
  return (
    stripComments(text)
      .replace(/`(?:\\.|\$\{[^}]*\}|[^`\\])*`/g, (tpl) => {
        const exprs = [...tpl.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]);
        return `"" ${exprs.join(' ')} ""`;
      })
      .replace(/(["'])(?:\\.|(?!\1)[^\n\\])*\1/g, '""')
      // The import statements themselves are not uses: `import { log } from ""`
      // mentions log without running anything through it.
      .replace(/\bimport\s+[^;]*?\bfrom\s*""/g, ' ')
      .replace(/\b(?:const|let|var)\s+(?:\{[^}]*\}|[\w$]+)\s*=\s*require\(\s*""\s*\)/g, ' ')
  );
}

/** The import graph slice the neighborhood needs, built once per triage. */
export interface NeighborhoodIndex {
  fileSet: Set<string>;
  aliases: AliasConfig[];
  /** target file → files that import it (relative or alias, value or type). */
  importers: Map<string, Set<string>>;
}

export async function buildNeighborhoodIndex(files: string[], readFile: FileReader): Promise<NeighborhoodIndex> {
  const fileSet = new Set(files);
  const aliases: AliasConfig[] = [];
  for (const file of files) {
    if (!/(^|\/)tsconfig[^/]*\.json$/.test(file)) continue;
    try {
      const parsed = parseTsconfigAliases(await readFile(file), file);
      if (parsed && parsed !== 'unparseable') aliases.push(parsed);
    } catch {
      // unreadable tsconfig: aliases from it are simply unknown
    }
  }
  const importers = new Map<string, Set<string>>();
  for (const file of files) {
    if (!(GRAPH_SOURCE_EXTS as readonly string[]).includes(extname(file))) continue;
    let content: string;
    try {
      content = await readFile(file);
    } catch {
      continue;
    }
    for (const edge of extractImports(content)) {
      const target = resolveTarget(file, edge.specifier, fileSet, aliases);
      if (!target || target === file) continue;
      const set = importers.get(target) ?? new Set<string>();
      set.add(file);
      importers.set(target, set);
    }
  }
  return { fileSet, aliases, importers };
}

function resolveTarget(
  importer: string,
  specifier: string,
  fileSet: Set<string>,
  aliases: AliasConfig[],
): string | null {
  return specifier.startsWith('.')
    ? resolveSpecifier(importer, specifier, fileSet)
    : resolveAliasSpecifier(specifier, aliases, fileSet);
}

interface Candidate {
  file: string;
  score: number;
  /** 0 = import of the flagged file, 1 = importer — imports carry the sanitizer/gate more often. */
  direction: 0 | 1;
  reason: string;
}

/**
 * Pick the neighbors for one triage unit: the flagged file, its content, and
 * the findings on it (only `neighborhood`-tier findings anchor the search).
 * Returns [] when nothing qualifies — the unit is then judged as before.
 */
export async function buildNeighborhood(
  file: string,
  content: string,
  findings: Finding[],
  index: NeighborhoodIndex,
  readFile: FileReader,
): Promise<Neighbor[]> {
  if (!(GRAPH_SOURCE_EXTS as readonly string[]).includes(extname(file))) return [];
  const anchored = findings.filter((f) => contextTierFor(f.id) === 'neighborhood');
  if (anchored.length === 0) return [];

  const lines = content.split('\n');
  const flaggedLines = anchored.map((f) => f.line).filter((l): l is number => typeof l === 'number' && l >= 1);
  const windowText = codeOnly(
    flaggedLines.length === 0
      ? content
      : flaggedLines
          .map((l) => lines.slice(Math.max(0, l - 1 - NEIGHBOR_WINDOW_LINES), l + NEIGHBOR_WINDOW_LINES).join('\n'))
          .join('\n'),
  );
  const anchors = new Set(flaggedLines.flatMap((l) => anchorTokens(lines[l - 1] ?? '')));

  const candidates = new Map<string, Candidate>();

  // Direction 1: modules this file imports, when an imported name is used near a flagged line.
  for (const binding of extractImportBindings(content)) {
    const target = resolveTarget(file, binding.specifier, index.fileSet, index.aliases);
    if (!target || target === file) continue;
    const used = binding.names.filter((n) => new RegExp(`\\b${escapeRe(n)}\\b`).test(windowText));
    if (used.length === 0) continue;
    const prev = candidates.get(target);
    const score = used.length + (prev?.score ?? 0);
    candidates.set(target, {
      file: target,
      score,
      direction: 0,
      reason: `imported by ${file}; ${used.join(', ')} used near the flagged code`,
    });
  }

  // Direction 2: modules importing this file that mention an anchor token from
  // a flagged line. The names the importer binds FROM this file do not count
  // as mentions — every importer of `tools` says "tools"; the evidence is the
  // executor that also says 'delete_file'.
  if (anchors.size > 0) {
    for (const importer of index.importers.get(file) ?? []) {
      if (candidates.has(importer)) continue;
      let text: string;
      try {
        text = await readFile(importer);
      } catch {
        continue;
      }
      const bound = new Set(
        extractImportBindings(text)
          .filter((b) => resolveTarget(importer, b.specifier, index.fileSet, index.aliases) === file)
          .flatMap((b) => b.names),
      );
      const hits = [...anchors].filter((a) => !bound.has(a) && text.includes(a));
      if (hits.length === 0) continue;
      candidates.set(importer, {
        file: importer,
        score: hits.length,
        direction: 1,
        reason: `imports ${file}; mentions ${hits.slice(0, 3).join(', ')}`,
      });
    }
  }

  const ordered = [...candidates.values()].sort(
    (a, b) => b.score - a.score || a.direction - b.direction || a.file.localeCompare(b.file),
  );

  const neighbors: Neighbor[] = [];
  let total = 0;
  for (const c of ordered) {
    if (neighbors.length >= MAX_NEIGHBORS || total >= MAX_NEIGHBORHOOD_CHARS) break;
    let text: string;
    try {
      text = await readFile(c.file);
    } catch {
      continue;
    }
    if (text.length > MAX_NEIGHBOR_CHARS) text = `${text.slice(0, MAX_NEIGHBOR_CHARS)}\n… [truncated]`;
    if (total + text.length > MAX_NEIGHBORHOOD_CHARS)
      text = `${text.slice(0, MAX_NEIGHBORHOOD_CHARS - total)}\n… [truncated]`;
    neighbors.push({ file: c.file, content: text, reason: c.reason });
    total += text.length;
  }
  return neighbors;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Everything the model reads for a unit — the cache key must cover all of it. */
export function unitContext(content: string, neighbors: Neighbor[] | undefined): string {
  if (!neighbors?.length) return content;
  return `${content}\n${neighbors.map((n) => `\0${n.file}\0${n.content}`).join('')}`;
}

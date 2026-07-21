import { dirname, extname, join, normalize } from 'node:path';
import { classifyFile } from './file-context.js';

/** A single import found in a file. */
export interface ImportEdge {
  /** The module specifier string literal, verbatim. */
  specifier: string;
  /** True only when the whole statement is `import type` / `export type`. */
  typeOnly: boolean;
}

/** Source extensions whose imports participate in the graph. */
export const GRAPH_SOURCE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs'] as const;

/**
 * Extract all import specifiers from TS/JS content, flagging type-only statements.
 *
 * A statement is type-only only when it begins with `import type` or `export type`
 * (statement-level erasure). Inline `import { type X, Y }` is a value edge because
 * `Y` is a runtime value. `import(expr)` with a non-literal argument yields no edge.
 */
/**
 * Remove line and block comments from TS/JS source so a commented-out import
 * (`// import { x } from './b.js'`) doesn't create a phantom graph edge — which
 * would fabricate a false cycle (STR-012). String and template literals are
 * preserved (a `//` inside "http://x" is not a comment). Regex literals aren't
 * tracked; a `//` after a `/regex/` is rare and at worst drops a real edge —
 * the safe direction for cycle detection.
 */
export function stripComments(content: string): string {
  let out = '';
  let state: 'code' | 'line' | 'block' | 'squote' | 'dquote' | 'template' = 'code';
  for (let i = 0; i < content.length; i++) {
    const c = content[i];
    const next = content[i + 1];
    if (state === 'code') {
      if (c === '/' && next === '/') {
        state = 'line';
        i++;
      } else if (c === '/' && next === '*') {
        state = 'block';
        i++;
      } else if (c === "'") {
        state = 'squote';
        out += c;
      } else if (c === '"') {
        state = 'dquote';
        out += c;
      } else if (c === '`') {
        state = 'template';
        out += c;
      } else {
        out += c;
      }
    } else if (state === 'line') {
      if (c === '\n') {
        state = 'code';
        out += c;
      }
    } else if (state === 'block') {
      if (c === '*' && next === '/') {
        state = 'code';
        i++;
      } else if (c === '\n') {
        out += c; // keep newlines so line numbers stay stable
      }
    } else {
      // inside a string / template literal — copy verbatim, honoring escapes
      if (c === '\\') {
        out += c + (next ?? '');
        i++;
      } else {
        if (state === 'squote' && c === "'") state = 'code';
        else if (state === 'dquote' && c === '"') state = 'code';
        else if (state === 'template' && c === '`') state = 'code';
        out += c;
      }
    }
  }
  return out;
}

export function extractImports(source: string): ImportEdge[] {
  const content = stripComments(source);
  const edges: ImportEdge[] = [];

  // The regexes below are mutually exclusive by construction:
  //   fromRe       — `import/export … from 'x'` (the clause [^'"]*? stops at the first
  //                  quote, so it cannot swallow a bare `import 'x'`)
  //   sideEffectRe — `import 'x'` with no `from` and no `(` after `import`
  //   require/dynamic — parenthesised `require('x')` / `import('x')`, which sideEffectRe
  //                  cannot match because `(` is neither whitespace nor a quote
  // A maintainer editing one regex must preserve this exclusivity (no dedup guard exists).

  // `import ... from 'x'` and `export ... from 'x'` — capture the keyword + the
  // clause between it and `from` so we can detect a leading `type`.
  // The clause between keyword and `from` must not itself contain `from` to avoid
  // runaway matches. We use a non-greedy match that excludes quote characters.
  const fromRe = /\b(import|export)\b([^'"]*?)\bfrom\s*['"]([^'"]+)['"]/g;
  for (const m of content.matchAll(fromRe)) {
    const clause = m[2];
    // type-only iff the word `type` immediately follows the keyword (before any binding).
    const typeOnly = /^\s+type\b/.test(clause);
    edges.push({ specifier: m[3], typeOnly });
  }

  // Side-effect `import 'x'` (no `from`, not followed by `(`).
  // Must NOT match `import(` (dynamic imports handled separately below).
  const sideEffectRe = /\bimport\s*['"]([^'"]+)['"]/g;
  for (const m of content.matchAll(sideEffectRe)) {
    edges.push({ specifier: m[1], typeOnly: false });
  }

  // `require('x')` — string literal only.
  const requireRe = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of content.matchAll(requireRe)) {
    edges.push({ specifier: m[1], typeOnly: false });
  }

  // Dynamic `import('x')` — string literal only.
  const dynamicImportRe = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of content.matchAll(dynamicImportRe)) {
    edges.push({ specifier: m[1], typeOnly: false });
  }

  return edges;
}

// Superset of GRAPH_SOURCE_EXTS; adds .cts/.mts for resolution candidates only.
const RESOLVE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cts', '.mts'];
const INDEX_FILES = RESOLVE_EXTS.map((ext) => `/index${ext}`);

/**
 * Expand a raw project-relative path into resolution candidates, in priority
 * order: exact, TS rewrite of a JS extension, appended extensions, index files.
 */
export function expandCandidates(raw: string): string[] {
  const candidates: string[] = [];

  // 1. Exact path as written.
  candidates.push(raw);

  // 2. TS rewrite: a .js/.jsx/.mjs/.cjs specifier often maps to a .ts/.tsx/.mts/.cts file.
  const jsToTs: Record<string, string[]> = {
    '.js': ['.ts', '.tsx'],
    '.jsx': ['.tsx'],
    '.mjs': ['.mts'],
    '.cjs': ['.cts'],
  };
  for (const [jsExt, tsExts] of Object.entries(jsToTs)) {
    if (raw.endsWith(jsExt)) {
      const stem = raw.slice(0, -jsExt.length);
      for (const tsExt of tsExts) candidates.push(stem + tsExt);
    }
  }

  // 3. Append source extensions (for extensionless specifiers like './a').
  for (const ext of RESOLVE_EXTS) candidates.push(raw + ext);

  // 4. Directory index files.
  for (const idx of INDEX_FILES) candidates.push(raw + idx);

  return candidates;
}

/** Normalize a joined path to project-relative POSIX form (no leading ./). */
export function toProjectPath(...segments: string[]): string {
  return normalize(join(...segments)).replaceAll('\\', '/');
}

/**
 * Resolve a RELATIVE specifier (`./` or `../`) to an existing project file, or null.
 * Bare specifiers and aliases (anything not starting with `.`) return null (external).
 * `fileSet` holds project-relative paths; resolution must hit a member of it.
 */
export function resolveSpecifier(importerPath: string, specifier: string, fileSet: Set<string>): string | null {
  if (!specifier.startsWith('.')) return null; // bare or alias → external

  const raw = toProjectPath(dirname(importerPath), specifier);
  for (const cand of expandCandidates(raw)) {
    if (fileSet.has(cand)) return cand;
  }
  return null;
}

/** Alias mappings from one tsconfig (`compilerOptions.baseUrl` + `paths`). */
export interface AliasConfig {
  /** Directory of the tsconfig, project-relative ('' for the root). */
  baseDir: string;
  /** compilerOptions.baseUrl relative to baseDir, or null when not set. */
  baseUrl: string | null;
  /** compilerOptions.paths patterns, e.g. { '@/*': ['./src/*'] }. */
  paths: Record<string, string[]>;
}

/**
 * Resolve a NON-relative specifier through tsconfig aliases (and baseUrl) to
 * an existing project file, or null. Patterns support the standard single `*`.
 */
export function resolveAliasSpecifier(specifier: string, aliases: AliasConfig[], fileSet: Set<string>): string | null {
  for (const alias of aliases) {
    const root = toProjectPath(alias.baseDir, alias.baseUrl ?? '.');

    for (const [pattern, targets] of Object.entries(alias.paths)) {
      const star = pattern.indexOf('*');
      let matched: string | null = null;
      if (star === -1) {
        if (specifier === pattern) matched = '';
      } else {
        const prefix = pattern.slice(0, star);
        const suffix = pattern.slice(star + 1);
        if (specifier.startsWith(prefix) && specifier.endsWith(suffix) && specifier.length >= pattern.length - 1) {
          matched = specifier.slice(prefix.length, specifier.length - suffix.length);
        }
      }
      if (matched === null) continue;

      for (const target of targets) {
        const raw = toProjectPath(root, target.replace('*', matched));
        for (const cand of expandCandidates(raw)) {
          if (fileSet.has(cand)) return cand;
        }
      }
    }

    // An explicit baseUrl lets bare specifiers resolve relative to it.
    if (alias.baseUrl !== null) {
      const raw = toProjectPath(root, specifier);
      for (const cand of expandCandidates(raw)) {
        if (fileSet.has(cand)) return cand;
      }
    }
  }
  return null;
}

/**
 * Build a directed graph of VALUE imports between `source`-context TS/JS files.
 * Nodes: every TS/JS source file. Edges: importer → resolved project target,
 * excluding type-only edges and unresolved/external specifiers.
 * Files that fail to read are skipped with an empty edge set (consistent with the other analyzers — one unreadable file must not abort the audit).
 */
export async function buildImportGraph(
  files: string[],
  readFile: (path: string) => Promise<string>,
): Promise<Map<string, Set<string>>> {
  const graph = new Map<string, Set<string>>();
  const fileSet = new Set(files);

  const nodes = files.filter(
    (f) => (GRAPH_SOURCE_EXTS as readonly string[]).includes(extname(f)) && classifyFile(f) === 'source',
  );
  const nodeSet = new Set(nodes);

  for (const file of nodes) {
    const out = new Set<string>();
    let content: string;
    try {
      content = await readFile(file);
    } catch {
      graph.set(file, out);
      continue;
    }
    for (const edge of extractImports(content)) {
      if (edge.typeOnly) continue;
      const target = resolveSpecifier(file, edge.specifier, fileSet);
      if (target && nodeSet.has(target)) out.add(target);
    }
    graph.set(file, out);
  }

  return graph;
}

/** What the dead-file reachability pass learns in its single read of the tree. */
export interface ReachabilityScan {
  /** Files that are the target of at least one resolved import — value OR type, from ANY file. */
  imported: Set<string>;
  /** TS/JS files in `source` context (the only dead-file candidates). */
  sourceFiles: string[];
  /** Files whose content starts with a shebang (executables — entry points). */
  shebangFiles: Set<string>;
  /** True if any file has a dynamic import/require with a non-literal argument. */
  hasNonLiteralDynamic: boolean;
}

/** Detect `import(expr)` / `require(expr)` where expr is not a string literal. */
export function hasNonLiteralDynamicImport(content: string): boolean {
  return /\b(?:import|require)\s*\(\s*[^'")\s]/.test(content);
}

/**
 * Scan reachability for dead-file detection. The tradeoff here is the OPPOSITE
 * of the cycle graph: a missed edge there loses a cycle (safe false negative);
 * a missed edge here invents a dead file (direct false positive). So this scan
 * is maximal: type-only edges count (a type-only target is not dead), imports
 * from EVERY TS/JS file count (a util imported only by tests is alive), and
 * non-relative specifiers resolve through tsconfig aliases.
 */
export async function scanReachability(
  files: string[],
  readFile: (path: string) => Promise<string>,
  aliases: AliasConfig[] = [],
): Promise<ReachabilityScan> {
  const fileSet = new Set(files);
  const tsJs = files.filter((f) => (GRAPH_SOURCE_EXTS as readonly string[]).includes(extname(f)));

  const imported = new Set<string>();
  const shebangFiles = new Set<string>();
  let hasNonLiteralDynamic = false;

  for (const file of tsJs) {
    let content: string;
    try {
      content = await readFile(file);
    } catch {
      continue; // unreadable importer contributes no edges
    }
    if (content.startsWith('#!')) shebangFiles.add(file);
    if (!hasNonLiteralDynamic && hasNonLiteralDynamicImport(content)) hasNonLiteralDynamic = true;

    for (const edge of extractImports(content)) {
      const target = edge.specifier.startsWith('.')
        ? resolveSpecifier(file, edge.specifier, fileSet)
        : resolveAliasSpecifier(edge.specifier, aliases, fileSet);
      if (target) imported.add(target);
    }
  }

  const sourceFiles = tsJs.filter((f) => classifyFile(f) === 'source' && !f.endsWith('.d.ts'));
  return { imported, sourceFiles, shebangFiles, hasNonLiteralDynamic };
}

/**
 * Find cycles via Tarjan's strongly-connected-components algorithm.
 * Returns each SCC of size >= 2, plus any self-loop (node with an edge to itself),
 * as a list of node names. Each cycle appears once.
 * Neighbours absent from the graph keys are traversed as isolated sink nodes (callers should ensure all reachable nodes are keys).
 */
// Recursive Tarjan; safe for typical project sizes.
export function findCycles(graph: Map<string, Set<string>>): string[][] {
  let index = 0;
  const stack: string[] = [];
  const onStack = new Set<string>();
  const indices = new Map<string, number>();
  const lowlink = new Map<string, number>();
  const cycles: string[][] = [];

  function strongConnect(v: string): void {
    indices.set(v, index);
    lowlink.set(v, index);
    index++;
    stack.push(v);
    onStack.add(v);

    for (const w of graph.get(v) ?? []) {
      if (!indices.has(w)) {
        strongConnect(w);
        lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
      } else if (onStack.has(w)) {
        lowlink.set(v, Math.min(lowlink.get(v)!, indices.get(w)!));
      }
    }

    if (lowlink.get(v) === indices.get(v)) {
      const scc: string[] = [];
      let w: string;
      do {
        w = stack.pop()!;
        onStack.delete(w);
        scc.push(w);
      } while (w !== v);

      if (scc.length > 1) {
        cycles.push(scc);
      } else {
        const only = scc[0];
        if (graph.get(only)?.has(only)) cycles.push(scc);
      }
    }
  }

  for (const v of graph.keys()) {
    if (!indices.has(v)) strongConnect(v);
  }

  return cycles;
}

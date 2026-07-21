import { basename, dirname, extname } from 'node:path';
import type { AliasConfig } from './import-graph.js';
import { scanReachability, expandCandidates, toProjectPath, GRAPH_SOURCE_EXTS } from './import-graph.js';

/**
 * Parse a tsconfig's `compilerOptions.baseUrl`/`paths` into an AliasConfig.
 * tsconfig is JSONC (comments + trailing commas allowed), so parsing is
 * tolerant. Returns:
 * - an AliasConfig when baseUrl or paths are present,
 * - null when the file parses but defines no aliases,
 * - 'unparseable' when it cannot be parsed AT ALL — the caller must then skip
 *   dead-file analysis: aliases we cannot see would make alias-only-reachable
 *   files look dead (a conservative abort beats inventing corpses).
 */
export function parseTsconfigAliases(content: string, tsconfigPath: string): AliasConfig | null | 'unparseable' {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    // JSONC: strip /* */ and // comments, then trailing commas, and retry.
    const stripped = content
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '')
      .replace(/,\s*([}\]])/g, '$1');
    try {
      parsed = JSON.parse(stripped);
    } catch {
      return 'unparseable';
    }
  }

  if (!parsed || typeof parsed !== 'object') return 'unparseable';
  const options = (parsed as { compilerOptions?: unknown }).compilerOptions;
  if (!options || typeof options !== 'object') return null;

  const { baseUrl, paths } = options as { baseUrl?: unknown; paths?: unknown };
  const validBaseUrl = typeof baseUrl === 'string' ? baseUrl : null;
  const validPaths: Record<string, string[]> = {};
  if (paths && typeof paths === 'object') {
    for (const [pattern, targets] of Object.entries(paths)) {
      if (Array.isArray(targets) && targets.every((t) => typeof t === 'string')) {
        validPaths[pattern] = targets;
      }
    }
  }

  if (validBaseUrl === null && Object.keys(validPaths).length === 0) return null;
  const dir = dirname(tsconfigPath);
  return { baseDir: dir === '.' ? '' : dir, baseUrl: validBaseUrl, paths: validPaths };
}

/** Path-like tokens with a source extension inside package.json scripts. */
const SCRIPT_FILE_TOKEN = /[\w@./-]+\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts)\b/g;

/**
 * Collect entry-point files referenced by one package.json: main/module/types/
 * browser, bin (string or map), exports (every nested string), and any
 * path-like token in scripts (covers `tsup src/cli/index.ts`, `tsx scripts/x.ts`…).
 * Refs resolve relative to the package.json's directory; only refs that hit an
 * actual project file count.
 */
export function collectPackageEntryPoints(pkgPath: string, content: string, fileSet: Set<string>): Set<string> {
  const entries = new Set<string>();
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content);
  } catch {
    return entries;
  }
  if (!pkg || typeof pkg !== 'object') return entries;

  const refs: string[] = [];
  for (const field of ['main', 'module', 'types', 'browser']) {
    if (typeof pkg[field] === 'string') refs.push(pkg[field] as string);
  }
  const bin = pkg.bin;
  if (typeof bin === 'string') refs.push(bin);
  else if (bin && typeof bin === 'object') {
    for (const v of Object.values(bin)) if (typeof v === 'string') refs.push(v);
  }
  collectStrings(pkg.exports, refs);
  const scripts = pkg.scripts;
  if (scripts && typeof scripts === 'object') {
    for (const cmd of Object.values(scripts)) {
      if (typeof cmd !== 'string') continue;
      for (const m of cmd.matchAll(SCRIPT_FILE_TOKEN)) refs.push(m[0]);
    }
  }

  const pkgDir = dirname(pkgPath);
  for (const ref of refs) {
    const joined = pkgDir === '.' ? ref : `${pkgDir}/${ref}`;
    const normalized = joined.replace(/^\.\//, '').replaceAll('/./', '/');
    if (fileSet.has(normalized)) entries.add(normalized);
  }
  return entries;
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) collectStrings(v, out);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) collectStrings(v, out);
}

/** Path-like token with a TS/JS extension, anywhere in text. */
const PATH_TOKEN = /[\w@./-]+\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts)\b/g;

// Non-source files whose content can launch or load code by path: HTML script
// tags (Vite entries), Dockerfile CMD/ENTRYPOINT, compose commands, shell
// scripts, task runners, generic JSON configs.
const REFERENCE_EXTS = new Set(['.html', '.yml', '.yaml', '.sh', '.toml', '.json']);
const REFERENCE_BASENAMES = /^(Dockerfile|Makefile|Justfile)/;

function isReferenceFile(file: string): boolean {
  return REFERENCE_EXTS.has(extname(file)) || REFERENCE_BASENAMES.test(basename(file));
}

/**
 * Resolve a path-like token found in arbitrary text to a project file. Tries,
 * in order: relative to the referrer's directory, from the project root, then
 * progressively stripping leading segments (absolute paths, build prefixes
 * like `dist/`), each base also with a `src/` variant (a `dist/x/index.js`
 * reference usually means `src/x/index.ts`). Every step only widens what
 * counts as ALIVE — a wrong match can never invent a dead file.
 */
export function resolvePathToken(token: string, referrerDir: string, fileSet: Set<string>): string | null {
  const tryBase = (base: string): string | null => {
    for (const cand of expandCandidates(base)) {
      if (fileSet.has(cand)) return cand;
    }
    return null;
  };

  if (token.startsWith('.')) {
    return tryBase(toProjectPath(referrerDir, token));
  }

  const cleaned = token.replace(/^\/+/, '');
  const bases: string[] = [toProjectPath(referrerDir, cleaned), cleaned];
  const segments = cleaned.split('/');
  for (let i = 1; i < Math.min(segments.length, 10); i++) {
    bases.push(segments.slice(i).join('/'));
  }
  for (const base of [...bases]) bases.push(`src/${base}`);

  for (const base of bases) {
    const hit = tryBase(base);
    if (hit) return hit;
  }
  return null;
}

/**
 * Collect every project file referenced by a path-like string anywhere in the
 * tree: fork/spawn/Worker paths in TS/JS, `<script src>` in HTML, Dockerfile
 * CMD, package.json bin pointing at build output, shell scripts… These are
 * reachability channels no import graph sees.
 */
export async function collectStringReferences(
  files: string[],
  readFile: (path: string) => Promise<string>,
): Promise<Set<string>> {
  const fileSet = new Set(files);
  const referenced = new Set<string>();

  const referrers = files.filter(
    (f) => isReferenceFile(f) || (GRAPH_SOURCE_EXTS as readonly string[]).includes(extname(f)),
  );
  for (const file of referrers) {
    let content: string;
    try {
      content = await readFile(file);
    } catch {
      continue;
    }
    const dir = dirname(file);
    for (const m of content.matchAll(PATH_TOKEN)) {
      const target = resolvePathToken(m[0], dir === '.' ? '' : dir, fileSet);
      if (target && target !== file) referenced.add(target);
    }
  }
  return referenced;
}

// Framework/tooling files loaded by convention, not by import. `scripts`,
// `bin` and `tools` hold manually-run utilities (`tsx scripts/x.ts`) that no
// import reaches by design.
const CONVENTION_DIRS = new Set(['pages', 'routes', 'scripts', 'bin', 'tools']);
const CONVENTION_BASENAMES = new Set([
  'page',
  'layout',
  'route',
  'loading',
  'error',
  'template',
  'not-found',
  'middleware',
  'instrumentation',
]);

/** True for files loaded by convention rather than by an import statement. */
export function isConventionEntry(file: string): boolean {
  const segments = file.split('/');
  if (segments.slice(0, -1).some((d) => CONVENTION_DIRS.has(d))) return true;

  const name = basename(file);
  const stem = name.replace(/\.[^.]+$/, '');
  if (CONVENTION_BASENAMES.has(stem)) return true;
  if (/\.(config|stories|story)\.[^.]+$/.test(name)) return true;
  // Root-level and src-level index files are package entries by convention.
  if (/^index\.[^.]+$/.test(name)) {
    const dir = segments.slice(0, -1).join('/');
    if (dir === '' || dir === 'src') return true;
  }
  return false;
}

export interface DeadFilesResult {
  /** Source files nothing imports and no entry-point heuristic claims. */
  dead: string[];
  /** Set when the analysis was skipped entirely (with the reason). */
  skippedReason?: string;
  /** The project has dynamic imports we cannot resolve — flag findings as such. */
  hasNonLiteralDynamic: boolean;
}

/**
 * Find TS/JS source files that nothing reaches: not imported by any file
 * (value or type, through relative paths or tsconfig aliases), not referenced
 * by any package.json, not an executable (shebang), not a convention entry.
 */
export async function findDeadFiles(
  files: string[],
  readFile: (path: string) => Promise<string>,
): Promise<DeadFilesResult> {
  const fileSet = new Set(files);

  // Aliases from every tsconfig*.json in the project (monorepo-aware).
  const aliases: AliasConfig[] = [];
  for (const file of files) {
    if (!/(^|\/)tsconfig[^/]*\.json$/.test(file)) continue;
    let content: string;
    try {
      content = await readFile(file);
    } catch {
      continue;
    }
    const parsed = parseTsconfigAliases(content, file);
    if (parsed === 'unparseable') {
      return {
        dead: [],
        skippedReason: `dead-file analysis skipped: could not parse ${file} (its path aliases may hide live imports)`,
        hasNonLiteralDynamic: false,
      };
    }
    if (parsed) aliases.push(parsed);
  }

  const reach = await scanReachability(files, readFile, aliases);
  const referenced = await collectStringReferences(files, readFile);

  const packageEntries = new Set<string>();
  for (const file of files) {
    if (basename(file) !== 'package.json') continue;
    let content: string;
    try {
      content = await readFile(file);
    } catch {
      continue;
    }
    for (const entry of collectPackageEntryPoints(file, content, fileSet)) packageEntries.add(entry);
  }

  const dead = reach.sourceFiles
    .filter(
      (f) =>
        !reach.imported.has(f) &&
        !referenced.has(f) &&
        !reach.shebangFiles.has(f) &&
        !packageEntries.has(f) &&
        !isConventionEntry(f),
    )
    .sort();

  return { dead, hasNonLiteralDynamic: reach.hasNonLiteralDynamic };
}

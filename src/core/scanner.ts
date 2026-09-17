import { readdir, stat, readFile } from 'node:fs/promises';
import type { Dirent } from 'node:fs';
import { join, relative, extname, basename, sep } from 'node:path';
import { existsSync } from 'node:fs';
import ignore from 'ignore';
import { classifyFile, isExcludedContext } from '../utils/file-context.js';
import type { ProjectScan, ProjectMeta, DetectedStack, FileNode } from './types.js';

/**
 * Hard cap on files inventoried. A hostile or merely pathological tree
 * (a monorepo with millions of entries, or someone pointing PRISM at a whole
 * disk) must not spin the walker unbounded or hand every downstream analyzer
 * (secrets, semgrep, OSV) an unbounded per-file read/scan workload. Generous
 * for any real codebase — same doctrine as MAX_ZIP_ENTRIES in input.ts.
 */
export const MAX_SCAN_FILES = 100_000;

/**
 * Rewrite the patterns of a NESTED .gitignore (living in `dir`, project-
 * relative POSIX) so they mean the same thing from the project root, per git
 * semantics: a pattern with no slash (or only a trailing one) matches at any
 * depth below `dir`; a leading slash anchors it to `dir`; a slash anywhere
 * else makes it relative to `dir`. Negations keep their `!`. Comments and
 * blank lines are dropped. Exported for tests.
 */
export function nestedIgnorePatterns(dir: string, content: string): string[] {
  const out: string[] = [];
  for (const raw of content.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
    const negated = line.startsWith('!');
    const p = negated ? line.slice(1) : line;
    let rewritten: string;
    if (p.startsWith('/')) rewritten = `${dir}/${p.slice(1)}`;
    else if (p.slice(0, -1).includes('/')) rewritten = `${dir}/${p}`;
    else rewritten = `${dir}/**/${p}`;
    out.push(negated ? `!${rewritten}` : rewritten);
  }
  return out;
}

/** Directories always excluded from scanning */
const ALWAYS_IGNORE = [
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '__pycache__',
  '.venv',
  'venv',
  '.cache',
  'coverage',
  '.nyc_output',
  '.turbo',
];

/** File extensions → language mapping */
const LANG_MAP: Record<string, string> = {
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.py': 'python',
  '.rs': 'rust',
  '.go': 'go',
  '.java': 'java',
  '.rb': 'ruby',
  '.php': 'php',
  '.cs': 'csharp',
  '.swift': 'swift',
  '.kt': 'kotlin',
};

/** Framework detection patterns */
const FRAMEWORK_INDICATORS: Record<string, (files: string[]) => boolean> = {
  'Next.js': (f) => f.some((p) => p === 'next.config.js' || p === 'next.config.ts' || p === 'next.config.mjs'),
  React: (f) => f.some((p) => p === 'package.json') && f.some((p) => p.endsWith('.tsx') || p.endsWith('.jsx')),
  NestJS: (f) => f.some((p) => p.includes('nest-cli.json') || p.includes('.module.ts')),
  // Express and FastAPI are dependency-based, not file-based (every Node repo
  // has package.json, every Python repo has .py) — resolved in detectFrameworks.
  Django: (f) => f.some((p) => p === 'manage.py' || p.includes('settings.py')),
  // Fixture/vendored Dockerfiles don't make the project itself dockerized.
  Docker: (f) =>
    f.some(
      (p) =>
        !isExcludedContext(classifyFile(p)) &&
        (basename(p) === 'Dockerfile' || basename(p) === 'docker-compose.yml' || basename(p) === 'docker-compose.yaml'),
    ),
  Vitest: (f) => f.some((p) => p.includes('vitest.config')),
  Jest: (f) => f.some((p) => p.includes('jest.config')),
  // pyproject.toml alone is not a Pytest signal (every modern Python repo has
  // one); require a real pytest marker file, or refine by deps in detectFrameworks.
  Pytest: (f) => f.some((p) => p === 'pytest.ini' || p.includes('conftest.py')),
  'GitHub Actions': (f) => f.some((p) => p.startsWith('.github/workflows/')),
  Prisma: (f) => f.some((p) => p.includes('schema.prisma')),
  Drizzle: (f) => f.some((p) => p.includes('drizzle.config')),
};

/**
 * Scans a project directory and produces a ProjectScan
 * with file listing, metadata, and tree structure.
 */
export async function scanProject(rootPath: string, opts: { maxFiles?: number } = {}): Promise<ProjectScan> {
  const maxFiles = opts.maxFiles ?? MAX_SCAN_FILES;
  const ig = ignore();

  // Load .gitignore if present
  const gitignorePath = join(rootPath, '.gitignore');
  if (existsSync(gitignorePath)) {
    const content = await readFile(gitignorePath, 'utf-8');
    ig.add(content);
  }

  // Always ignore these
  ig.add(ALWAYS_IGNORE);

  // Collect all files
  const files: string[] = [];
  const warnings = { unreadableDirs: 0, unstatableFiles: 0, truncated: false };
  const fileTree = await walkDirectory(rootPath, rootPath, ig, files, warnings, maxFiles);

  // Detect stack
  const stack = detectStack(files);
  const frameworks = await detectFrameworks(rootPath, files);
  const meta = buildMeta(rootPath, files, stack, frameworks);

  return {
    rootPath,
    files,
    fileTree,
    meta,
    ...(warnings.unreadableDirs > 0 || warnings.unstatableFiles > 0 || warnings.truncated
      ? {
          scanWarnings: {
            unreadableDirs: warnings.unreadableDirs,
            unstatableFiles: warnings.unstatableFiles,
            ...(warnings.truncated ? { truncated: true as const } : {}),
          },
        }
      : {}),
  };
}

async function walkDirectory(
  currentPath: string,
  rootPath: string,
  ig: ReturnType<typeof ignore>,
  collectedFiles: string[],
  warnings: { unreadableDirs: number; unstatableFiles: number; truncated: boolean },
  maxFiles: number,
): Promise<FileNode[]> {
  // Once the cap is hit, every remaining subtree short-circuits here instead
  // of issuing another readdir — bounded by nesting depth, not file count.
  if (warnings.truncated) return [];

  // An unreadable directory (EACCES) must not abort the whole scan — but it is
  // counted so the coverage gap is reported, not silently swallowed.
  let entries: Dirent[];
  try {
    entries = await readdir(currentPath, { withFileTypes: true });
  } catch {
    warnings.unreadableDirs++;
    return [];
  }
  const nodes: FileNode[] = [];

  // A .gitignore below the root applies to its own subtree, with precedence
  // over the root's rules (later patterns win in `ignore`, matching git's
  // deeper-file-wins). Loaded BEFORE this directory's entries are judged.
  // The root .gitignore was loaded by scanProject.
  if (currentPath !== rootPath && entries.some((e) => e.isFile() && e.name === '.gitignore')) {
    try {
      const relDir = relative(rootPath, currentPath).split(sep).join('/');
      ig.add(nestedIgnorePatterns(relDir, await readFile(join(currentPath, '.gitignore'), 'utf-8')));
    } catch {
      // An unreadable nested .gitignore simply contributes no rules.
    }
  }

  for (const entry of entries) {
    if (collectedFiles.length >= maxFiles) {
      warnings.truncated = true;
      break;
    }
    const fullPath = join(currentPath, entry.name);
    // Normalize to POSIX separators at the source: every consumer (ignore
    // rules, .github/workflows/ prefixes, fixture classification, import
    // graph) assumes '/' — on Windows path.relative() yields '\'.
    const relPath = relative(rootPath, fullPath).split(sep).join('/');

    // Check against ignore rules. Directories are matched with a trailing
    // slash so dir-only patterns like `logs/` actually exclude the directory
    // (otherwise the tree is walked in full and reported as an empty dir).
    if (ig.ignores(entry.isDirectory() ? `${relPath}/` : relPath)) continue;

    if (entry.isDirectory()) {
      const children = await walkDirectory(fullPath, rootPath, ig, collectedFiles, warnings, maxFiles);
      nodes.push({
        name: entry.name,
        path: relPath,
        type: 'directory',
        children,
      });
    } else if (entry.isFile()) {
      // A file removed/unreadable between readdir and stat must not abort — but
      // it is counted (it will be absent from `files`, so silence would let the
      // inventory undercount).
      let size = 0;
      try {
        size = (await stat(fullPath)).size;
      } catch {
        warnings.unstatableFiles++;
        continue;
      }
      collectedFiles.push(relPath);
      nodes.push({
        name: entry.name,
        path: relPath,
        type: 'file',
        size,
      });
    }
    // Symlinks are intentionally not followed (traversal safety).
  }

  return nodes.sort((a, b) => {
    // Directories first, then alphabetical
    if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

function detectStack(files: string[]): DetectedStack {
  const langCount: Record<string, number> = {};

  for (const file of files) {
    const ext = extname(file);
    const lang = LANG_MAP[ext];
    if (lang) {
      langCount[lang] = (langCount[lang] || 0) + 1;
    }
  }

  const sorted = Object.entries(langCount).sort(([, a], [, b]) => b - a);

  if (sorted.length === 0) {
    return { primary: 'unknown', secondary: [] };
  }

  const primary = sorted[0][0];
  const secondary = sorted.slice(1).map(([lang]) => lang);

  // Detect runtime
  let runtime: string | undefined;
  if (primary === 'typescript' || primary === 'javascript') {
    runtime = files.some((f) => f === 'package.json') ? 'node' : undefined;
  } else if (primary === 'python') {
    runtime = 'python';
  } else if (primary === 'rust') {
    runtime = 'rust';
  }

  return { primary, secondary, runtime };
}

async function detectFrameworks(rootPath: string, files: string[]): Promise<string[]> {
  const detected: string[] = [];
  for (const [name, check] of Object.entries(FRAMEWORK_INDICATORS)) {
    if (check(files)) {
      detected.push(name);
    }
  }

  // Dependency-based frameworks: confirm against real manifests, not just the
  // presence of package.json / *.py (which every repo of that language has).
  if (files.includes('package.json')) {
    try {
      const pkg = JSON.parse(await readFile(join(rootPath, 'package.json'), 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if ('express' in deps) detected.push('Express');
    } catch {
      // malformed package.json — no framework claim
    }
  }

  let pyManifest = '';
  for (const f of ['requirements.txt', 'pyproject.toml', 'Pipfile', 'setup.py']) {
    if (files.includes(f)) {
      try {
        pyManifest += `\n${await readFile(join(rootPath, f), 'utf-8')}`;
      } catch {
        // unreadable — skip
      }
    }
  }
  if (/\bfastapi\b/i.test(pyManifest)) detected.push('FastAPI');
  if (!detected.includes('Pytest') && (/\bpytest\b/i.test(pyManifest) || /\[tool\.pytest/i.test(pyManifest))) {
    detected.push('Pytest');
  }

  return detected;
}

function buildMeta(rootPath: string, files: string[], stack: DetectedStack, frameworks: string[]): ProjectMeta {
  // Detect package manager
  let packageManager: ProjectMeta['packageManager'];
  if (files.includes('pnpm-lock.yaml')) packageManager = 'pnpm';
  else if (files.includes('yarn.lock')) packageManager = 'yarn';
  else if (files.includes('package-lock.json')) packageManager = 'npm';
  else if (files.includes('Pipfile.lock') || files.includes('Pipfile')) packageManager = 'pip';
  else if (files.includes('poetry.lock')) packageManager = 'poetry';
  else if (files.includes('Cargo.lock')) packageManager = 'cargo';

  return {
    stack,
    totalLoc: 0, // calculated later if needed (expensive)
    totalFiles: files.length,
    hasGit: existsSync(join(rootPath, '.git')),
    // Only user-authored Docker files count — a Dockerfile inside test
    // fixtures/vendored code must not flag the project as dockerized (it used
    // to make the structure analyzer award a Docker bonus off a fixture).
    hasDocker: files.some(
      (f) =>
        !isExcludedContext(classifyFile(f)) &&
        (basename(f) === 'Dockerfile' || basename(f).startsWith('docker-compose')),
    ),
    hasCi: files.some(
      (f) => f.startsWith('.github/workflows/') || f === '.gitlab-ci.yml' || f.startsWith('.circleci/'),
    ),
    packageManager,
    frameworks,
  };
}

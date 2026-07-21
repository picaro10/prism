import { readdir, stat, readFile } from 'node:fs/promises';
import type { Dirent } from 'node:fs';
import { join, relative, extname, basename } from 'node:path';
import { existsSync } from 'node:fs';
import ignore from 'ignore';
import type { ProjectScan, ProjectMeta, DetectedStack, FileNode } from './types.js';

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
  Docker: (f) =>
    f.some(
      (p) =>
        basename(p) === 'Dockerfile' || basename(p) === 'docker-compose.yml' || basename(p) === 'docker-compose.yaml',
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
export async function scanProject(rootPath: string): Promise<ProjectScan> {
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
  const fileTree = await walkDirectory(rootPath, rootPath, ig, files);

  // Detect stack
  const stack = detectStack(files);
  const frameworks = await detectFrameworks(rootPath, files);
  const meta = buildMeta(rootPath, files, stack, frameworks);

  return {
    rootPath,
    files,
    fileTree,
    meta,
  };
}

async function walkDirectory(
  currentPath: string,
  rootPath: string,
  ig: ReturnType<typeof ignore>,
  collectedFiles: string[],
): Promise<FileNode[]> {
  // An unreadable directory (EACCES) must not abort the whole scan.
  let entries: Dirent[];
  try {
    entries = await readdir(currentPath, { withFileTypes: true });
  } catch {
    return [];
  }
  const nodes: FileNode[] = [];

  for (const entry of entries) {
    const fullPath = join(currentPath, entry.name);
    const relPath = relative(rootPath, fullPath);

    // Check against ignore rules. Directories are matched with a trailing
    // slash so dir-only patterns like `logs/` actually exclude the directory
    // (otherwise the tree is walked in full and reported as an empty dir).
    if (ig.ignores(entry.isDirectory() ? `${relPath}/` : relPath)) continue;

    if (entry.isDirectory()) {
      const children = await walkDirectory(fullPath, rootPath, ig, collectedFiles);
      nodes.push({
        name: entry.name,
        path: relPath,
        type: 'directory',
        children,
      });
    } else if (entry.isFile()) {
      // A file removed/unreadable between readdir and stat must not abort.
      let size = 0;
      try {
        size = (await stat(fullPath)).size;
      } catch {
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
    hasDocker: files.some((f) => basename(f) === 'Dockerfile' || basename(f).startsWith('docker-compose')),
    hasCi: files.some(
      (f) => f.startsWith('.github/workflows/') || f === '.gitlab-ci.yml' || f.startsWith('.circleci/'),
    ),
    packageManager,
    frameworks,
  };
}

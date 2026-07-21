import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding, FileNode } from '../core/types.js';
import { basename, extname } from 'node:path';
import { classifyFile } from '../utils/file-context.js';
import {
  countLoc,
  classifyGodFile,
  computeSizeMetrics,
  type MeasuredFile,
  type GodFileTier,
  type SizeMetrics,
} from '../utils/loc.js';
import { buildImportGraph, findCycles } from '../utils/import-graph.js';
import { findDeadFiles, type DeadFilesResult } from '../utils/dead-files.js';

const GOD_FILE_SOURCE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '.rs', '.go', '.java'];
const MAX_GOD_FILE_FINDINGS = 25;
/** Per-tier score deduction; total god-file deduction is capped (see below). */
const GOD_FILE_PENALTY: Record<Exclude<GodFileTier, 'info'>, number> = {
  low: 0.2,
  medium: 0.5,
  high: 1.0,
};
const GOD_FILE_PENALTY_CAP = 3.0;

const MAX_CYCLE_FINDINGS = 20;
const CYCLE_PENALTY = 0.5;
const CYCLE_PENALTY_CAP = 2.0;

const MAX_DEAD_FILE_FINDINGS = 20;
const DEAD_FILE_PENALTY = 0.1;
const DEAD_FILE_PENALTY_CAP = 1.0;

/**
 * StructureAnalyzer — Evaluates project organization, file hygiene, and architecture signals.
 *
 * Checks:
 * - Has README, LICENSE, .gitignore
 * - Source code is organized (not flat dump in root)
 * - No excessively deep nesting
 * - No orphan files (random files in root)
 * - Has proper config files (tsconfig, eslint/biome, etc.)
 * - Detects monorepo vs single project
 * - File naming consistency
 */
export class StructureAnalyzer implements Analyzer {
  readonly name = 'structure';
  readonly category = 'structure' as const;
  readonly description = 'Evaluates project organization, file hygiene, and structural patterns';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;

    // --- Check: README exists ---
    if (!scan.files.some((f) => f.toLowerCase() === 'readme.md')) {
      findings.push({
        id: 'STR-001',
        category: 'structure',
        severity: 'medium',
        title: 'Missing README.md',
        description: 'No README.md found in project root. Every project needs documentation.',
        suggestion: 'Create a README.md with project description, setup instructions, and usage.',
      });
      score -= 1;
    }

    // --- Check: .gitignore exists ---
    if (!scan.files.includes('.gitignore')) {
      findings.push({
        id: 'STR-002',
        category: 'structure',
        severity: 'high',
        title: 'Missing .gitignore',
        description: 'No .gitignore found. Risk of committing node_modules, .env, or build artifacts.',
        suggestion: 'Add a .gitignore appropriate for your stack.',
      });
      score -= 1.5;
    }

    // --- Check: Source code organization ---
    const sourceExts = ['.ts', '.js', '.tsx', '.jsx', '.py', '.rs', '.go'];
    const rootSourceFiles = scan.files.filter((f) => !f.includes('/') && sourceExts.includes(extname(f)));

    if (rootSourceFiles.length > 5) {
      findings.push({
        id: 'STR-003',
        category: 'structure',
        severity: 'medium',
        title: 'Source files scattered in root',
        description: `Found ${rootSourceFiles.length} source files directly in root directory. Source code should live in src/, lib/, or app/.`,
        suggestion: 'Move source files into a dedicated source directory.',
        meta: { files: rootSourceFiles.slice(0, 10) },
      });
      score -= 1;
    }

    // --- Check: Excessive nesting ---
    const deepFiles = scan.files.filter((f) => f.split('/').length > 8);
    if (deepFiles.length > 0) {
      findings.push({
        id: 'STR-004',
        category: 'structure',
        severity: 'low',
        title: 'Deeply nested files detected',
        description: `${deepFiles.length} file(s) are nested more than 8 levels deep. This can indicate over-engineering or poor organization.`,
        suggestion: 'Consider flattening your directory structure where possible.',
        meta: { examples: deepFiles.slice(0, 5) },
      });
      score -= 0.5;
    }

    // --- Check: Naming consistency ---
    const tsFiles = scan.files.filter((f) => extname(f) === '.ts' || extname(f) === '.tsx');
    if (tsFiles.length > 0) {
      const namingIssues = checkNamingConsistency(tsFiles);
      if (namingIssues.length > 0) {
        findings.push({
          id: 'STR-005',
          category: 'structure',
          severity: 'low',
          title: 'Inconsistent file naming',
          description: `Mixed naming conventions detected: ${namingIssues.join(', ')}`,
          suggestion: 'Pick one convention (kebab-case or camelCase) and stick with it.',
          meta: { issues: namingIssues },
        });
        score -= 0.5;
      }
    }

    // --- Check: Has linter/formatter config ---
    const hasLinter = scan.files.some(
      (f) =>
        f.includes('biome.json') ||
        f.includes('.eslintrc') ||
        f.includes('eslint.config') ||
        f.includes('.prettierrc') ||
        f.includes('prettier.config'),
    );
    if (!hasLinter && scan.meta.stack.primary !== 'unknown') {
      findings.push({
        id: 'STR-006',
        category: 'structure',
        severity: 'medium',
        title: 'No linter/formatter configuration',
        description: 'No ESLint, Biome, or Prettier config found.',
        suggestion: 'Add a linter and formatter to enforce code consistency.',
      });
      score -= 0.5;
    }

    // --- Check: Has TypeScript config (if TS project) ---
    if (
      scan.meta.stack.primary === 'typescript' &&
      !scan.files.some((f) => f === 'tsconfig.json' || f.endsWith('/tsconfig.json'))
    ) {
      findings.push({
        id: 'STR-007',
        category: 'structure',
        severity: 'high',
        title: 'TypeScript project without tsconfig.json',
        description: 'TypeScript files detected but no tsconfig.json found.',
        suggestion: 'Add a tsconfig.json with strict mode enabled.',
      });
      score -= 1;
    }

    // --- Check: Empty directories (from tree) ---
    const emptyDirs = findEmptyDirs(scan.fileTree);
    if (emptyDirs.length > 0) {
      findings.push({
        id: 'STR-008',
        category: 'structure',
        severity: 'info',
        title: 'Empty directories found',
        description: `${emptyDirs.length} empty director${emptyDirs.length === 1 ? 'y' : 'ies'} detected.`,
        suggestion: 'Remove empty directories or add .gitkeep if intentional.',
        meta: { dirs: emptyDirs },
      });
    }

    // --- Check: Large file count without proper organization ---
    if (scan.meta.totalFiles > 100) {
      const hasSrcDir = scan.fileTree.some((n) => n.type === 'directory' && n.name === 'src');
      const hasTestDir = scan.fileTree.some(
        (n) => n.type === 'directory' && (n.name === 'tests' || n.name === 'test' || n.name === '__tests__'),
      );

      if (!hasSrcDir) {
        findings.push({
          id: 'STR-009',
          category: 'structure',
          severity: 'medium',
          title: 'Large project without src/ directory',
          description: `Project has ${scan.meta.totalFiles} files but no src/ directory. Organization is critical at this scale.`,
          suggestion: 'Create a src/ directory for your source code.',
        });
        score -= 1;
      }

      if (!hasTestDir) {
        findings.push({
          id: 'STR-010',
          category: 'structure',
          severity: 'medium',
          title: 'Large project without test directory',
          description: `Project has ${scan.meta.totalFiles} files but no tests/ or __tests__/ directory.`,
          suggestion: 'Create a tests/ directory and add tests.',
        });
        score -= 1;
      }
    }

    // --- Check: God files (content-aware) ---
    // Measured source files (consumed by the size-distribution summary in a later step).
    const measured: MeasuredFile[] = [];
    const godFiles: { path: string; loc: number; tier: GodFileTier }[] = [];

    for (const file of scan.files) {
      // Anti-FP gate: only real production source counts.
      if (!GOD_FILE_SOURCE_EXTS.includes(extname(file))) continue;
      if (classifyFile(file) !== 'source') continue;

      let content: string;
      try {
        content = await readFile(file);
      } catch {
        continue; // unreadable — skip
      }

      const loc = countLoc(content);
      // Skip minified/bundled/data files: not hand-written.
      if (content.length / Math.max(loc, 1) > 500) continue;

      measured.push({ path: file, loc });

      const tier = classifyGodFile(loc);
      if (tier) godFiles.push({ path: file, loc, tier });
    }

    // Emit per-file findings only for low/medium/high (info is metrics-only).
    const findingTiers = ['low', 'medium', 'high'] as const;
    type FindingTier = (typeof findingTiers)[number];
    const reportable = godFiles
      .filter((g): g is { path: string; loc: number; tier: FindingTier } =>
        (findingTiers as readonly string[]).includes(g.tier),
      )
      .sort((a, b) => b.loc - a.loc);

    let godPenalty = 0;
    for (const g of reportable.slice(0, MAX_GOD_FILE_FINDINGS)) {
      const severity = g.tier;
      findings.push({
        id: 'STR-011',
        category: 'structure',
        severity,
        title: `God file: ${g.path} (${g.loc} LOC)`,
        description: `${g.path} has ${g.loc} lines. Large files concentrate responsibilities and make testing and review harder.`,
        file: g.path,
        suggestion: 'Consider splitting this file by responsibility into smaller modules.',
        meta: { loc: g.loc, tier: g.tier },
      });
      godPenalty += GOD_FILE_PENALTY[severity];
    }
    score -= Math.min(godPenalty, GOD_FILE_PENALTY_CAP);
    const godOverflow = Math.max(0, reportable.length - MAX_GOD_FILE_FINDINGS);

    // --- Check: Circular dependencies (TS/JS value-import graph) ---
    const graph = await buildImportGraph(scan.files, readFile);
    const cycles = findCycles(graph);

    let cyclePenalty = 0;
    for (const cycle of cycles.slice(0, MAX_CYCLE_FINDINGS)) {
      const chain = [...cycle, cycle[0]].join(' → ');
      findings.push({
        id: 'STR-012',
        category: 'structure',
        severity: 'medium',
        title: cycle.length === 1 ? `Self-import: ${cycle[0]}` : `Circular dependency (${cycle.length} files)`,
        description: `Circular import chain: ${chain}. Circular dependencies can cause partially-initialized modules at runtime and make the code harder to reason about.`,
        suggestion: 'Break the cycle by extracting shared code into a separate module, or invert one dependency.',
        meta: { cycle },
      });
      cyclePenalty += CYCLE_PENALTY;
    }
    score -= Math.min(cyclePenalty, CYCLE_PENALTY_CAP);
    const cycleOverflow = Math.max(0, cycles.length - MAX_CYCLE_FINDINGS);

    // --- Check: Dead files (never imported, no entry-point heuristic claims them) ---
    const deadResult = await findDeadFiles(scan.files, readFile);
    const dynamicNote = deadResult.hasNonLiteralDynamic
      ? ' Note: this project has dynamic imports PRISM cannot resolve — confirm before deleting.'
      : '';
    let deadPenalty = 0;
    for (const dead of deadResult.dead.slice(0, MAX_DEAD_FILE_FINDINGS)) {
      findings.push({
        id: 'STR-013',
        category: 'structure',
        severity: 'low',
        title: `Dead file: ${dead}`,
        description: `${dead} is never imported (by value or type, including via tsconfig aliases) and is not a recognized entry point.${dynamicNote}`,
        file: dead,
        suggestion: 'Delete it, or wire it back in if it should be used.',
      });
      deadPenalty += DEAD_FILE_PENALTY;
    }
    score -= Math.min(deadPenalty, DEAD_FILE_PENALTY_CAP);
    const deadOverflow = Math.max(0, deadResult.dead.length - MAX_DEAD_FILE_FINDINGS);

    // --- Positive signals ---
    if (scan.meta.hasCi) score = Math.min(10, score + 0.5);
    if (scan.meta.hasDocker) score = Math.min(10, score + 0.3);
    if (hasLinter) score = Math.min(10, score + 0.2);

    return {
      category: 'structure',
      score: Math.max(0, Math.min(10, Math.round(score * 10) / 10)),
      findings,
      summary: buildSummary(
        scan,
        findings,
        computeSizeMetrics(measured),
        godOverflow,
        cycles.length,
        cycleOverflow,
        deadResult,
        deadOverflow,
      ),
    };
  }
}

// --- Helpers ---

function checkNamingConsistency(files: string[]): string[] {
  const issues: string[] = [];
  let kebabCount = 0;
  let camelCount = 0;
  let snakeCount = 0;

  for (const file of files) {
    const name = basename(file, extname(file));
    if (name.includes('-')) kebabCount++;
    if (/[a-z][A-Z]/.test(name)) camelCount++;
    if (name.includes('_') && !name.startsWith('_')) snakeCount++;
  }

  const styles = [
    { name: 'kebab-case', count: kebabCount },
    { name: 'camelCase', count: camelCount },
    { name: 'snake_case', count: snakeCount },
  ].filter((s) => s.count > 0);

  if (styles.length > 1) {
    issues.push(styles.map((s) => `${s.name} (${s.count} files)`).join(' vs '));
  }

  return issues;
}

function findEmptyDirs(tree: FileNode[]): string[] {
  const empty: string[] = [];
  for (const node of tree) {
    if (node.type === 'directory') {
      if (!node.children || node.children.length === 0) {
        empty.push(node.path);
      } else {
        empty.push(...findEmptyDirs(node.children));
      }
    }
  }
  return empty;
}

function buildSummary(
  scan: ProjectScan,
  findings: Finding[],
  metrics: SizeMetrics,
  godOverflow: number,
  cycleCount: number,
  cycleOverflow: number,
  deadResult: DeadFilesResult,
  deadOverflow: number,
): string {
  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const highs = findings.filter((f) => f.severity === 'high').length;
  const parts: string[] = [];

  parts.push(`${scan.meta.totalFiles} files scanned`);
  parts.push(`Stack: ${scan.meta.stack.primary}`);

  if (scan.meta.frameworks.length > 0) {
    parts.push(`Frameworks: ${scan.meta.frameworks.join(', ')}`);
  }

  // Distribution metrics (god files + size distribution).
  if (metrics.fileCount > 0) {
    const k = metrics.totalLoc >= 1000 ? `${(metrics.totalLoc / 1000).toFixed(1)}k LOC` : `${metrics.totalLoc} LOC`;
    parts.push(k);
    parts.push(`${metrics.fileCount} source files`);
    parts.push(`median ${metrics.median} LOC`);
    if (metrics.largest) parts.push(`largest ${metrics.largest.path} (${metrics.largest.loc})`);
    parts.push(`top-5 = ${metrics.top5Pct}% of code`);

    const godCount = findings.filter((f) => f.id === 'STR-011').length;
    if (godCount > 0) parts.push(`${godCount} god file${godCount === 1 ? '' : 's'}`);
    if (godOverflow > 0) parts.push(`${godOverflow} more files exceed 600 LOC`);

    if (cycleCount === 0) {
      parts.push('no circular dependencies');
    } else {
      parts.push(`${cycleCount} circular dependenc${cycleCount === 1 ? 'y' : 'ies'}`);
      if (cycleOverflow > 0) parts.push(`${cycleOverflow} more`);
    }

    if (deadResult.skippedReason) {
      parts.push(deadResult.skippedReason);
    } else if (deadResult.dead.length > 0) {
      parts.push(`${deadResult.dead.length} dead file${deadResult.dead.length === 1 ? '' : 's'}`);
      if (deadOverflow > 0) parts.push(`${deadOverflow} more not listed`);
    }
  }

  if (criticals > 0) parts.push(`${criticals} critical issue${criticals > 1 ? 's' : ''}`);
  if (highs > 0) parts.push(`${highs} high issue${highs > 1 ? 's' : ''}`);
  if (findings.length === 0) parts.push('Clean structure');

  return parts.join(' · ');
}

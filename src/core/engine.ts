import { readFile as fsReadFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { scanProject } from './scanner.js';
import type {
  PrismConfig,
  AuditReport,
  Analyzer,
  AnalyzerResult,
  CategoryScore,
  Finding,
  FileReader,
  SuppressedFinding,
} from './types.js';
import type { LLMClient } from '../ai/types.js';
import { applyAiTriage } from '../ai/run.js';

// Analyzers
import { StructureAnalyzer } from '../analyzers/structure.js';
import { SecretsAnalyzer } from '../analyzers/secrets.js';
import { DependenciesAnalyzer } from '../analyzers/dependencies.js';
import { DockerAnalyzer } from '../analyzers/docker.js';
import { TestsAnalyzer } from '../analyzers/tests.js';
import { ConsistencyAnalyzer } from '../analyzers/consistency.js';
import { AgenticAnalyzer } from '../analyzers/agentic.js';
import { WorkflowAnalyzer } from '../analyzers/workflow.js';

const PRISM_VERSION = '1.2.0';

/** Cap on a single file read — beyond this a "source" file is pathological. */
const MAX_READ_BYTES = 15 * 1024 * 1024;

/** Categories accepted by the `--only` filter (one per static analyzer). */
export const ANALYZER_CATEGORIES = [
  'structure',
  'security',
  'dependencies',
  'docker',
  'tests',
  'consistency',
  'agentic',
  'workflow',
] as const;

/** Weight each category contributes to the overall score */
const CATEGORY_WEIGHTS: Record<string, number> = {
  structure: 1.0,
  security: 2.0, // Security weighs double
  dependencies: 1.5,
  docker: 1.0,
  tests: 1.5,
  consistency: 0.8,
  agentic: 1.5, // AI-agent security risks weigh like tests/deps
  workflow: 1.0, // CI/CD hygiene weighs like docker/structure
  architecture: 2.0, // Future: LLM-powered
};

/** All available analyzers */
function createAnalyzers(): Analyzer[] {
  return [
    new StructureAnalyzer(),
    new SecretsAnalyzer(),
    new DependenciesAnalyzer(),
    new DockerAnalyzer(),
    new TestsAnalyzer(),
    new ConsistencyAnalyzer(),
    new AgenticAnalyzer(),
    new WorkflowAnalyzer(),
  ];
}

/**
 * Run a full PRISM audit on a project.
 *
 * @param config - Audit configuration
 * @param onProgress - Optional callback for progress updates
 * @returns Complete audit report
 */
export async function runAudit(
  config: PrismConfig,
  onProgress?: (message: string) => void,
  injectedClient?: LLMClient,
): Promise<AuditReport> {
  const startedAt = new Date();

  // Phase 1: Scan the project
  onProgress?.('Scanning project structure...');
  const scan = await scanProject(config.targetPath);
  onProgress?.(`Found ${scan.files.length} files · Stack: ${scan.meta.stack.primary}`);

  // Phase 2: Create file reader bound to the project root. A stat guard caps
  // reads so a hostile repo with a huge file can't OOM the process before an
  // analyzer's own size check runs. Analyzers already catch read errors and skip.
  const fileReader: FileReader = async (relativePath: string) => {
    const abs = join(scan.rootPath, relativePath);
    const { size } = await stat(abs);
    if (size > MAX_READ_BYTES) {
      throw new Error(`file too large to read (${size} bytes): ${relativePath}`);
    }
    return fsReadFile(abs, 'utf-8');
  };

  // Phase 3: Run analyzers
  const allAnalyzers = createAnalyzers();
  const analyzersToRun = config.analyzers
    ? allAnalyzers.filter((a) => config.analyzers!.includes(a.category))
    : allAnalyzers;

  let results: AnalyzerResult[] = [];

  for (const analyzer of analyzersToRun) {
    onProgress?.(`Running ${analyzer.name} analyzer...`);
    try {
      const result = await analyzer.analyze(scan, fileReader);
      results.push(result);
      onProgress?.(`  → ${analyzer.name}: ${result.score}/10 (${result.findings.length} findings)`);
    } catch (error) {
      onProgress?.(`  ⚠ ${analyzer.name} failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      results.push({
        category: analyzer.category,
        score: 0,
        findings: [
          {
            id: `${analyzer.name.toUpperCase()}-ERROR`,
            category: analyzer.category,
            severity: 'high',
            title: `${analyzer.name} analyzer failed`,
            description: `Analyzer threw an error: ${error instanceof Error ? error.message : 'Unknown'}`,
            suggestion: 'Check if the project is accessible and try again.',
          },
        ],
        summary: `Analyzer failed: ${error instanceof Error ? error.message : 'Unknown'}`,
      });
    }
  }

  // Phase 3.5: Justified suppressions — silence accepted findings BEFORE
  // scoring, fingerprints, gates, and AI triage (no tokens spent judging a
  // finding the human already ruled on).
  let suppressed: SuppressedFinding[] = [];
  let suppressionWarnings: string[] = [];
  if (config.suppressions && config.suppressions.length > 0) {
    const { applySuppressions } = await import('./suppressions.js');
    const outcome = applySuppressions(results, config.suppressions);
    results = outcome.results;
    suppressed = outcome.suppressed;
    suppressionWarnings = outcome.warnings;
    if (suppressed.length > 0) onProgress?.(`Suppressed ${suppressed.length} finding(s) by config`);
  }

  // Phase 4: Calculate overall score (weighted average)
  const overallScore = calculateOverallScore(results);

  // Phase 5: Compile report
  const completedAt = new Date();

  const categories: CategoryScore[] = results.map((r) => ({
    category: r.category,
    score: r.score,
    maxScore: 10,
    findings: r.findings,
    summary: r.summary,
  }));

  // All findings sorted by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const allFindings: Finding[] = results
    .flatMap((r) => r.findings)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Assign stable fingerprints (robust to line shifts) for baseline/new-code diffing.
  const { assignFingerprints } = await import('./fingerprint.js');
  await assignFingerprints(allFindings, fileReader);

  // Derive project name
  let projectName = scan.rootPath.split('/').pop() || 'unknown';
  try {
    const pkgContent = await fileReader('package.json');
    const pkg = JSON.parse(pkgContent);
    if (pkg.name) projectName = pkg.name;
  } catch {
    /* not a node project or no package.json */
  }

  const report: AuditReport = {
    projectName,
    projectPath: scan.rootPath,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    overallScore,
    categories,
    findings: allFindings,
    projectMeta: scan.meta,
    prismVersion: PRISM_VERSION,
    ...(suppressed.length > 0 ? { suppressed } : {}),
    ...(suppressionWarnings.length > 0 ? { suppressionWarnings } : {}),
  };

  onProgress?.(`Audit complete: ${overallScore}/10 · ${allFindings.length} findings · ${report.durationMs}ms`);

  // Phase 6: AI triage (opt-in). Must never destroy the static report.
  if (config.ai) {
    await applyAiTriage(report, fileReader, config, onProgress, injectedClient);
  }

  return report;
}

function calculateOverallScore(results: AnalyzerResult[]): number {
  let totalWeight = 0;
  let weightedSum = 0;

  for (const result of results) {
    const weight = CATEGORY_WEIGHTS[result.category] || 1.0;
    weightedSum += result.score * weight;
    totalWeight += weight;
  }

  if (totalWeight === 0) return 0;

  const raw = weightedSum / totalWeight;
  return Math.round(raw * 10) / 10;
}

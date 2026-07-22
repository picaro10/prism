// ============================================================
// PRISM — Core Types
// The contract every analyzer, reporter, and the engine share.
// ============================================================

// Type-only import: src/ai/types.ts also imports from here. Both sides use
// `import type`, which TypeScript erases — so there is no runtime cycle.
import type { TriageResult, Remediation } from '../ai/types.js';

/** Severity of an individual finding */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Category of analysis */
export type AnalysisCategory =
  | 'structure'
  | 'security'
  | 'dependencies'
  | 'docker'
  | 'tests'
  | 'consistency'
  | 'agentic' // AI-agent code risks (tools, shell, secrets-in-prompt)
  | 'architecture'; // future: LLM-powered

/** A single finding from an analyzer */
export interface Finding {
  /** Unique ID within the analyzer (e.g. SEC-001) */
  id: string;
  /** Which analyzer produced this */
  category: AnalysisCategory;
  severity: Severity;
  /** Human-readable title */
  title: string;
  /** Detailed description of the issue */
  description: string;
  /** File path relative to project root (if applicable) */
  file?: string;
  /** Line number (if applicable) */
  line?: number;
  /**
   * Disambiguator for findings that would otherwise share an id+file+line
   * (e.g. one DEP-002 per wildcard dependency, all on package.json with no
   * line). Assigned by assignFindingInstances; absent for the common unique
   * case. Only the 2nd+ member of a colliding group carries one.
   */
  instance?: number;
  /** Actionable fix suggestion */
  suggestion?: string;
  /** Metadata the analyzer wants to attach */
  meta?: Record<string, unknown>;
  /**
   * Stable identity robust to line-number shifts (rule + file + normalized
   * flagged line). Assigned by the engine; used by the new-code / baseline gate
   * to tell a genuinely new finding from one that just moved.
   */
  fingerprint?: string;
}

/** Score for a single category (0-10) */
export interface CategoryScore {
  category: AnalysisCategory;
  score: number;
  maxScore: 10;
  findings: Finding[];
  /** Short summary of this category's result */
  summary: string;
}

/** The complete audit report */
export interface AuditReport {
  /** Project name (derived from package.json, directory name, etc.) */
  projectName: string;
  /** Absolute path that was analyzed */
  projectPath: string;
  /** When the audit started */
  startedAt: string;
  /** When the audit completed */
  completedAt: string;
  /** Duration in milliseconds */
  durationMs: number;
  /** Overall score (0-10, weighted average of categories) */
  overallScore: number;
  /** Per-category breakdown */
  categories: CategoryScore[];
  /** Aggregated findings sorted by severity */
  findings: Finding[];
  /** Project metadata discovered during scan */
  projectMeta: ProjectMeta;
  /** PRISM version that produced this report */
  prismVersion: string;
  /** AI triage verdicts (present only when run with --ai). */
  aiTriage?: TriageResult;
  /** AI executive summary prose (present only when run with --ai and summary enabled). */
  aiSummary?: string;
  /** AI fix proposals for confirmed-real findings (present only when run with --ai and remediation enabled). */
  aiRemediation?: Remediation[];
  /** Findings silenced by justified suppressions (present only when any applied). */
  suppressed?: SuppressedFinding[];
  /** Human-facing notices from the suppression pass (expired/stale entries). */
  suppressionWarnings?: string[];
}

/** Metadata about the project discovered by the scanner */
export interface ProjectMeta {
  /** Detected language/runtime */
  stack: DetectedStack;
  /** Total lines of code (excluding node_modules, dist, etc.) */
  totalLoc: number;
  /** Number of source files */
  totalFiles: number;
  /** Whether a git repo was detected */
  hasGit: boolean;
  /** Whether Docker was detected */
  hasDocker: boolean;
  /** Whether a CI/CD config was detected */
  hasCi: boolean;
  /** Detected package manager */
  packageManager?: 'npm' | 'yarn' | 'pnpm' | 'pip' | 'poetry' | 'cargo' | 'unknown';
  /** Frameworks detected */
  frameworks: string[];
}

export interface DetectedStack {
  /** Primary language */
  primary: string;
  /** Other languages found */
  secondary: string[];
  /** Runtime if detected */
  runtime?: string;
}

/** What the project scanner returns before analyzers run */
export interface ProjectScan {
  /** Root path */
  rootPath: string;
  /** All files relative to root (respecting .gitignore) */
  files: string[];
  /** File tree for structure analysis */
  fileTree: FileNode[];
  /** Detected metadata */
  meta: ProjectMeta;
}

export interface FileNode {
  name: string;
  path: string;
  type: 'file' | 'directory';
  size?: number;
  children?: FileNode[];
}

// ============================================================
// Analyzer contract
// ============================================================

export interface AnalyzerResult {
  category: AnalysisCategory;
  score: number;
  findings: Finding[];
  summary: string;
}

export interface Analyzer {
  /** Unique name of this analyzer */
  readonly name: string;
  /** Which category this analyzer contributes to */
  readonly category: AnalysisCategory;
  /** Human-readable description */
  readonly description: string;
  /** Run the analysis. Receives the project scan + file contents reader. */
  analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult>;
}

/** Function to read a file's content by relative path */
export type FileReader = (relativePath: string) => Promise<string>;

// ============================================================
// Suppressions ("accepted findings")
// ============================================================

/**
 * A justified suppression from prism.config.json: silences a specific rule
 * (optionally narrowed to a file pattern) with a mandatory human reason and
 * an optional expiry so exceptions don't outlive their justification.
 */
export interface Suppression {
  /** Rule id to suppress (e.g. "SEC-ENV-VALUE"). */
  rule: string;
  /** Optional file pattern (gitignore syntax) relative to the project root. Omitted = the rule everywhere. */
  file?: string;
  /** Why this finding is accepted — required, this is the "justified" part. */
  reason: string;
  /** Optional YYYY-MM-DD date after which the suppression stops applying. */
  expires?: string;
}

/** A finding removed from the report by a suppression, kept for transparency. */
export interface SuppressedFinding {
  finding: Finding;
  reason: string;
}

// ============================================================
// Engine config
// ============================================================

export interface PrismConfig {
  /** Path to analyze */
  targetPath: string;
  /** Which analyzers to run (empty = all) */
  analyzers?: AnalysisCategory[];
  /** Patterns to ignore beyond .gitignore */
  ignorePatterns?: string[];
  /** Output format */
  output?: 'cli' | 'json' | 'html';
  /** Output file path (for json/html) */
  outputPath?: string;
  /** Verbose logging */
  verbose?: boolean;
  /** Run the AI triage layer after static analysis. */
  ai?: boolean;
  /** Override the triage model (provider-specific default). */
  aiModel?: string;
  /** Which LLM provider backs triage. Defaults to anthropic if ANTHROPIC_API_KEY is set, else openrouter. */
  aiProvider?: 'anthropic' | 'openrouter';
  /** Adversarially re-check false-positive verdicts (default true). */
  aiVerify?: boolean;
  /**
   * Model IDs forming an N-model verification panel for false-positive
   * verdicts (majority vote). Unset = the triage model verifies alone.
   */
  aiVoteModels?: string[];
  /** Max concurrent triage LLM calls (default 5). */
  aiConcurrency?: number;
  /** Generate an AI executive summary after triage (default true when --ai). */
  aiSummary?: boolean;
  /** Propose fixes for confirmed-real findings after triage (default true when --ai). */
  aiRemediate?: boolean;
  /** Use canned AI responses instead of a real provider — no network, no API key. */
  aiDryRun?: boolean;
  /** Justified suppressions (from prism.config.json) applied before scoring/gates/AI. */
  suppressions?: Suppression[];
}

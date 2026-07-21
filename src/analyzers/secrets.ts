import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding } from '../core/types.js';
import { SECRET_PATTERNS, SECRET_SAFE_FILES, shannonEntropy } from '../utils/patterns.js';
import {
  classifyFile,
  isSecurityTool,
  adjustSeverity,
  isExcludedContext,
  type FileContext,
} from '../utils/file-context.js';
import { loadPrismIgnore } from '../utils/prismignore.js';
import { extname, basename } from 'node:path';

/** File extensions worth scanning for secrets */
const SCANNABLE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.java',
  '.kt',
  '.swift',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.ini',
  '.cfg',
  '.env',
  '.sh',
  '.bash',
  '.zsh',
  '.xml',
  '.html',
  '.sql',
  '.tf',
  '.hcl', // terraform
  '.php',
  '.cs',
]);

/** Max file size to scan (2MB) — skip binaries and huge files */
const MAX_FILE_SIZE = 2 * 1024 * 1024;

/** Extensions that are binary / not worth scanning */
const SKIP_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.ico',
  '.webp',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.zip',
  '.tar',
  '.gz',
  '.br',
  '.pdf',
  '.doc',
  '.docx',
  '.mp3',
  '.mp4',
  '.wav',
  '.avi',
  '.lock', // lock files generate false positives
]);

export class SecretsAnalyzer implements Analyzer {
  readonly name = 'secrets';
  readonly category = 'security' as const;
  readonly description = 'Detects hardcoded secrets, API keys, tokens, and credentials';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;

    // --- Check: .env file committed ---
    // Skip .env files in non-user-authored contexts (e.g. a test fixture's .env)
    // so we don't raise a project-level critical for intentional scaffolding.
    const envFiles = scan.files.filter(
      (f) =>
        !isExcludedContext(classifyFile(f)) &&
        (basename(f) === '.env' || (basename(f).startsWith('.env.') && !isSafeEnvFile(f))),
    );

    if (envFiles.length > 0) {
      findings.push({
        id: 'SEC-ENV-COMMITTED',
        category: 'security',
        severity: 'critical',
        title: '.env file present in project',
        description: `Found ${envFiles.length} .env file(s) that may contain secrets: ${envFiles.join(', ')}. If this is a git repo, these may be committed.`,
        suggestion: 'Add .env to .gitignore and use .env.example for templates.',
        meta: { files: envFiles },
      });
      score -= 2;
    }

    // --- Check: .env in .gitignore ---
    if (scan.files.includes('.gitignore')) {
      try {
        const gitignoreContent = await readFile('.gitignore');
        if (!gitignoreContent.includes('.env')) {
          findings.push({
            id: 'SEC-GITIGNORE-ENV',
            category: 'security',
            severity: 'high',
            title: '.env not in .gitignore',
            description: '.gitignore exists but does not exclude .env files.',
            file: '.gitignore',
            suggestion: 'Add .env and .env.* to .gitignore.',
          });
          score -= 1;
        }
      } catch {
        // If we can't read it, skip this check
      }
    }

    // --- Load .prismignore ---
    const prismIgnore = await loadPrismIgnore(scan.rootPath);

    // --- Scan files for secret patterns ---
    const filesToScan = scan.files.filter((f) => shouldScanFile(f));

    for (const file of filesToScan) {
      // Skip files excluded by .prismignore
      if (prismIgnore.ignores(file)) continue;

      // Classify file context
      const context = classifyFile(file);

      // Skip files that don't need secret scanning (single source of truth).
      // (Path-based classifyFile never returns 'security-tool' — that's detected
      // by content below via effectiveContext — so this is behavior-preserving.)
      if (isExcludedContext(context)) {
        continue;
      }

      try {
        const content = await readFile(file);

        // Skip files that are too large
        if (content.length > MAX_FILE_SIZE) continue;

        // Content-based context: detect security tools (scanners, validators)
        const effectiveContext =
          context === 'source' && isSecurityTool(content) ? ('security-tool' as FileContext) : context;

        // Skip security tools entirely — they contain detection patterns, not leaks
        if (effectiveContext === 'security-tool') continue;

        const lines = content.split('\n');

        for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
          const line = lines[lineIdx];

          // Skip comments (basic heuristic)
          const trimmed = line.trim();
          if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
            // Still scan — comments can contain accidentally pasted secrets
            // but we'll reduce severity
          }

          for (const pattern of SECRET_PATTERNS) {
            if (pattern.pattern.test(line)) {
              // False positive check: is this in a safe file?
              if (isSafeFile(file)) continue;

              // False positive check: is this a placeholder/example?
              if (isPlaceholderValue(line)) continue;

              // Adjust severity based on file context
              const adjusted = adjustSeverity(pattern.severity, effectiveContext);
              if (adjusted === null) continue; // Skip this finding entirely

              findings.push({
                id: pattern.id,
                category: 'security',
                severity: adjusted,
                title: `${pattern.name} detected`,
                description: `Possible ${pattern.name.toLowerCase()} found in source code.`,
                file,
                line: lineIdx + 1,
                suggestion: 'Move this value to an environment variable and reference it via process.env.',
                meta: {
                  // Never include the actual secret in the finding!
                  patternName: pattern.name,
                  linePreview: redactLine(line),
                  fileContext: effectiveContext,
                },
              });

              if (adjusted === 'critical') score -= 1.5;
              else if (adjusted === 'high') score -= 1;
              else if (adjusted === 'medium') score -= 0.5;
              else score -= 0.2;
            }
          }

          // --- High entropy string detection ---
          const highEntropyMatches = findHighEntropyStrings(line);
          for (const match of highEntropyMatches) {
            if (isSafeFile(file) || isPlaceholderValue(line)) continue;

            const entropyAdjusted = adjustSeverity('medium', effectiveContext);
            if (entropyAdjusted === null) continue;

            findings.push({
              id: 'SEC-ENTROPY',
              category: 'security',
              severity: entropyAdjusted,
              title: 'High-entropy string (possible secret)',
              description: `A string with unusually high entropy (${match.entropy.toFixed(2)}) was found. This may be a hardcoded secret.`,
              file,
              line: lineIdx + 1,
              suggestion: 'Verify this is not a secret. If it is, move it to an environment variable.',
              meta: { entropy: match.entropy, length: match.length, fileContext: effectiveContext },
            });
            score -= 0.3;
          }
        }
      } catch {
        // File read error — skip silently
      }
    }

    // Deduplicate findings by id+file+line
    const deduped = deduplicateFindings(findings);

    return {
      category: 'security',
      score: Math.max(0, Math.min(10, Math.round(score * 10) / 10)),
      findings: deduped,
      summary: buildSummary(deduped, filesToScan.length),
    };
  }
}

// --- Helpers ---

function shouldScanFile(filePath: string): boolean {
  const ext = extname(filePath);
  if (SKIP_EXTENSIONS.has(ext)) return false;

  // Scan files with known extensions, or extensionless configs
  if (SCANNABLE_EXTENSIONS.has(ext)) return true;

  // Also scan files that look like configs
  const name = basename(filePath);
  if (name.startsWith('.env')) return true;
  if (name === 'Dockerfile' || name === 'Makefile') return true;

  return false;
}

function isSafeFile(filePath: string): boolean {
  const name = basename(filePath);
  return SECRET_SAFE_FILES.some((safe) => {
    if (safe.startsWith('*')) {
      return name.endsWith(safe.slice(1));
    }
    return name === safe;
  });
}

function isSafeEnvFile(filePath: string): boolean {
  const name = basename(filePath);
  return name === '.env.example' || name === '.env.template' || name === '.env.sample';
}

function isPlaceholderValue(line: string): boolean {
  const lower = line.toLowerCase();
  return (
    lower.includes('your_') ||
    lower.includes('xxx') ||
    lower.includes('placeholder') ||
    lower.includes('example') ||
    lower.includes('changeme') ||
    lower.includes('todo') ||
    lower.includes('replace_') ||
    lower.includes('<your') ||
    lower.includes('${') || // Template literals / env var references
    lower.includes('process.env') ||
    lower.includes('os.environ') ||
    lower.includes('os.getenv')
  );
}

/**
 * Find high-entropy strings in a line that look like they could be secrets.
 * We look for quoted strings of 20+ chars with entropy > 4.5.
 */
function findHighEntropyStrings(line: string): { entropy: number; length: number }[] {
  const results: { entropy: number; length: number }[] = [];

  // Match quoted strings of 20+ chars
  const stringPattern = /['"]([A-Za-z0-9+/=_\-]{20,})['"]/g;
  let match: RegExpExecArray | null;

  while ((match = stringPattern.exec(line)) !== null) {
    const value = match[1];
    const entropy = shannonEntropy(value);

    if (entropy > 4.5 && value.length >= 20) {
      results.push({ entropy, length: value.length });
    }
  }

  return results;
}

/** Redact sensitive parts of a line for safe reporting */
function redactLine(line: string): string {
  const trimmed = line.trim();
  // Replace URIs with credentials
  let redacted = trimmed.replace(/(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+/gi, '[REDACTED_URI]');
  // Replace quoted strings that look like secrets (20+ chars)
  redacted = redacted.replace(/(['"])[A-Za-z0-9+/=_\-]{20,}\1/g, '"[REDACTED]"');
  // Replace values after = or :
  redacted = redacted.replace(/(?<=[=:]\s*['"]?)[A-Za-z0-9+/=_\-]{16,}(?=['"]?)/g, '[REDACTED]');
  // If still too long, truncate
  if (redacted.length > 120) {
    return `${redacted.substring(0, 50)}...[REDACTED]`;
  }
  return redacted;
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.id}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildSummary(findings: Finding[], filesScanned: number): string {
  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const highs = findings.filter((f) => f.severity === 'high').length;

  const parts: string[] = [`${filesScanned} files scanned for secrets`];

  if (findings.length === 0) {
    parts.push('No secrets detected');
  } else {
    parts.push(`${findings.length} potential secret(s) found`);
    if (criticals > 0) parts.push(`${criticals} critical`);
    if (highs > 0) parts.push(`${highs} high`);
  }

  return parts.join(' · ');
}

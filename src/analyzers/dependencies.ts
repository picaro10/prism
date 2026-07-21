import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding } from '../core/types.js';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { existsSync } from 'node:fs';

export class DependenciesAnalyzer implements Analyzer {
  readonly name = 'dependencies';
  readonly category = 'dependencies' as const;
  readonly description = 'Audits project dependencies for vulnerabilities, unused packages, and hygiene';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;

    // Node.js projects
    if (scan.files.includes('package.json')) {
      const nodeFindings = await this.analyzeNode(scan, readFile);
      findings.push(...nodeFindings.findings);
      score += nodeFindings.scoreDelta;
    }

    // Python projects
    if (scan.files.includes('requirements.txt') || scan.files.includes('pyproject.toml')) {
      const pyFindings = await this.analyzePython(scan, readFile);
      findings.push(...pyFindings.findings);
      score += pyFindings.scoreDelta;
    }

    return {
      category: 'dependencies',
      score: Math.max(0, Math.min(10, Math.round(score * 10) / 10)),
      findings,
      summary: buildSummary(findings, scan),
    };
  }

  private async analyzeNode(
    scan: ProjectScan,
    readFile: FileReader,
  ): Promise<{ findings: Finding[]; scoreDelta: number }> {
    const findings: Finding[] = [];
    let scoreDelta = 0;

    try {
      const pkgContent = await readFile('package.json');
      const pkg = JSON.parse(pkgContent);

      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      // --- Check: No lock file ---
      const hasLockFile =
        scan.files.includes('package-lock.json') ||
        scan.files.includes('yarn.lock') ||
        scan.files.includes('pnpm-lock.yaml');

      if (!hasLockFile) {
        findings.push({
          id: 'DEP-001',
          category: 'dependencies',
          severity: 'high',
          title: 'No lock file found',
          description: 'No package-lock.json, yarn.lock, or pnpm-lock.yaml. Builds are not reproducible.',
          file: 'package.json',
          suggestion: 'Run npm install to generate a lock file and commit it.',
        });
        scoreDelta -= 1.5;
      }

      // --- Check: Wildcard versions ---
      for (const [name, version] of Object.entries(allDeps)) {
        const v = String(version);
        if (v === '*' || v === 'latest') {
          findings.push({
            id: 'DEP-002',
            category: 'dependencies',
            severity: 'high',
            title: `Wildcard version for ${name}`,
            description: `Package "${name}" uses "${v}" — this is unpredictable and dangerous.`,
            file: 'package.json',
            suggestion: `Pin to a specific version range (e.g., "^1.0.0").`,
          });
          scoreDelta -= 0.5;
        }
      }

      // --- Check: Suspiciously high number of dependencies ---
      const depCount = Object.keys(pkg.dependencies || {}).length;

      if (depCount > 30) {
        findings.push({
          id: 'DEP-003',
          category: 'dependencies',
          severity: 'medium',
          title: 'High dependency count',
          description: `${depCount} production dependencies. More dependencies = larger attack surface + more maintenance.`,
          file: 'package.json',
          suggestion: 'Review if all dependencies are actually used. Consider native alternatives.',
          meta: { count: depCount },
        });
        scoreDelta -= 0.5;
      }

      // --- Check: No engines field ---
      if (!pkg.engines) {
        findings.push({
          id: 'DEP-004',
          category: 'dependencies',
          severity: 'low',
          title: 'No engines field in package.json',
          description:
            'No Node.js version requirement specified. Different environments may use incompatible versions.',
          file: 'package.json',
          suggestion: 'Add "engines": { "node": ">=22.0.0" } to package.json.',
        });
        scoreDelta -= 0.3;
      }

      // --- Check: npm audit (if lock file exists and npm is available) ---
      if (hasLockFile && existsSync(join(scan.rootPath, 'package-lock.json'))) {
        // npm audit exits non-zero PRECISELY when it finds vulnerabilities, so
        // execSync throws on exactly the cases we care about — but the JSON
        // report is still on stdout. Read it from both success and error.
        let auditJson: string | undefined;
        try {
          auditJson = execSync('npm audit --json', {
            cwd: scan.rootPath,
            timeout: 30_000,
            encoding: 'utf-8',
            stdio: ['ignore', 'pipe', 'ignore'],
            // The analyzed repo is untrusted: a malicious .npmrc in it could
            // point registry= at an attacker host and exfiltrate the dep tree.
            // env config outranks the repo's .npmrc, so pin the public registry.
            env: { ...process.env, npm_config_registry: 'https://registry.npmjs.org/' },
          });
        } catch (err) {
          const stdout = (err as { stdout?: string | Buffer } | null)?.stdout;
          if (stdout) auditJson = stdout.toString();
        }

        let vulnCount: { critical?: number; high?: number } | undefined;
        if (auditJson) {
          try {
            vulnCount = JSON.parse(auditJson)?.metadata?.vulnerabilities;
          } catch {
            // unparseable output — treated as "could not run" below
          }
        }

        if (vulnCount) {
          if ((vulnCount.critical ?? 0) > 0) {
            findings.push({
              id: 'DEP-AUDIT-CRITICAL',
              category: 'dependencies',
              severity: 'critical',
              title: `${vulnCount.critical} critical npm vulnerabilities`,
              description: `npm audit found ${vulnCount.critical} critical vulnerabilities.`,
              suggestion: 'Run npm audit fix or update affected packages.',
              meta: { vulnerabilities: vulnCount },
            });
            scoreDelta -= 2;
          }

          if ((vulnCount.high ?? 0) > 0) {
            findings.push({
              id: 'DEP-AUDIT-HIGH',
              category: 'dependencies',
              severity: 'high',
              title: `${vulnCount.high} high npm vulnerabilities`,
              description: `npm audit found ${vulnCount.high} high-severity vulnerabilities.`,
              suggestion: 'Run npm audit fix.',
              meta: { vulnerabilities: vulnCount },
            });
            scoreDelta -= 1;
          }
        } else {
          // npm missing, no network for the advisory db, or unparseable output
          findings.push({
            id: 'DEP-AUDIT-SKIP',
            category: 'dependencies',
            severity: 'info',
            title: 'npm audit could not run',
            description: 'Could not execute npm audit. Install dependencies first or run manually.',
            suggestion: 'Run npm install && npm audit manually.',
          });
        }
      }

      // --- Check: scripts.test exists ---
      if (!pkg.scripts?.test || pkg.scripts.test.includes('no test specified')) {
        findings.push({
          id: 'DEP-005',
          category: 'dependencies',
          severity: 'medium',
          title: 'No test script defined',
          description: 'package.json has no valid test script.',
          file: 'package.json',
          suggestion: 'Add a test script that runs your test suite.',
        });
        scoreDelta -= 0.5;
      }
    } catch {
      findings.push({
        id: 'DEP-PARSE-ERR',
        category: 'dependencies',
        severity: 'high',
        title: 'Could not parse package.json',
        description: 'package.json exists but could not be parsed. It may be malformed.',
        file: 'package.json',
        suggestion: 'Validate your package.json with jsonlint or similar.',
      });
      scoreDelta -= 2;
    }

    return { findings, scoreDelta };
  }

  private async analyzePython(
    scan: ProjectScan,
    readFile: FileReader,
  ): Promise<{ findings: Finding[]; scoreDelta: number }> {
    const findings: Finding[] = [];
    let scoreDelta = 0;

    // --- Check: requirements.txt pinning ---
    if (scan.files.includes('requirements.txt')) {
      try {
        const content = await readFile('requirements.txt');
        const lines = content.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));

        const unpinned = lines.filter((l) => !l.includes('==') && !l.includes('>=') && !l.includes('~='));

        if (unpinned.length > 0) {
          findings.push({
            id: 'DEP-PY-001',
            category: 'dependencies',
            severity: 'medium',
            title: 'Unpinned Python dependencies',
            description: `${unpinned.length} packages without version pinning: ${unpinned.slice(0, 5).join(', ')}`,
            file: 'requirements.txt',
            suggestion: 'Pin all dependencies to specific versions (e.g., requests==2.31.0).',
            meta: { unpinned: unpinned.slice(0, 10) },
          });
          scoreDelta -= 0.5;
        }
      } catch {
        /* skip */
      }
    }

    return { findings, scoreDelta };
  }
}

function buildSummary(findings: Finding[], scan: ProjectScan): string {
  const parts: string[] = [];

  if (scan.meta.packageManager) {
    parts.push(`Package manager: ${scan.meta.packageManager}`);
  }

  const criticals = findings.filter((f) => f.severity === 'critical').length;
  if (criticals > 0) parts.push(`${criticals} critical`);
  if (findings.length === 0) parts.push('Dependencies look healthy');
  else parts.push(`${findings.length} issue(s) found`);

  return parts.join(' · ');
}

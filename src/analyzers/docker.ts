import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding } from '../core/types.js';
import { basename } from 'node:path';
import { classifyFile, isExcludedContext } from '../utils/file-context.js';

/**
 * DockerAnalyzer — Audits Dockerfiles, docker-compose configs, and container best practices.
 *
 * Checks:
 * - Running as root (no USER directive)
 * - No multi-stage build (bloated images)
 * - Using :latest tag (non-reproducible builds)
 * - No .dockerignore
 * - No HEALTHCHECK
 * - COPY . . without .dockerignore (copies secrets, node_modules, etc.)
 * - Exposing unnecessary ports
 * - docker-compose: no resource limits, no restart policy, privileged mode
 * - docker-compose: hardcoded credentials in environment
 */
export class DockerAnalyzer implements Analyzer {
  readonly name = 'docker';
  readonly category = 'docker' as const;
  readonly description = 'Audits Dockerfiles and docker-compose for security and best practices';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;

    // If no Docker at all, skip gracefully
    if (!scan.meta.hasDocker) {
      return {
        category: 'docker',
        score: 10,
        findings: [],
        summary: 'No Docker configuration found — skipped',
      };
    }

    // Find all Dockerfiles and compose files. Skip files in non-user-authored
    // contexts (test fixtures, templates, vendored/generated) — a deliberately
    // bad Dockerfile used as a test fixture is not a real finding.
    const isReal = (f: string) => !isExcludedContext(classifyFile(f));
    const dockerfiles = scan.files.filter(
      (f) => isReal(f) && (basename(f) === 'Dockerfile' || basename(f).startsWith('Dockerfile.')),
    );
    const composeFiles = scan.files.filter(
      (f) =>
        isReal(f) &&
        (basename(f) === 'docker-compose.yml' ||
          basename(f) === 'docker-compose.yaml' ||
          basename(f).match(/^docker-compose\..+\.ya?ml$/)),
    );
    const hasDockerignore = scan.files.some((f) => basename(f) === '.dockerignore');

    // --- Check: .dockerignore ---
    if (!hasDockerignore && dockerfiles.length > 0) {
      findings.push({
        id: 'DOC-001',
        category: 'docker',
        severity: 'high',
        title: 'Missing .dockerignore',
        description:
          'No .dockerignore found. COPY/ADD commands may include node_modules, .env, .git, and other unwanted files in the image.',
        suggestion: 'Create a .dockerignore with: node_modules, .git, .env*, dist, coverage, *.log',
      });
      score -= 1.5;
    }

    // --- Analyze each Dockerfile ---
    for (const dockerfile of dockerfiles) {
      try {
        const content = await readFile(dockerfile);
        const dfFindings = analyzeDockerfile(dockerfile, content);
        findings.push(...dfFindings.findings);
        score += dfFindings.scoreDelta;
      } catch {
        // Can't read — skip
      }
    }

    // --- Analyze each docker-compose file ---
    for (const composeFile of composeFiles) {
      try {
        const content = await readFile(composeFile);
        const dcFindings = analyzeCompose(composeFile, content);
        findings.push(...dcFindings.findings);
        score += dcFindings.scoreDelta;
      } catch {
        // Can't read — skip
      }
    }

    return {
      category: 'docker',
      score: Math.max(0, Math.min(10, Math.round(score * 10) / 10)),
      findings,
      summary: buildSummary(dockerfiles.length, composeFiles.length, findings),
    };
  }
}

// ============================================================
// Dockerfile analysis
// ============================================================

function analyzeDockerfile(file: string, content: string): { findings: Finding[]; scoreDelta: number } {
  const findings: Finding[] = [];
  let scoreDelta = 0;
  const lines = content.split('\n');

  // --- Check: Running as root ---
  const hasUser = lines.some((l) => /^\s*USER\s+/i.test(l));
  if (!hasUser) {
    findings.push({
      id: 'DOC-010',
      category: 'docker',
      severity: 'high',
      title: 'Container runs as root',
      description: `${file}: No USER directive found. Container will run as root, increasing attack surface.`,
      file,
      suggestion: 'Add USER node (or a non-root user) before the CMD/ENTRYPOINT.',
    });
    scoreDelta -= 1.5;
  }

  // --- Check: No multi-stage build ---
  const fromCount = lines.filter((l) => /^\s*FROM\s+/i.test(l)).length;
  if (fromCount === 1 && content.includes('npm') && !content.includes('AS ')) {
    findings.push({
      id: 'DOC-011',
      category: 'docker',
      severity: 'medium',
      title: 'No multi-stage build',
      description: `${file}: Single FROM stage with npm detected. Build dependencies end up in the production image, increasing size and attack surface.`,
      file,
      suggestion: 'Use multi-stage: build in one stage, copy only the output to a slim production stage.',
    });
    scoreDelta -= 0.5;
  }

  // --- Check: Using :latest tag ---
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (/^\s*FROM\s+\S+:latest/i.test(line) || /^\s*FROM\s+[^:@\s]+\s*$/i.test(line)) {
      // FROM image (no tag) or FROM image:latest
      const isLatest = line.includes(':latest') || !line.includes(':');
      if (isLatest && !line.includes('AS ') && !line.includes(' as ')) {
        findings.push({
          id: 'DOC-012',
          category: 'docker',
          severity: 'medium',
          title: 'Using :latest or untagged base image',
          description: `${file}:${i + 1}: Base image without pinned version. Builds are not reproducible.`,
          file,
          line: i + 1,
          suggestion: 'Pin to a specific version (e.g., node:22-slim instead of node:latest).',
        });
        scoreDelta -= 0.5;
        break; // One finding per Dockerfile for this
      }
    }
  }

  // --- Check: No HEALTHCHECK ---
  const hasHealthcheck = lines.some((l) => /^\s*HEALTHCHECK\s+/i.test(l));
  if (!hasHealthcheck) {
    findings.push({
      id: 'DOC-013',
      category: 'docker',
      severity: 'low',
      title: 'No HEALTHCHECK defined',
      description: `${file}: No HEALTHCHECK instruction. Orchestrators cannot determine if the container is healthy.`,
      file,
      suggestion: 'Add HEALTHCHECK --interval=30s CMD curl -f http://localhost:PORT/health || exit 1',
    });
    scoreDelta -= 0.3;
  }

  // --- Check: COPY . . without dockerignore context ---
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (/^\s*COPY\s+\.\s+\./i.test(line)) {
      findings.push({
        id: 'DOC-014',
        category: 'docker',
        severity: 'medium',
        title: 'COPY . . copies entire context',
        description: `${file}:${i + 1}: COPY . . includes everything in the build context. Without a proper .dockerignore, this may include .env, .git, node_modules.`,
        file,
        line: i + 1,
        suggestion: 'Use specific COPY paths or ensure .dockerignore excludes sensitive/unnecessary files.',
      });
      scoreDelta -= 0.5;
      break;
    }
  }

  // --- Check: apt-get without cleanup ---
  if (content.includes('apt-get install') && !content.includes('rm -rf /var/lib/apt')) {
    findings.push({
      id: 'DOC-015',
      category: 'docker',
      severity: 'low',
      title: 'apt-get without cache cleanup',
      description: `${file}: apt-get install found without rm -rf /var/lib/apt/lists/*. Image size is unnecessarily bloated.`,
      file,
      suggestion: 'Add && rm -rf /var/lib/apt/lists/* after apt-get install in the same RUN layer.',
    });
    scoreDelta -= 0.2;
  }

  // --- Positive: slim/alpine base ---
  if (content.includes('-slim') || content.includes('-alpine') || content.includes('distroless')) {
    scoreDelta += 0.3;
  }

  return { findings, scoreDelta };
}

// ============================================================
// docker-compose analysis
// ============================================================

function analyzeCompose(file: string, content: string): { findings: Finding[]; scoreDelta: number } {
  const findings: Finding[] = [];
  let scoreDelta = 0;
  const lines = content.split('\n');

  // --- Check: privileged mode ---
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*privileged:\s*true/i.test(lines[i])) {
      findings.push({
        id: 'DOC-020',
        category: 'docker',
        severity: 'critical',
        title: 'Container running in privileged mode',
        description: `${file}:${i + 1}: privileged: true gives the container full host access. This is a major security risk.`,
        file,
        line: i + 1,
        suggestion: 'Remove privileged: true. Use specific capabilities (cap_add) instead if needed.',
      });
      scoreDelta -= 2;
    }
  }

  // --- Check: hardcoded passwords in environment ---
  const envPasswordPattern = /^\s*-?\s*\S*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)\s*[:=]\s*\S+/i;
  for (let i = 0; i < lines.length; i++) {
    if (envPasswordPattern.test(lines[i])) {
      // Skip if it references a variable (${ or $)
      if (lines[i].includes('${') || lines[i].includes('$')) continue;

      // Skip if the value is a file/mount path (Docker secrets pattern)
      // e.g., "./secrets/orion_api_token" or "/run/secrets/db_password"
      const valueMatch = lines[i].match(/[:=]\s*(.+)/);
      if (valueMatch) {
        const value = valueMatch[1].trim().replace(/['"]/g, '');
        if (value.startsWith('./') || value.startsWith('/') || value.includes('/secrets/')) {
          continue; // This is a mount path or Docker secrets reference, not a hardcoded value
        }
      }

      findings.push({
        id: 'DOC-021',
        category: 'docker',
        severity: 'high',
        title: 'Hardcoded credential in docker-compose',
        description: `${file}:${i + 1}: Password or secret appears hardcoded in docker-compose environment.`,
        file,
        line: i + 1,
        suggestion: 'Use environment variable references: ${DB_PASSWORD} and define in .env file.',
      });
      scoreDelta -= 1;
    }
  }

  // --- Check: no restart policy ---
  if (!content.includes('restart:')) {
    findings.push({
      id: 'DOC-022',
      category: 'docker',
      severity: 'low',
      title: 'No restart policy defined',
      description: `${file}: No restart policy on any service. Containers won't auto-recover from crashes.`,
      file,
      suggestion: 'Add restart: unless-stopped or restart: on-failure to production services.',
    });
    scoreDelta -= 0.3;
  }

  // --- Check: no resource limits ---
  if (!content.includes('mem_limit') && !content.includes('memory:') && !content.includes('deploy:')) {
    findings.push({
      id: 'DOC-023',
      category: 'docker',
      severity: 'low',
      title: 'No resource limits defined',
      description: `${file}: No memory or CPU limits. A runaway container can consume all host resources.`,
      file,
      suggestion: 'Add deploy.resources.limits or mem_limit/cpus per service.',
    });
    scoreDelta -= 0.2;
  }

  // --- Check: exposed ports without binding to specific interface ---
  const portAllInterfaces = /^\s*-\s*["']?\d+:\d+["']?\s*$/;
  for (let i = 0; i < lines.length; i++) {
    if (portAllInterfaces.test(lines[i])) {
      findings.push({
        id: 'DOC-024',
        category: 'docker',
        severity: 'medium',
        title: 'Port exposed on all interfaces',
        description: `${file}:${i + 1}: Port binding without interface restriction (0.0.0.0). Service is accessible from any network.`,
        file,
        line: i + 1,
        suggestion: 'Bind to 127.0.0.1 for internal services: "127.0.0.1:5432:5432".',
      });
      scoreDelta -= 0.5;
      break; // One finding per file
    }
  }

  return { findings, scoreDelta };
}

function buildSummary(dockerfileCount: number, composeCount: number, findings: Finding[]): string {
  const parts: string[] = [];
  parts.push(`${dockerfileCount} Dockerfile(s), ${composeCount} compose file(s) analyzed`);

  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const highs = findings.filter((f) => f.severity === 'high').length;

  if (findings.length === 0) {
    parts.push('Docker config looks solid');
  } else {
    if (criticals > 0) parts.push(`${criticals} critical`);
    if (highs > 0) parts.push(`${highs} high`);
    parts.push(`${findings.length} total findings`);
  }

  return parts.join(' · ');
}

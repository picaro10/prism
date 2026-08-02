// ============================================================
// PRISM — OSV Analyzer (dependencies category)
//
// Multi-ecosystem SCA via OSV.dev: parses pinned lockfiles for Python,
// Rust, Go, PHP and Ruby (npm stays with `npm audit`) and queries the
// public OSV API for known vulnerabilities. Merges into the same
// `dependencies` category as the npm analyzer, with the same philosophy:
// critical/high advisories become findings with score penalties, an API
// that could not be reached reports UNKNOWN (never clean), and — the Day-6
// lesson — this is a *dynamic external signal*: it informs; nobody should
// gate CI on its raw counts (the `--fail-on critical` hard door aside,
// same as DEP-AUDIT-CRITICAL).
// ============================================================

import { basename } from 'node:path';
import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding } from '../core/types.js';
import { classifyFile, isExcludedContext } from '../utils/file-context.js';
import { mapWithConcurrency } from '../utils/concurrency.js';
import { parseLockfile, LOCKFILE_PARSERS, type LockedPackage } from './osv-lockfiles.js';

/** Injectable seam over global fetch — tests fake the OSV API with it. */
export type OsvFetch = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

const OSV_API = 'https://api.osv.dev';
const QUERY_CHUNK = 500; // OSV querybatch hard limit is 1000
const MAX_PACKAGES = 2000;
/**
 * Lockfile names where parsing to zero packages is NORMAL, not a coverage gap:
 * requirements.txt with only version ranges (unpinned — DEP-PY-001's job) and
 * go.mod with no `require` block. Flagging these as DEP-OSV-INCOMPLETE was a
 * false positive on ordinary projects.
 */
const ZERO_YIELD_IS_NORMAL = new Set(['requirements.txt', 'go.mod']);
/**
 * Detail lookups per run. This is a budget on TRUTH, not on noise: whatever
 * falls outside is reported as explicitly unclassified (DEP-OSV-UNKNOWN,
 * medium) — never quietly folded into the low bucket. Sized so a realistic
 * dependency tree gets fully classified (measured: 236 advisories across 10
 * stale Python packages).
 */
const MAX_VULN_DETAILS = 300;
const DETAIL_CONCURRENCY = 8;
const REQUEST_TIMEOUT_MS = 15_000;

const defaultFetch: OsvFetch = (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });

interface VulnerablePackage {
  pkg: LockedPackage;
  file: string;
  vulnIds: string[];
}

type OsvSeverity = 'critical' | 'high' | 'lower' | 'unknown';

export class OsvAnalyzer implements Analyzer {
  readonly name = 'osv';
  readonly category = 'dependencies' as const;
  readonly description = 'Multi-ecosystem known-vulnerability check (Python/Rust/Go/PHP/Ruby) via OSV.dev';

  constructor(private readonly fetchImpl: OsvFetch = defaultFetch) {}

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const { packages, files, zeroYield, droppedByCap } = await this.collectPackages(scan, readFile);
    const incomplete = incompleteFinding(zeroYield, droppedByCap);
    if (packages.length === 0) {
      if (incomplete) {
        return this.result(9.5, [incomplete], `OSV: 0 packages checked · ${incompleteNote(zeroYield, droppedByCap)}`);
      }
      return this.result(10, [], 'OSV: no non-npm lockfiles to check');
    }

    let vulnerable: VulnerablePackage[];
    try {
      vulnerable = await this.queryBatch(packages);
    } catch {
      return this.result(
        9,
        [
          {
            id: 'DEP-OSV-SKIP',
            category: 'dependencies',
            severity: 'low',
            title: 'OSV.dev could not be queried — vulnerability status UNKNOWN',
            description: `${packages.length} locked package(s) from ${files.join(', ')} could not be checked against OSV.dev (offline or API unreachable). Known-vulnerability status is unknown, not clean.`,
            suggestion: 'Re-run PRISM with network access, or check the lockfiles with osv-scanner locally.',
            meta: { engine: 'osv', files },
          },
        ],
        'OSV unreachable — advisory status unknown',
      );
    }

    if (vulnerable.length === 0) {
      if (incomplete) {
        return this.result(
          9.5,
          [incomplete],
          `OSV: ${packages.length} package(s) across ${files.length} lockfile(s) — no known vulnerabilities · ${incompleteNote(zeroYield, droppedByCap)}`,
        );
      }
      return this.result(
        10,
        [],
        `OSV: ${packages.length} package(s) across ${files.length} lockfile(s) — no known vulnerabilities`,
      );
    }

    const vulnCount = new Set(vulnerable.flatMap((v) => v.vulnIds)).size;
    const truncatedCount = Math.max(0, vulnCount - MAX_VULN_DETAILS);
    const severityByVuln = await this.classifyVulns(vulnerable);
    const findings = this.buildFindings(vulnerable, severityByVuln, truncatedCount);

    if (incomplete) findings.push(incomplete);

    let score = 10;
    for (const f of findings) {
      if (f.id === 'DEP-OSV-CRITICAL') score -= 2;
      else if (f.id === 'DEP-OSV-HIGH') score -= 1;
      // Unclassified advisories carry a real penalty — the same weight the
      // dependencies analyzer gives an audit that could not run at all.
      else if (f.id === 'DEP-OSV-UNKNOWN') score -= 1;
      else if (f.id === 'DEP-OSV-INCOMPLETE') score -= 0.5;
      else score -= 0.2;
    }
    score = Math.max(0, Math.round(score * 10) / 10);

    const unclassified = findings.find((f) => f.id === 'DEP-OSV-UNKNOWN')?.meta?.count;
    return this.result(
      score,
      findings,
      `OSV: ${vulnCount} known advisories across ${vulnerable.length} of ${packages.length} package(s)${
        unclassified ? ` · ${unclassified} unclassified (severity unknown)` : ''
      }${incomplete ? ` · ${incompleteNote(zeroYield, droppedByCap)}` : ''}`,
    );
  }

  private async collectPackages(
    scan: ProjectScan,
    readFile: FileReader,
  ): Promise<{ packages: VulnerablePackage[]; files: string[]; zeroYield: string[]; droppedByCap: number }> {
    const packages: VulnerablePackage[] = [];
    const files: string[] = [];
    // Coverage gaps must be REPORTED, not silently absorbed: a lockfile that
    // was unreadable or yielded nothing (unparseable/empty), and packages
    // dropped past the MAX_PACKAGES cap, are unchecked — unknown, not clean.
    const zeroYield: string[] = [];
    let droppedByCap = 0;
    const seen = new Set<string>();
    for (const file of scan.files) {
      if (!(basename(file) in LOCKFILE_PARSERS)) continue;
      if (isExcludedContext(classifyFile(file))) continue;
      let content: string;
      try {
        content = await readFile(file);
      } catch {
        zeroYield.push(file);
        continue;
      }
      // A genuinely empty lockfile has zero deps — nothing unchecked. Only a
      // NON-empty file that yields no packages is a parse-coverage gap...
      if (content.trim() === '') continue;
      const parsed = parseLockfile(basename(file), content);
      if (parsed.length > 0) files.push(file);
      // ...EXCEPT requirements.txt/go.mod, where yielding zero is normal, not a
      // parse failure: the requirements parser accepts only exact `==` pins (a
      // ranges-only file is legitimately unpinned — DEP-PY-001 covers that) and
      // a go.mod may have no `require` block. Flagging those as "incomplete"
      // was a false positive on ordinary Python/Go projects.
      else if (!ZERO_YIELD_IS_NORMAL.has(basename(file))) zeroYield.push(file);
      for (const pkg of parsed) {
        const key = `${pkg.ecosystem}|${pkg.name}|${pkg.version}`;
        if (seen.has(key)) continue; // duplicate of an already-seen package → not a new drop
        if (seen.size >= MAX_PACKAGES) {
          seen.add(key); // remember it so further copies don't recount the drop
          droppedByCap++;
          continue;
        }
        seen.add(key);
        packages.push({ pkg, file, vulnIds: [] });
      }
    }
    return { packages, files, zeroYield, droppedByCap };
  }

  /** POST /v1/querybatch in chunks; fills vulnIds and returns the hit entries. */
  private async queryBatch(packages: VulnerablePackage[]): Promise<VulnerablePackage[]> {
    for (let i = 0; i < packages.length; i += QUERY_CHUNK) {
      const chunk = packages.slice(i, i + QUERY_CHUNK);
      const body = JSON.stringify({
        queries: chunk.map((p) => ({
          package: { name: p.pkg.name, ecosystem: p.pkg.ecosystem },
          version: p.pkg.version,
        })),
      });
      const res = await this.fetchImpl(`${OSV_API}/v1/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status}`);
      const data = (await res.json()) as { results?: { vulns?: { id?: string }[] }[] };
      if (!Array.isArray(data.results) || data.results.length !== chunk.length) {
        throw new Error('OSV querybatch: malformed response');
      }
      for (let j = 0; j < chunk.length; j++) {
        const vulns = data.results[j]?.vulns;
        if (Array.isArray(vulns)) {
          chunk[j].vulnIds = vulns.map((v) => v.id).filter((id): id is string => typeof id === 'string');
        }
      }
    }
    return packages.filter((p) => p.vulnIds.length > 0);
  }

  /**
   * GET /v1/vulns/{id} for up to MAX_VULN_DETAILS unique advisories, following
   * the `aliases` chain when the primary entry carries no severity: roughly
   * half of PyPI advisories are `PYSEC-*` records that mirror a `GHSA-*` one,
   * and only the GHSA side has `database_specific.severity`. Anything still
   * unresolved stays `unknown` — which is a REPORTED state, not a low one.
   */
  private async classifyVulns(vulnerable: VulnerablePackage[]): Promise<Map<string, OsvSeverity>> {
    const uniqueIds = [...new Set(vulnerable.flatMap((v) => v.vulnIds))];
    const toFetch = uniqueIds.slice(0, MAX_VULN_DETAILS);
    const severityByVuln = new Map<string, OsvSeverity>(uniqueIds.map((id) => [id, 'unknown' as const]));

    const severityOf = async (id: string): Promise<{ severity?: string; aliases: string[] }> => {
      const res = await this.fetchImpl(`${OSV_API}/v1/vulns/${encodeURIComponent(id)}`);
      if (!res.ok) return { aliases: [] };
      const data = (await res.json()) as { database_specific?: { severity?: unknown }; aliases?: unknown };
      const raw = data.database_specific?.severity;
      return {
        ...(typeof raw === 'string' ? { severity: raw } : {}),
        aliases: Array.isArray(data.aliases) ? data.aliases.filter((a): a is string => typeof a === 'string') : [],
      };
    };

    await mapWithConcurrency(toFetch, DETAIL_CONCURRENCY, async (id) => {
      try {
        let { severity, aliases } = await severityOf(id);
        if (severity === undefined) {
          // One hop only, and only to a GHSA record (the one ecosystem that
          // reliably publishes a severity) — keeps the request budget bounded.
          const ghsa = aliases.find((a) => a.startsWith('GHSA-'));
          if (ghsa) severity = (await severityOf(ghsa)).severity;
        }
        if (severity === undefined) return;
        const s = severity.toUpperCase();
        if (s === 'CRITICAL') severityByVuln.set(id, 'critical');
        else if (s === 'HIGH') severityByVuln.set(id, 'high');
        else severityByVuln.set(id, 'lower');
      } catch {
        // detail fetch failures leave the advisory as 'unknown' — reported, not dropped
      }
    });
    return severityByVuln;
  }

  private buildFindings(
    vulnerable: VulnerablePackage[],
    severityByVuln: Map<string, OsvSeverity>,
    truncatedCount: number,
  ): Finding[] {
    const buckets: Record<OsvSeverity, { pkg: VulnerablePackage; ids: string[] }[]> = {
      critical: [],
      high: [],
      lower: [],
      unknown: [],
    };
    for (const v of vulnerable) {
      const byBucket = new Map<OsvSeverity, string[]>();
      for (const id of v.vulnIds) {
        const bucket = severityByVuln.get(id) ?? 'unknown';
        byBucket.set(bucket, [...(byBucket.get(bucket) ?? []), id]);
      }
      for (const [bucket, ids] of byBucket) buckets[bucket].push({ pkg: v, ids });
    }

    const describe = (entries: { pkg: VulnerablePackage; ids: string[] }[]): string =>
      entries
        .slice(0, 5)
        .map((e) => `${e.pkg.pkg.name}@${e.pkg.pkg.version} (${e.ids.slice(0, 3).join(', ')})`)
        .join('; ') + (entries.length > 5 ? ` … and ${entries.length - 5} more package(s)` : '');

    const findings: Finding[] = [];
    const advisoryFinding = (
      id: string,
      severity: Finding['severity'],
      entries: { pkg: VulnerablePackage; ids: string[] }[],
      label: string,
    ): Finding => ({
      id,
      category: 'dependencies',
      severity,
      title: `${entries.reduce((n, e) => n + e.ids.length, 0)} ${label} advisories in locked dependencies (OSV.dev)`,
      description: `Known ${label} vulnerabilities in: ${describe(entries)}. Full advisories at https://osv.dev.`,
      file: entries[0].pkg.file,
      suggestion: 'Update the affected packages to patched versions and regenerate the lockfile.',
      meta: {
        engine: 'osv',
        packages: entries.slice(0, 20).map((e) => ({
          name: e.pkg.pkg.name,
          version: e.pkg.pkg.version,
          ecosystem: e.pkg.pkg.ecosystem,
          vulns: e.ids.slice(0, 10),
        })),
      },
    });

    if (buckets.critical.length > 0)
      findings.push(advisoryFinding('DEP-OSV-CRITICAL', 'critical', buckets.critical, 'critical'));
    if (buckets.high.length > 0) findings.push(advisoryFinding('DEP-OSV-HIGH', 'high', buckets.high, 'high'));

    if (buckets.lower.length > 0) {
      const count = buckets.lower.reduce((n, e) => n + e.ids.length, 0);
      findings.push({
        id: 'DEP-OSV-LOWER',
        category: 'dependencies',
        severity: 'low',
        title: `${count} lower-severity advisories (OSV.dev)`,
        description: `${count} advisories classified below high severity affect: ${describe(buckets.lower)}.`,
        file: buckets.lower[0].pkg.file,
        suggestion: 'Review the advisories on https://osv.dev and update where a patched version exists.',
        meta: { engine: 'osv', count },
      });
    }

    // Advisories whose severity could NOT be established get their own finding
    // at medium — never folded into the low bucket. An unclassified advisory
    // may well be a critical; presenting it as "lower-severity" is the exact
    // failure mode ("unknown ≠ clean") this project exists to call out.
    if (buckets.unknown.length > 0) {
      const count = buckets.unknown.reduce((n, e) => n + e.ids.length, 0);
      const overBudget = truncatedCount > 0;
      findings.push({
        id: 'DEP-OSV-UNKNOWN',
        category: 'dependencies',
        severity: 'medium',
        title: `${count} advisories of UNKNOWN severity (OSV.dev)`,
        description: `${count} known advisories could not be classified — OSV.dev publishes no severity for them${
          overBudget ? `, and ${truncatedCount} exceeded this run's classification budget of ${MAX_VULN_DETAILS}` : ''
        }. Unknown severity is NOT low severity: any of these may be critical. Affected: ${describe(buckets.unknown)}.`,
        file: buckets.unknown[0].pkg.file,
        suggestion:
          'Review these advisories individually on https://osv.dev — do not treat them as low risk until classified.',
        meta: { engine: 'osv', count, overBudget, budget: MAX_VULN_DETAILS },
      });
    }
    return findings;
  }

  private result(score: number, findings: Finding[], summary: string): AnalyzerResult {
    return { category: 'dependencies', score, findings, summary };
  }
}

/** Short human-readable coverage-gap note for summaries. */
function incompleteNote(zeroYield: string[], droppedByCap: number): string {
  const parts: string[] = [];
  if (zeroYield.length > 0) parts.push(`${zeroYield.length} lockfile(s) yielded no packages (unreadable/unparseable)`);
  if (droppedByCap > 0) parts.push(`${droppedByCap} package(s) beyond the ${MAX_PACKAGES}-package cap NOT checked`);
  return parts.join(' · ');
}

/**
 * A coverage gap is a finding, not a footnote: lockfiles that yielded nothing
 * and packages dropped past the cap were never checked against OSV — their
 * advisory status is unknown, and unknown is not clean.
 */
function incompleteFinding(zeroYield: string[], droppedByCap: number): Finding | null {
  if (zeroYield.length === 0 && droppedByCap === 0) return null;
  return {
    id: 'DEP-OSV-INCOMPLETE',
    category: 'dependencies',
    severity: 'low',
    title: 'OSV coverage incomplete — some dependencies were NOT checked',
    description: `${incompleteNote(zeroYield, droppedByCap)}. ${
      zeroYield.length > 0 ? `Affected lockfile(s): ${zeroYield.slice(0, 5).join(', ')}. ` : ''
    }Unchecked dependencies have UNKNOWN advisory status — not clean.`,
    ...(zeroYield.length > 0 ? { file: zeroYield[0] } : {}),
    suggestion:
      'Verify the lockfiles are valid and readable; for very large dependency trees run osv-scanner directly for full coverage.',
    meta: { engine: 'osv', zeroYield, droppedByCap, cap: MAX_PACKAGES },
  };
}

// ============================================================
// PRISM — Lockfile parsers for the OSV analyzer
//
// Pure functions: lockfile content in, exact (name, version, ecosystem)
// triples out. Only PINNED versions are extracted — OSV queries need an
// exact version, so ranged/unpinned entries are skipped (the dependencies
// analyzer already flags unpinned Python deps separately). npm is absent
// on purpose: package-lock.json is covered by `npm audit`.
// ============================================================

/** OSV.dev ecosystem identifiers — https://ossf.github.io/osv-schema/ */
export type OsvEcosystem = 'PyPI' | 'crates.io' | 'Go' | 'Packagist' | 'RubyGems';

export interface LockedPackage {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
}

type Parser = (content: string) => LockedPackage[];

function parseRequirementsTxt(content: string): LockedPackage[] {
  const packages: LockedPackage[] = [];
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    // Only exact pins: name[extras] == version (ranges can't be queried against OSV).
    const m = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!*-]+)\s*(?:;.*)?$/.exec(line);
    if (m) packages.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
  }
  return packages;
}

/** Shared shape of poetry.lock and Cargo.lock: TOML `[[package]]` blocks. */
function parseTomlPackageBlocks(content: string, ecosystem: OsvEcosystem): LockedPackage[] {
  const packages: LockedPackage[] = [];
  for (const block of content.split('[[package]]').slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (name && version) packages.push({ ecosystem, name, version });
  }
  return packages;
}

function parsePipfileLock(content: string): LockedPackage[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  if (typeof parsed !== 'object' || parsed === null) return [];
  const packages: LockedPackage[] = [];
  for (const section of ['default', 'develop']) {
    const deps = (parsed as Record<string, unknown>)[section];
    if (typeof deps !== 'object' || deps === null) continue;
    for (const [name, spec] of Object.entries(deps)) {
      const version = (spec as { version?: unknown } | null)?.version;
      if (typeof version === 'string' && version.startsWith('==')) {
        packages.push({ ecosystem: 'PyPI', name, version: version.slice(2) });
      }
    }
  }
  return packages;
}

function parseGoMod(content: string): LockedPackage[] {
  const packages: LockedPackage[] = [];
  const add = (name: string, version: string) => {
    // go.mod versions carry a leading v (v1.9.0); OSV's Go ecosystem expects it stripped.
    packages.push({ ecosystem: 'Go', name, version: version.replace(/^v/, '') });
  };
  // Block form: require ( ... one module per line ... )
  for (const block of content.matchAll(/^require\s*\(([\s\S]*?)\)/gm)) {
    for (const line of block[1].split('\n')) {
      const m = /^\s*([^\s]+)\s+(v[^\s]+)/.exec(line);
      if (m) add(m[1], m[2]);
    }
  }
  // Single-line form: require module v1.2.3
  for (const m of content.matchAll(/^require\s+([^\s(]+)\s+(v[^\s]+)/gm)) {
    add(m[1], m[2]);
  }
  return packages;
}

function parseComposerLock(content: string): LockedPackage[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  if (typeof parsed !== 'object' || parsed === null) return [];
  const packages: LockedPackage[] = [];
  for (const section of ['packages', 'packages-dev']) {
    const deps = (parsed as Record<string, unknown>)[section];
    if (!Array.isArray(deps)) continue;
    for (const dep of deps) {
      const name = (dep as { name?: unknown } | null)?.name;
      const version = (dep as { version?: unknown } | null)?.version;
      if (typeof name === 'string' && typeof version === 'string') {
        packages.push({ ecosystem: 'Packagist', name, version: version.replace(/^v/, '') });
      }
    }
  }
  return packages;
}

function parseGemfileLock(content: string): LockedPackage[] {
  const packages: LockedPackage[] = [];
  // Top-level specs are indented exactly 4 spaces: `    name (1.2.3)`.
  // Their transitive requirements are indented 6+ and often carry range
  // operators — the exact-4 indent plus a plain version filters to the former.
  for (const m of content.matchAll(/^ {4}([A-Za-z0-9._-]+) \(([0-9][A-Za-z0-9.-]*)\)$/gm)) {
    packages.push({ ecosystem: 'RubyGems', name: m[1], version: m[2] });
  }
  return packages;
}

/** Lockfile basename → parser. Key order is also the scan/report order. */
export const LOCKFILE_PARSERS: Record<string, Parser> = {
  'requirements.txt': parseRequirementsTxt,
  'poetry.lock': (c) => parseTomlPackageBlocks(c, 'PyPI'),
  'Pipfile.lock': parsePipfileLock,
  'Cargo.lock': (c) => parseTomlPackageBlocks(c, 'crates.io'),
  'go.mod': parseGoMod,
  'composer.lock': parseComposerLock,
  'Gemfile.lock': parseGemfileLock,
};

/** Parse a lockfile by basename. Unknown names and malformed content yield []. */
export function parseLockfile(basename: string, content: string): LockedPackage[] {
  const parser = LOCKFILE_PARSERS[basename];
  if (!parser) return [];
  try {
    return parser(content);
  } catch {
    return [];
  }
}

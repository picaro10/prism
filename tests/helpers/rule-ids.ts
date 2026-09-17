import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = resolve(__dirname, '../..');

/**
 * Every static rule id declared in the analyzers and the secret-pattern table.
 * Shared by the sync tests (docs catalog, CWE map, context tiers) so a new
 * declaration style is taught here once.
 */
export function ruleIdsInSource(): string[] {
  const sources = [
    ...readdirSync(join(ROOT, 'src/analyzers'))
      .filter((f) => f.endsWith('.ts'))
      .map((f) => join(ROOT, 'src/analyzers', f)),
    join(ROOT, 'src/utils/patterns.ts'),
  ];
  const ids = new Set<string>();
  for (const file of sources) {
    const src = readFileSync(file, 'utf-8');
    // Five shapes: inline `id: 'XXX-NNN'` literals, `finding('XXX-NNN', ...)`
    // helper calls (the workflow analyzer's style), `notice('XXX', ...)` helper
    // calls (the semgrep analyzer's engine-state notices), `advisoryFinding('XXX', ...)`
    // helper calls (the OSV analyzer's aggregates), and the embedded semgrep
    // rule pack, whose `- id: prism-xxx` YAML entries surface as SG-XXX.
    for (const m of src.matchAll(/id: '([A-Z]{2,4}-[A-Z0-9-]+)'/g)) ids.add(m[1]);
    for (const m of src.matchAll(/finding\(\s*'([A-Z]{2,4}-[A-Z0-9-]+)'/g)) ids.add(m[1]);
    for (const m of src.matchAll(/notice\(\s*'([A-Z]{2,4}-[A-Z0-9-]+)'/g)) ids.add(m[1]);
    for (const m of src.matchAll(/advisoryFinding\(\s*'([A-Z]{2,4}-[A-Z0-9-]+)'/g)) ids.add(m[1]);
    for (const m of src.matchAll(/^ {2}- id: prism-([a-z0-9-]+)$/gm)) ids.add(`SG-${m[1].toUpperCase()}`);
  }
  return [...ids].sort();
}

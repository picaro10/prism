// ============================================================
// .prismignore loader
// Same syntax as .gitignore — one pattern per line.
// Loaded from the target project root.
// ============================================================

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import ignore from 'ignore';

/**
 * Load a .prismignore file from the project root.
 * Returns an ignore instance that can test paths.
 * If no .prismignore exists, returns an empty ignore instance.
 */
export async function loadPrismIgnore(projectRoot: string): Promise<ReturnType<typeof ignore>> {
  const ig = ignore();

  const prismignorePath = join(projectRoot, '.prismignore');
  if (existsSync(prismignorePath)) {
    const content = await readFile(prismignorePath, 'utf-8');
    ig.add(content);
  }

  return ig;
}

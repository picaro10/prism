import { stat, readFile } from 'node:fs/promises';
import { resolve, sep, isAbsolute } from 'node:path';
import type { FileReader } from '../core/types.js';

/** Cap on any single file read — a hostile repo must not OOM the process. */
export const MAX_READ_BYTES = 15 * 1024 * 1024;

/**
 * Resolve `relativePath` inside `root`, rejecting absolute paths and any
 * `../` escape. Saved reports are untrusted input: a manipulated report with
 * `file: "../../etc/passwd"` must not read outside the project root it names.
 */
export function resolveWithin(root: string, relativePath: string): string {
  if (isAbsolute(relativePath)) {
    throw new Error(`absolute path not allowed: ${relativePath}`);
  }
  const rootAbs = resolve(root);
  const target = resolve(rootAbs, relativePath);
  if (target !== rootAbs && !target.startsWith(rootAbs + sep)) {
    throw new Error(`path escapes the project root: ${relativePath}`);
  }
  return target;
}

/**
 * A FileReader confined to `root` with the standard size cap. Used wherever
 * file paths come from a saved report (triage, finding bundles) instead of a
 * fresh scan.
 */
export function confinedReader(root: string): FileReader {
  return async (relativePath: string) => {
    const abs = resolveWithin(root, relativePath);
    const { size } = await stat(abs);
    if (size > MAX_READ_BYTES) {
      throw new Error(`file too large to read (${size} bytes): ${relativePath}`);
    }
    return readFile(abs, 'utf-8');
  };
}

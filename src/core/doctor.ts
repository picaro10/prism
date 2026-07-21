import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, constants } from 'node:fs/promises';

const execFileAsync = promisify(execFile);

export type CheckStatus = 'ok' | 'warn' | 'fail';

export interface DoctorCheck {
  name: string;
  status: CheckStatus;
  detail: string;
}

/** Parse the major version from a `process.version`-style string (e.g. "v22.1.0"). */
export function parseNodeMajor(version: string): number {
  const m = /^v?(\d+)\./.exec(version);
  return m ? Number(m[1]) : Number.NaN;
}

/** Node must be >= min (package.json engines requires >=22). A fail here is fatal. */
export function checkNodeVersion(version: string, min = 22): DoctorCheck {
  const major = parseNodeMajor(version);
  if (Number.isNaN(major)) {
    return { name: 'Node.js', status: 'warn', detail: `could not parse version '${version}'` };
  }
  return major >= min
    ? { name: 'Node.js', status: 'ok', detail: `${version} (>= ${min})` }
    : { name: 'Node.js', status: 'fail', detail: `${version} — PRISM requires Node >= ${min}` };
}

/** API keys are only needed for `--ai`; absence is a warning, not a failure. */
export function checkApiKeys(env: NodeJS.ProcessEnv): DoctorCheck {
  const present = [
    env.ANTHROPIC_API_KEY ? 'ANTHROPIC_API_KEY' : null,
    env.OPENROUTER_API_KEY ? 'OPENROUTER_API_KEY' : null,
  ].filter(Boolean);
  return present.length > 0
    ? { name: 'AI provider key', status: 'ok', detail: `found ${present.join(', ')}` }
    : {
        name: 'AI provider key',
        status: 'warn',
        detail: 'none set — `--ai` needs ANTHROPIC_API_KEY or OPENROUTER_API_KEY (static analysis works without it)',
      };
}

async function checkGit(): Promise<DoctorCheck> {
  try {
    const { stdout } = await execFileAsync('git', ['--version'], { timeout: 5000 });
    return { name: 'git', status: 'ok', detail: stdout.trim() };
  } catch {
    return { name: 'git', status: 'warn', detail: 'not found — needed only to analyze git URLs' };
  }
}

async function checkWritable(dir: string): Promise<DoctorCheck> {
  try {
    await access(dir, constants.W_OK);
    return { name: 'writable cwd', status: 'ok', detail: dir };
  } catch {
    return { name: 'writable cwd', status: 'warn', detail: `${dir} is not writable — reports can't be saved here` };
  }
}

/** Run every environment check. Order is stable for predictable output. */
export async function runDoctorChecks(
  env: NodeJS.ProcessEnv,
  nodeVersion: string,
  cwd: string,
): Promise<DoctorCheck[]> {
  return [checkNodeVersion(nodeVersion), await checkGit(), checkApiKeys(env), await checkWritable(cwd)];
}

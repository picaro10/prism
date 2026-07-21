// ============================================================
// File Context Classifier
// Determines the "role" of a file so analyzers can adjust
// severity and skip false positives intelligently.
// ============================================================

import { basename } from 'node:path';

export type FileContext =
  | 'source' // Normal source code — full scrutiny
  | 'test' // Test file — lower severity for hardcoded values
  | 'fixture' // Test fixture / sample data — skip secret detection
  | 'template' // Template / example file — skip or info-only
  | 'security-tool' // File is itself a security scanner — skip pattern matches
  | 'documentation' // Docs, READMEs — skip
  | 'generated' // Auto-generated files — skip
  | 'config-template' // .env.example, config templates — skip
  | 'vendor'; // Third-party / vendored code — skip

/** Path segments that indicate test fixtures or sample data */
const FIXTURE_SEGMENTS = [
  'fixtures',
  'fixture',
  '__fixtures__',
  'samples',
  'sample',
  'mocks',
  'mock',
  '__mocks__',
  'stubs',
  'testdata',
  'test-data',
  'test_data',
  'fake',
  'fakes',
];

/** Path segments that indicate template/example files */
const TEMPLATE_SEGMENTS = [
  'templates',
  'template',
  'examples',
  'example',
  'demos',
  'demo',
  'assets', // skill assets, documentation assets
  'snippets',
  'boilerplate',
  'scaffold',
];

/** Path segments that indicate vendored / third-party code */
const VENDOR_SEGMENTS = ['node_modules', 'vendor', 'vendors', 'third-party', 'third_party', 'external', 'lib/vendor'];

/** Path segments that indicate generated code */
const GENERATED_SEGMENTS = ['generated', '__generated__', 'gen', '.next', 'dist', 'build', 'out'];

/** File name patterns for config templates */
const CONFIG_TEMPLATE_NAMES = [
  '.env.example',
  '.env.template',
  '.env.sample',
  '.env.local.example',
  'config.example.json',
  'config.sample.json',
  'settings.example.py',
  'settings.sample.py',
];

/**
 * Classify a file by its path and optionally its content.
 * Content-based classification (e.g. detecting security tools)
 * is more expensive, so it's opt-in.
 */
export function classifyFile(relativePath: string): FileContext {
  const name = basename(relativePath);
  const pathLower = relativePath.toLowerCase();
  const segments = pathLower.split('/');

  // Config templates
  if (CONFIG_TEMPLATE_NAMES.some((t) => name.toLowerCase() === t)) {
    return 'config-template';
  }

  // Documentation
  if (
    name.toLowerCase() === 'readme.md' ||
    name.toLowerCase() === 'changelog.md' ||
    name.toLowerCase() === 'contributing.md' ||
    name.toLowerCase() === 'license' ||
    name.toLowerCase() === 'license.md' ||
    pathLower.startsWith('docs/') ||
    pathLower.startsWith('documentation/')
  ) {
    return 'documentation';
  }

  // Generated
  if (GENERATED_SEGMENTS.some((s) => segments.includes(s))) {
    return 'generated';
  }

  // Vendor
  if (VENDOR_SEGMENTS.some((s) => segments.includes(s))) {
    return 'vendor';
  }

  // Test files
  if (
    name.includes('.test.') ||
    name.includes('.spec.') ||
    name.includes('_test.') ||
    name.includes('_spec.') ||
    segments.includes('__tests__') ||
    segments.includes('tests') ||
    segments.includes('test')
  ) {
    // Check if it's a fixture within tests
    if (FIXTURE_SEGMENTS.some((s) => segments.includes(s))) {
      return 'fixture';
    }
    return 'test';
  }

  // Fixtures (also outside test dirs)
  if (FIXTURE_SEGMENTS.some((s) => segments.includes(s))) {
    return 'fixture';
  }

  // Templates and examples
  if (TEMPLATE_SEGMENTS.some((s) => segments.includes(s))) {
    return 'template';
  }

  // Files with "sample" or "example" in the name
  if (
    name.toLowerCase().includes('sample') ||
    name.toLowerCase().includes('example') ||
    name.toLowerCase().includes('mock') ||
    name.toLowerCase().includes('dummy')
  ) {
    return 'template';
  }

  // Default: normal source code
  return 'source';
}

/**
 * Content-based classification: detect if a file is a security tool
 * by checking if it contains multiple regex patterns for secret detection.
 *
 * Call this only on files already classified as 'source' where you want
 * deeper analysis.
 */
export function isSecurityTool(content: string): boolean {
  // A security tool DEFINES secret-detection patterns; we must distinguish that
  // from an ordinary file that merely mentions "token"/"password" in prose. The
  // signal is a keyword sitting inside REGEX SYNTAX (a detector definition), or a
  // distinctive credential prefix inside a literal — never a plain error message.
  // Over-matching is dangerous here: a false "security-tool" verdict skips the
  // whole secret scan, and it would do so on exactly the auth/credential files
  // where a hardcoded key is most likely (a false negative, worse than a FP).
  const STRONG = /-----BEGIN|PRIVATE KEY|\bAKIA|sk-ant|sk_live|pk_live|\bAIza|\bghp_|xox[baprs]-/;
  const KEYWORD = /password|secret|api.?key|token|credential/i;
  // Regex metacharacters that only appear in a pattern definition, not in prose.
  const REGEXY = /\\s|\[:=\]|\{\d|re\.compile|new RegExp|\br["']|\\w|\.\*/;

  let signals = 0;
  for (const line of content.split('\n')) {
    if (!/['"`/]/.test(line)) continue; // must be inside a literal / regex delimiter
    if (STRONG.test(line)) signals++;
    else if (KEYWORD.test(line) && REGEXY.test(line)) signals++;
  }

  // 3+ pattern definitions → it's a security tool
  return signals >= 3;
}

/**
 * Determine if a finding's severity should be adjusted based on file context.
 * Returns null if the finding should be skipped entirely.
 */
export function adjustSeverity(
  originalSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  context: FileContext,
): 'critical' | 'high' | 'medium' | 'low' | 'info' | null {
  switch (context) {
    case 'source':
      return originalSeverity; // Full severity

    case 'test':
      // Downgrade by one level
      if (originalSeverity === 'critical') return 'medium';
      if (originalSeverity === 'high') return 'low';
      if (originalSeverity === 'medium') return 'info';
      return 'info';

    case 'fixture':
    case 'template':
    case 'config-template':
    case 'documentation':
      return null; // Skip entirely

    case 'security-tool':
      return null; // Skip — it's detection patterns, not leaks

    case 'generated':
    case 'vendor':
      return null; // Skip — not the user's code

    default:
      return originalSeverity;
  }
}

/**
 * Whether findings on a file of this context should be skipped entirely.
 *
 * These contexts are not user-authored production/test code, so flagging them
 * is a false positive: fixtures and templates are intentional bad examples,
 * generated/vendor code is not the user's, docs/config-templates aren't code,
 * and security tools are detection patterns, not leaks. `source` and `test`
 * are NOT excluded (real code gets analyzed; tests get severity-downgraded
 * via adjustSeverity, not skipped).
 *
 * This is the single source of truth for the skip policy — secrets, docker,
 * and tests analyzers all defer to it so they stay consistent.
 */
export function isExcludedContext(context: FileContext): boolean {
  return (
    context === 'fixture' ||
    context === 'template' ||
    context === 'config-template' ||
    context === 'documentation' ||
    context === 'generated' ||
    context === 'vendor' ||
    context === 'security-tool'
  );
}

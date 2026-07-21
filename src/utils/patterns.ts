// ============================================================
// Detection patterns for secrets, tokens, and credentials
// ============================================================

export interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
}

/**
 * Known secret patterns.
 * Each regex is designed to minimize false positives while catching real leaks.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  // AWS — Only the Access Key ID (AKIA prefix) is specific enough for reliable detection.
  // The Secret Access Key (any 40-char base64) was generating massive false positives
  // on SHA hashes, GitHub Actions checksums, YAML values, etc. Removed in v0.5.1.
  // The entropy detector covers truly random high-entropy strings if needed.
  {
    id: 'SEC-AWS-KEY',
    name: 'AWS Access Key ID',
    pattern: /(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])/,
    severity: 'critical',
  },

  // GitHub
  {
    id: 'SEC-GH-PAT',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[0-9a-zA-Z]{36}/,
    severity: 'critical',
  },
  {
    id: 'SEC-GH-OAUTH',
    name: 'GitHub OAuth Token',
    pattern: /gho_[0-9a-zA-Z]{36}/,
    severity: 'critical',
  },

  // Generic API keys
  {
    id: 'SEC-API-KEY',
    name: 'Hardcoded API Key',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/i,
    severity: 'high',
  },

  // Private keys
  {
    id: 'SEC-PRIVATE-KEY',
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
  },

  // Database URLs
  {
    id: 'SEC-DB-URL',
    name: 'Database Connection String',
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/i,
    severity: 'critical',
  },

  // JWT
  {
    id: 'SEC-JWT',
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/,
    severity: 'high',
  },

  // Telegram
  {
    id: 'SEC-TELEGRAM',
    name: 'Telegram Bot Token',
    pattern: /(?<![0-9])[0-9]{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/,
    severity: 'critical',
  },

  // Stripe
  {
    id: 'SEC-STRIPE-SK',
    name: 'Stripe Secret Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/,
    severity: 'critical',
  },
  {
    id: 'SEC-STRIPE-PK',
    name: 'Stripe Publishable Key (live)',
    pattern: /pk_live_[0-9a-zA-Z]{24,}/,
    severity: 'medium',
  },

  // OpenAI / Anthropic
  {
    id: 'SEC-OPENAI',
    name: 'OpenAI API Key',
    pattern: /(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}(?![A-Za-z0-9])/,
    severity: 'critical',
  },
  {
    id: 'SEC-ANTHROPIC',
    name: 'Anthropic API Key',
    pattern: /sk-ant-[A-Za-z0-9_-]{20,}/,
    severity: 'critical',
  },

  // Generic password in config
  {
    id: 'SEC-PASSWORD',
    name: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    severity: 'high',
  },

  // .env reference hardcoded (someone pasted the value instead of using env var)
  {
    id: 'SEC-ENV-VALUE',
    name: 'Possible .env value hardcoded',
    pattern: /(?:TOKEN|SECRET|KEY|PASS|CREDENTIALS)\s*=\s*['"][A-Za-z0-9_\-/+=]{16,}['"]/,
    severity: 'medium',
  },
];

/** Files that are expected to contain secret-like patterns (false positive reduction) */
export const SECRET_SAFE_FILES = [
  '.env.example',
  '.env.template',
  '.env.sample',
  'README.md',
  'CHANGELOG.md',
  '*.test.ts',
  '*.test.js',
  '*.spec.ts',
  '*.spec.js',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
];

/**
 * Shannon entropy calculation for a string.
 * High entropy strings (> 4.5) in source code are suspicious.
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

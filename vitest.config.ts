import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // Command wiring is exercised by the spawn-based e2e tests in tests/cli
      // (child processes — invisible to in-process V8 coverage). The testable
      // CLI logic lives in src/cli/shared.ts + core modules, which ARE covered.
      exclude: ['src/cli/index.ts', 'src/cli/commands/**'],
      // A serious, enforced floor — set just below current coverage (≈88/80/90/90)
      // so it guards against regression without chasing decorative 100%. Raise
      // as coverage grows; the CI runs `test:coverage`, so these are enforced.
      thresholds: {
        statements: 85,
        branches: 77,
        functions: 87,
        lines: 87,
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
});

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
      exclude: ['src/cli/index.ts'],
      // A serious, enforced floor — set just below current coverage (≈80/74/82/81)
      // so it guards against regression without chasing decorative 100%. Raise
      // as coverage grows; the CI runs `test:coverage`, so these are enforced.
      thresholds: {
        statements: 78,
        branches: 72,
        functions: 78,
        lines: 78,
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
});

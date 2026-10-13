// Vitest 配置（Node 端）。
// alias @ -> src/; include tests 下所有 .spec.ts; exclude tests/fuzz。
import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  test: {
    include: ['tests/**/*.spec.ts'],
    exclude: ['tests/fuzz/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
    testTimeout: 20_000,
  },
});

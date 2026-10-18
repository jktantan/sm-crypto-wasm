/**
 * fuzz runner 配置。
 *
 * 主配置（vitest.config.ts）刻意把 tests/fuzz 排除在常规回归之外；
 * fuzz 用例数量与随机性更高，用 `pnpm test:fuzz` 单独跑。
 */
import path from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  test: {
    include: ['tests/fuzz/**/*.spec.ts'],
    environment: 'node',
    testTimeout: 60_000,
  },
});

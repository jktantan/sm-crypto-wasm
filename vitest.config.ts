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
    // SM9 pairing 测试单测粒度需要 ≥ 60s (sm9 sign 10s + verify 16s + encrypt 10s + decrypt 7s);
    // 完整 pnpm test 跑约 130-150s 在 2m0s 主机 cap 内可一次跑完。
    testTimeout: 60_000,
  },
});

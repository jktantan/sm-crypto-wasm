/**
 * 浏览器 runner 配置（spec §13 DoD：Node 与浏览器两套 runner 全绿）。
 *
 * 复用 `vitest.config.ts` 的 alias 与 include；唯一差异是 environment：
 * `happy-dom` 提供浏览器 DOM 上下文，让 `loadWasm` 的浏览器分支
 *（`fetch(new URL('../<name>/<name>.wasm', import.meta.url))`）能跑通。
 *
 * 选 happy-dom 而不是真浏览器（Playwright/Chromium）的理由：
 *  1. 本库对外只暴露纯 wasm + TS API，不依赖 DOM；
 *  2. happy-dom 跑 vitest 极快（秒级），足够在 CI 守红线；
 *  3. 真浏览器另开 `playwright` 配置可作远期增强，本轮不做。
 */
import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  test: {
    include: ['tests/browser/**/*.spec.ts'],
    exclude: ['node_modules/**', 'dist/**'],
    environment: 'happy-dom',
    testTimeout: 60_000,
  },
});

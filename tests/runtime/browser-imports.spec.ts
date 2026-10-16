import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as loadWasmNode from '@/runtime/loadWasm';
import * as loadWasmBrowser from '@/runtime/loadWasm.browser';
import * as randomNode from '@/runtime/random';
import * as randomBrowser from '@/runtime/random.browser';

/**
 * 浏览器可分发性防护。
 *
 * ## 为什么需要这组测试
 *
 * 浏览器构建的模块图里**不能出现 `node:*`**：Webpack 5 / esbuild / Rspack 在**解析期**
 * 就会因 `node:fs` 之类的裸模块构建失败（tree-shaking 帮不上忙 —— 解析先于摇树）。
 * Vite 是少数会把 `node:*` 外部化成空 stub 的特例，不能依赖。
 *
 * 因此 `loadWasm` / `random` 各有两份实现，由 package.json 的 `browser` 字段在打包时
 * 替换（Node 版用 `node:*`，浏览器版零 `node:*`）。这组测试钉住三件事：
 *
 * 1. `src/` 下不存在 `node:*` **具名导入**（具名导入即使被 externalize 成 stub 也会
 *    让 rollup 报 "X is not exported"，而 namespace 导入只警告）；
 * 2. 浏览器变体（含 core）**零 `node:` 引用**；
 * 3. 浏览器变体的**导出面与 Node 版一致** —— 否则替换后调用方拿到 undefined。
 *
 * 依据：2026-10-16 实测 —— 具名导入下 Vite/esbuild/Webpack 全部构建失败；改 namespace
 * 导入仅 Vite 通过；再拆双实现 + `browser` 字段后四者（Vite / esbuild / Webpack 5 /
 * Node）全部通过，且真 Chromium 端到端跑通。
 */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith('.ts')) out.push(p);
  }
  return out;
}

const SRC_DIR = fileURLToPath(new URL('../../src', import.meta.url));
const RUNTIME_DIR = join(SRC_DIR, 'runtime');

describe('宿主内置模块的导入形式', () => {
  it('src/ 下不存在 node:* 的具名导入', () => {
    // 匹配 `import { a, b as c } from 'node:...'`。
    const named = /import\s*\{[^}]*\}\s*from\s*['"]node:[^'"]+['"]/g;
    const offenders: string[] = [];

    for (const file of walk(SRC_DIR)) {
      for (const m of readFileSync(file, 'utf8').matchAll(named)) {
        offenders.push(`${file.replace(SRC_DIR, 'src')}: ${m[0]}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  it('浏览器变体与 core 零 node: 引用', () => {
    const files = [
      'loadWasm.browser.ts',
      'random.browser.ts',
      'loadWasm.core.ts',
      'random.core.ts',
    ];
    const offenders: string[] = [];

    for (const f of files) {
      const src = readFileSync(join(RUNTIME_DIR, f), 'utf8');
      // 静态 import / export-from / 动态 import 都要挡。
      const re = /(?:from\s*|import\s*\(\s*)['"]node:[^'"]+['"]/g;
      for (const m of src.matchAll(re)) offenders.push(`${f}: ${m[0]}`);
    }

    expect(offenders).toEqual([]);
  });

  it('浏览器变体的导出面与 Node 版一致', () => {
    // 替换发生在打包期，两边必须提供同一套 API；否则浏览器里会拿到 undefined。
    expect(Object.keys(loadWasmBrowser).sort()).toEqual(Object.keys(loadWasmNode).sort());
    expect(Object.keys(randomBrowser).sort()).toEqual(Object.keys(randomNode).sort());
  });
});

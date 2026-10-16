import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * 回归防护：宿主内置模块（`node:*`）必须用 **namespace 导入**（`import * as`）。
 *
 * 具名导入（`import { x } from 'node:fs'`）会让打包器把 `node:*` 外部化成只有
 * default 的空 stub 后**构建直接失败** —— Vite/Rollup 会报
 * `"x" is not exported by "__vite-browser-external"`，浏览器用户完全用不了这个包。
 * namespace 导入只产生警告；运行时浏览器分支取到 undefined 也无妨，因为那些函数
 * 只在 `isNode` 为真时调用。
 *
 * 依据：2026-10-16 用真 Chromium + Vite 复现（具名导入 → build failed；
 * namespace 导入 → build ok，且五个算法在真浏览器里端到端跑通）。
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
});

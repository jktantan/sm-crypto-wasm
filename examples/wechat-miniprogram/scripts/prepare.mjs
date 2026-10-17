#!/usr/bin/env node
/**
 * 准备微信小程序示例的运行时资源：
 *   1. 把仓库 dist/ 复制到 miniprogram/vendor/sm-crypto-wasm/dist/；
 *   2. 用 miniprogram/shims/ 下的小程序实现覆盖 runtime/loadWasm.js、runtime/random.js；
 *   3. 删掉不会被小程序引用的浏览器版 runtime。
 *
 * 原生小程序没有 tree-shaking：代码包里放什么就上传什么。因此支持按算法裁剪：
 *
 *   pnpm example:wechat:prepare                      # 全部算法
 *   pnpm example:wechat:prepare --algos sm3,sm4      # 只准备 SM3 + SM4
 *   SM_ALGOS=sm3,sm4 pnpm example:wechat:prepare     # 同上（bash / zsh）
 *
 * sm2 / sm9 会自动带上它们依赖的 sm4、pem、common。
 *
 * 用法（仓库根目录）：
 *   pnpm build && pnpm example:wechat:prepare
 */

import { cp, mkdir, readdir, rm, stat } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ALL_ALGOS = ['sm2', 'sm3', 'sm4', 'sm9', 'zuc'];

const here = path.dirname(fileURLToPath(import.meta.url));
const exampleRoot = path.resolve(here, '..');
const repoRoot = path.resolve(exampleRoot, '../..');
const distDir = path.join(repoRoot, 'dist');
const destDir = path.join(exampleRoot, 'miniprogram/vendor/sm-crypto-wasm/dist');
const shimsDir = path.join(exampleRoot, 'miniprogram/shims');

/** 解析 --algos a,b / --algos=a,b / 环境变量 SM_ALGOS。 */
function parseRequested() {
  const env = process.env.SM_ALGOS;
  if (env) return env;

  const args = process.argv.slice(2);
  const eq = args.find((arg) => arg.startsWith('--algos='));
  if (eq) return eq.slice('--algos='.length);

  const i = args.indexOf('--algos');
  if (i >= 0 && args[i + 1]) return args[i + 1];

  return 'all';
}

const raw = parseRequested().trim().toLowerCase();
const requested = raw === 'all' ? [...ALL_ALGOS] : raw.split(',').map((s) => s.trim()).filter(Boolean);

if (requested.length === 0) {
  console.error('[example:wechat] --algos 为空。可选：' + ALL_ALGOS.join(','));
  process.exit(1);
}

const unknown = requested.filter((algo) => !ALL_ALGOS.includes(algo));
if (unknown.length > 0) {
  console.error(`[example:wechat] 未知算法：${unknown.join(',')}。可选：${ALL_ALGOS.join(',')}`);
  process.exit(1);
}

if (!existsSync(path.join(distDir, 'index.js'))) {
  console.error('[example:wechat] 找不到 dist/。请先在仓库根目录运行：pnpm build');
  process.exit(1);
}

const algorithms = new Set(requested);
const copyDirs = new Set(['runtime', ...algorithms]);
const needsPem = algorithms.has('sm2') || algorithms.has('sm9');

if (needsPem) {
  // SM2 / SM9 的 hybrid 走 SM4-GCM；PEM 编解码在 pem/ 与 common/。
  // 即使调用方不直接用这些子功能，模块顶层的 import 也需要它们存在。
  algorithms.add('sm4');
  copyDirs.add('sm4');
  copyDirs.add('pem');
  copyDirs.add('common');
}

await rm(destDir, { recursive: true, force: true });
await mkdir(destDir, { recursive: true });

for (const dir of copyDirs) {
  const src = path.join(distDir, dir);
  if (!existsSync(src)) {
    console.error(`[example:wechat] dist/${dir} 不存在，dist 可能不完整。请重新 pnpm build`);
    process.exit(1);
  }
  await cp(src, path.join(destDir, dir), {
    recursive: true,
    filter: (file) => {
      // 只保留 .js / .wasm；目录本身要保留，否则递归会中断。
      if (statSync(file).isDirectory()) return true;
      return file.endsWith('.js') || file.endsWith('.wasm');
    },
  });
}

// 用小程序实现覆盖运行时。
await cp(path.join(shimsDir, 'loadWasm.js'), path.join(destDir, 'runtime/loadWasm.js'));
await cp(path.join(shimsDir, 'random.js'), path.join(destDir, 'runtime/random.js'));

// 浏览器版 runtime 在小程序里不会被引用，删掉避免误 import。
for (const file of ['runtime/loadWasm.browser.js', 'runtime/random.browser.js']) {
  await rm(path.join(destDir, file), { force: true });
}

async function dirSize(dir) {
  let total = 0;
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) total += await dirSize(p);
    else total += (await stat(p)).size;
  }
  return total;
}

const size = await dirSize(destDir);
const kb = Math.round(size / 1024);

const deps = [...algorithms].filter((algo) => !requested.includes(algo));
console.log(`[example:wechat] 算法：${[...algorithms].join(', ')}${deps.length ? `（依赖自动补全：${deps.join(', ')}）` : ''}`);
console.log(`[example:wechat] 已准备 ${path.relative(repoRoot, destDir)}（约 ${kb} KB）`);
if (raw !== 'all') {
  console.log(
    '[example:wechat] 注意：示例页面固定 import 了全部 5 个算法；裁剪后请同步删除页面里未选算法的 import 和测试块，否则编译会找不到模块。',
  );
}
console.log('[example:wechat] 下一步：微信开发者工具导入 examples/wechat-miniprogram');
console.log('[example:wechat] 调试基础库请选择 2.15.0 或更高');

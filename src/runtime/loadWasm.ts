/**
 * WASM 加载器（**Node 版**）。
 *
 * 浏览器打包时，本文件会被 `loadWasm.browser.ts` 替换（package.json 的 `browser`
 * 字段）—— 因为这里的 `node:fs` / `node:path` / `node:url` 会让 Webpack / esbuild /
 * Rspack 在解析期直接构建失败。共享逻辑（类型、实例化、记忆化）在
 * `loadWasm.core.ts`。**不要在 core 或 browser 版里 import 本文件。**
 *
 * 设计要点：
 * - **按算法名称记忆化**：同名在并发调用下只实例化一次（见 core 的 `memoizeLoad`）。
 * - **同步 / 异步并存**：业务 API 大量使用同步入口，但 WASM 加载必须异步；
 *   这里同时提供 `loadWasm`（async）与 `loadWasmSync`（Node 专用，
 *   每次独立读文件 + instantiate，与异步版不共享实例）。
 * - **内存视图返回**：所有从 WASM 内存取出的字节都由上层 `slice()` 拷贝，
 *   绝不让上层持有会因内存增长而失效的视图。
 */

import * as nodeFs from 'node:fs';
import * as nodeFsPromises from 'node:fs/promises';
import * as nodePath from 'node:path';
import * as nodeUrl from 'node:url';
import {
  instantiateFromBuffer,
  isWasmAlgo,
  memoizeLoad,
  rejectBadName,
  resetCacheForTests,
  type WasmAlgo,
  type WasmModule,
} from './loadWasm.core.js';

export type { WasmAlgo, WasmModule } from './loadWasm.core.js';

/** 当前是否在 Node 进程内。CI / Vite SSR / 真浏览器都据此切换加载路径。 */
const isNode = typeof process !== 'undefined' && !!process.versions?.node;

/**
 * 计算 dist 子目录下的 wasm 路径。
 *
 * 优先从 `process.cwd()/dist/<name>/<name>.wasm` 找（开发模式从 repo 根跑）；
 * 找不到再回退到当前源文件相对路径（生产构建产物 `dist/runtime/loadWasm.js`
 * 加载同级目录的 `../<name>/<name>.wasm`）。
 *
 * @param name 算法名。
 * @returns 绝对文件系统路径。
 */
function wasmPath(name: WasmAlgo): string {
  // 1. cwd/dist（开发/单仓根目录模式）。这是首选路径；日志里
  // 见到 "src/<name>/<name>.wasm" 即说明回退路径被命中，提示开发模式
  // 下应当先 `pnpm build:wasm:<name>`。
  const cwdPath = nodePath.resolve(process.cwd(), 'dist', name, `${name}.wasm`);
  if (nodeFs.existsSync(cwdPath)) return cwdPath;
  // 2. 源文件相对路径（生产产物 dist/runtime/loadWasm.js → ../<name>/<name>.wasm）。
  let here: string;
  try {
    here = nodePath.dirname(nodeUrl.fileURLToPath(import.meta.url));
  } catch {
    here = process.cwd();
  }
  return nodePath.resolve(here, '..', name, `${name}.wasm`);
}

/**
 * 异步读取 wasm 字节（Node 路径）。
 *
 * @param name 算法名。
 * @returns wasm 二进制 ArrayBuffer；总是一个**拷贝**，不持有 fd 缓存。
 */
async function nodeReadWasm(name: WasmAlgo): Promise<ArrayBuffer> {
  const buf = await nodeFsPromises.readFile(wasmPath(name));
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/**
 * 同步读取 wasm 字节（Node 路径，仅 `loadWasmSync` 使用）。
 *
 * @param name 算法名。
 * @returns wasm 二进制 ArrayBuffer。
 */
function nodeReadWasmSync(name: WasmAlgo): ArrayBuffer {
  const buf = nodeFs.readFileSync(wasmPath(name));
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/**
 * 异步加载并实例化 wasm。**这是业务代码的主入口**。
 *
 * 并发安全：同名的第二次调用复用第一次的 Promise，不会触发额外 instantiate。
 *
 * @param name 算法名。
 * @returns 解析后冻结的 WasmModule。
 */
export function loadWasm(name: WasmAlgo): Promise<WasmModule> {
  if (!isWasmAlgo(name)) rejectBadName(name);
  return memoizeLoad(name, async (n) => instantiateFromBuffer(await nodeReadWasm(n)));
}

/**
 * 同步加载 wasm（**Node 专用**）。浏览器路径不可用，会抛错。
 *
 * 每次调用独立读文件 + instantiate，**不**复用 `loadWasm` 的缓存实例
 * （Node 的 Promise 无法被同步等待）。
 *
 * @param name 算法名。
 * @returns 冻结的 WasmModule。
 */
export function loadWasmSync(name: WasmAlgo): WasmModule {
  if (!isNode) {
    throw new Error('loadWasmSync: browser must await loadWasm() first');
  }
  if (!isWasmAlgo(name)) rejectBadName(name);
  return instantiateFromBuffer(nodeReadWasmSync(name));
}

/**
 * 获取已缓存的 wasm 引用（若无则初始化）。等价于 `loadWasm`，提供语义化别名。
 *
 * @param name 算法名。
 */
export function getCachedWasm(name: WasmAlgo): Promise<WasmModule> {
  return loadWasm(name);
}

/**
 * 清空缓存。仅供测试使用 —— 单元测试需要测并发安全场景时必须能重置状态。
 */
export function _resetCacheForTests(): void {
  resetCacheForTests();
}

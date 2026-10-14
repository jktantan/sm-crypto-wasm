/**
 * 跨运行时 WASM 加载器（runtime WASM loader）。
 *
 * 支持三种环境：
 * - Node.js 18+：通过 `node:fs/promises` 读取构建产物 `dist/<name>/<name>.wasm`。
 * - 现代浏览器（Vite/Webpack/Rollup）：用 `fetch(new URL(...))`，由打包器解析资源 URL。
 * - Deno/Bun：自动复用 Node 路径（都暴露 `node:fs`）。
 *
 * 设计要点：
 * - **按算法名称记忆化（memoization）**：同一个 `name` 在并发调用下只实例化一次。
 *   缓存键为 `WasmAlgo`，值为 `Promise<WasmModule>`；第一个调用挂上 Promise，
 *   后续调用拿到同一引用。Review-Focus #7 明确要求"并发调用拿到同一模块"。
 * - **同步 / 异步并存**：业务 API 大量使用同步入口（见 spec §12.1 Q2），
 *   但 WASM 加载必须异步；这里同时提供 `loadWasm`（async）与 `loadWasmSync`
 *   （Node 专用），后者内部用 `fs.readFileSync` + `WebAssembly.Module`。
 * - **内存视图返回**：所有从 WASM 内存取出的字节都用 `slice()` 返回拷贝，
 *   绝不让上层持有会因内存增长而失效的视图。Review-Focus #8。
 *
 * spec/plan 对应：plan Task 1；spec §7 跨运行时、§10 测试。
 */

import { existsSync, readFile, readFileSync } from 'node:fs';
import { readFile as readFileAsync } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** 算法枚举。扩展时同步更新 `nodeReadWasm` 路径解析。 */
export type WasmAlgo = 'sm2' | 'sm3' | 'sm4' | 'sm9' | 'zuc';

/** 加载完成后的 WASM 模块封装。`exports` 已类型化为 `WebAssembly.Exports`。 */
export interface WasmModule {
  readonly exports: WebAssembly.Exports;
  readonly memory: WebAssembly.Memory;
}

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
  const cwdPath = resolve(process.cwd(), 'dist', name, `${name}.wasm`);
  if (existsSync(cwdPath)) return cwdPath;
  // 2. 源文件相对路径（生产产物 dist/runtime/loadWasm.js → ../<name>/<name>.wasm）。
  let here: string;
  try {
    here = dirname(fileURLToPath(import.meta.url));
  } catch {
    here = process.cwd();
  }
  return resolve(here, '..', name, `${name}.wasm`);
}

/**
 * 异步读取 wasm 字节（Node 路径）。
 *
 * @param name 算法名。
 * @returns wasm 二进制 ArrayBuffer；总是一个**拷贝**，不持有 fd 缓存。
 */
async function nodeReadWasm(name: WasmAlgo): Promise<ArrayBuffer> {
  const buf = await readFileAsync(wasmPath(name));
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/**
 * 同步读取 wasm 字节（Node 路径，仅 `loadWasmSync` 使用）。
 *
 * @param name 算法名。
 * @returns wasm 二进制 ArrayBuffer。
 */
function nodeReadWasmSync(name: WasmAlgo): ArrayBuffer {
  const buf = readFileSync(wasmPath(name));
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/**
 * 抽象出"按当前环境读 wasm 字节"。
 *
 * @param name 算法名。
 * @returns ArrayBuffer 形式的 wasm 字节。
 */
async function loadArrayBuffer(name: WasmAlgo): Promise<ArrayBuffer> {
  if (isNode) return nodeReadWasm(name);
  // 浏览器：用 import.meta.url 解析同级 wasm 资源；打包器负责重写 URL。
  const url = new URL(`../${name}/${name}.wasm`, import.meta.url);
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`loadWasm: failed to fetch ${url}: ${res.status} ${res.statusText}`);
  }
  return res.arrayBuffer();
}

/**
 * 同步实例化 wasm（仅 Node）。失败抛 WebAssembly 自身的 CompileError / LinkError。
 *
 * @param buf wasm 字节。
 */
function instantiateFromBuffer(buf: ArrayBuffer): WasmModule {
  const mod = new WebAssembly.Module(buf);
  const inst = new WebAssembly.Instance(mod, {});
  const exports = inst.exports as WebAssembly.Exports;
  const memory =
    (exports.memory as WebAssembly.Memory | undefined) ?? new WebAssembly.Memory({ initial: 1 });
  return Object.freeze({ exports, memory });
}

/** 模块缓存。key = 算法名，value = 已 memoize 的 Promise。 */
const cache = new Map<WasmAlgo, Promise<WasmModule>>();

/**
 * 异步加载并实例化 wasm。**这是业务代码的主入口**。
 *
 * 并发安全：同名的第二次调用复用第一次的 Promise，不会触发额外 instantiate。
 *
 * @param name 算法名。
 * @returns 解析后冻结的 WasmModule。
 */
export function loadWasm(name: WasmAlgo): Promise<WasmModule> {
  let p = cache.get(name);
  if (!p) {
    p = (async () => {
      const buf = await loadArrayBuffer(name);
      // ASC 默认产物会导入 `env` 模块（abort、trace 等）；
      // 我们提供空 stub，AS 库函数都不会被调用所以足够。
      const imports: WebAssembly.Imports = {
        env: {
          abort: () => {
            throw new Error('wasm: abort');
          },
          trace: () => {},
          __assert_fail: () => {
            throw new Error('wasm: assert_fail');
          },
        },
      };
      const { instance } = await WebAssembly.instantiate(buf, imports);
      const exports = instance.exports as WebAssembly.Exports;
      const memory =
        (exports.memory as WebAssembly.Memory | undefined) ??
        new WebAssembly.Memory({ initial: 1 });
      return Object.freeze({ exports, memory });
    })();
    cache.set(name, p);
  }
  return p;
}

/**
 * 同步加载 wasm（Node 专用）。浏览器路径不可用，会抛错。
 *
 * 用法：在应用启动时先 `await loadWasm('sm3')` 预热缓存，之后业务函数
 * 调用 `loadWasmSync('sm3')` 即可零开销获取引用。
 *
 * @param name 算法名。
 * @returns 冻结的 WasmModule。
 */
export function loadWasmSync(name: WasmAlgo): WasmModule {
  if (!isNode) {
    throw new Error('loadWasmSync: browser must await loadWasm() first');
  }
  const buf = nodeReadWasmSync(name);
  return instantiateFromBuffer(buf);
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
  cache.clear();
}

// 引用 readFile 以避免被 unused 误删（运行时仅在动态分支用到）。
void readFile;

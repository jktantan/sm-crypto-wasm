/**
 * WASM 加载器（**浏览器版**）。
 *
 * 打包时由 package.json 的 `browser` 字段替换 `loadWasm.js`。存在的唯一理由是：
 * 浏览器的模块图里**不能出现 `node:*`** —— Webpack 5 / esbuild / Rspack 在解析期
 * 就会因此构建失败（Vite 是少数会把 `node:*` 外部化成空 stub 的特例，不能依赖）。
 * 本文件因此**零 `node:*` 引用**，共享逻辑在 `loadWasm.core.ts`。
 *
 * Node 环境下这个文件不会被用到（Node 用 `loadWasm.ts`）。
 */

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

/**
 * 每个算法的 wasm URL。
 *
 * **显式列出**而不是用模板拼路径（`../${name}/${name}.wasm`）：打包器只能静态识别
 * `new URL('./literal.wasm', import.meta.url)` 这种写法，才会把 wasm 归档进产物并
 * 重写 URL；动态拼接出来的路径打包器既不会复制文件、也不会改写，运行时必然 404。
 */
const WASM_URLS: Record<WasmAlgo, URL> = {
  sm2: new URL('../sm2/sm2.wasm', import.meta.url),
  sm3: new URL('../sm3/sm3.wasm', import.meta.url),
  sm4: new URL('../sm4/sm4.wasm', import.meta.url),
  sm9: new URL('../sm9/sm9.wasm', import.meta.url),
  zuc: new URL('../zuc/zuc.wasm', import.meta.url),
};

/**
 * 取 wasm 字节（浏览器路径：`fetch` 同级资源，URL 由打包器解析）。
 *
 * @param name 算法名。
 * @returns wasm 二进制 ArrayBuffer（总是一次新的读取）。
 */
async function fetchWasm(name: WasmAlgo): Promise<ArrayBuffer> {
  const url = WASM_URLS[name];
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`loadWasm: failed to fetch ${url}: ${res.status} ${res.statusText}`);
  }
  return res.arrayBuffer();
}

/**
 * 异步加载并实例化 wasm。**这是业务代码的主入口**。
 *
 * 并发安全：同名的第二次调用复用第一次的 Promise，不会触发额外 instantiate。
 * 调用前请确保已初始化（软件包文档里说明的 wasm 资源可被解析到）。
 *
 * @param name 算法名。
 * @returns 解析后冻结的 WasmModule。
 */
export function loadWasm(name: WasmAlgo): Promise<WasmModule> {
  if (!isWasmAlgo(name)) rejectBadName(name);
  return memoizeLoad(name, async (n) => instantiateFromBuffer(await fetchWasm(n)));
}

/**
 * 同步加载：**浏览器端不可用**（`fetch` 本质上异步）。
 *
 * @param name 算法名。
 * @throws 恒抛错，提示改用 `await loadWasm(name)`。
 */
export function loadWasmSync(name: WasmAlgo): WasmModule {
  if (!isWasmAlgo(name)) rejectBadName(name);
  throw new Error('loadWasmSync: browser must await loadWasm() first');
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
 * 清空缓存。仅供测试使用。
 */
export function _resetCacheForTests(): void {
  resetCacheForTests();
}

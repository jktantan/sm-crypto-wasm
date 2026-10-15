/// <reference types="vite/client" />

/**
 * 文档站专用的 wasm 加载器 —— 在构建期替换掉库内部的 `runtime/loadWasm.js`
 * （替换规则见 `../config.ts` 的 `wasmLoaderShimPlugin`）。
 *
 * 需要它的原因：库的浏览器分支用
 * `fetch(new URL(\`../${name}/${name}.wasm\`, import.meta.url))` 定位 wasm，URL 是
 * 运行时拼出来的，打包器静态分析不了；在 VitePress 的产物布局里会落到不存在的
 * 路径。这里改用 Vite 的 `?url` 静态导入 —— 源文件正是 `pnpm build:wasm:all`
 * 产出的 `dist/<algo>/<algo>.wasm`，所以 Playground 跑的就是发布包里那一份。
 *
 * 导出面必须与 `dist/runtime/loadWasm.js` 一致（`loadWasm` / `loadWasmSync` /
 * `getCachedWasm` / `_resetCacheForTests`），否则 dist 里的 import 会解析失败。
 */

import sm2Url from '../../../dist/sm2/sm2.wasm?url';
import sm3Url from '../../../dist/sm3/sm3.wasm?url';
import sm4Url from '../../../dist/sm4/sm4.wasm?url';
import sm9Url from '../../../dist/sm9/sm9.wasm?url';
import zucUrl from '../../../dist/zuc/zuc.wasm?url';

/** 算法白名单，与库保持一致。 */
export type WasmAlgo = 'sm2' | 'sm3' | 'sm4' | 'sm9' | 'zuc';

/** 与库同形的模块封装。 */
export interface WasmModule {
  readonly exports: WebAssembly.Exports;
  readonly memory: WebAssembly.Memory;
}

const WASM_ALGOS: readonly WasmAlgo[] = ['sm2', 'sm3', 'sm4', 'sm9', 'zuc'];

const URLS: Record<WasmAlgo, string> = {
  sm2: sm2Url,
  sm3: sm3Url,
  sm4: sm4Url,
  sm9: sm9Url,
  zuc: zucUrl,
};

/**
 * ASC 默认产物会导入 `env` 模块的这三个符号，与库内 `loadWasm` 的 stub 保持一致。
 */
const ASC_ENV: WebAssembly.Imports = {
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

function assertAlgo(name: unknown): asserts name is WasmAlgo {
  if (typeof name !== 'string' || !(WASM_ALGOS as readonly string[]).includes(name)) {
    throw new RangeError(
      `loadWasm: 未知算法 ${typeof name === 'string' ? `"${name}"` : typeof name}`,
    );
  }
}

const cache = new Map<WasmAlgo, Promise<WasmModule>>();

/** 与库同签名：并发调用复用同一 Promise，wasm 只实例化一次。 */
export function loadWasm(name: WasmAlgo): Promise<WasmModule> {
  assertAlgo(name);
  let p = cache.get(name);
  if (!p) {
    p = (async () => {
      const res = await fetch(URLS[name]);
      if (!res.ok) {
        throw new Error(`loadWasm: 拉取 ${name}.wasm 失败（${res.status} ${res.statusText}）`);
      }
      const bytes = await res.arrayBuffer();
      const mod = await WebAssembly.compile(bytes);
      const inst = await WebAssembly.instantiate(mod, ASC_ENV);
      return Object.freeze({
        exports: inst.exports,
        memory: inst.exports.memory as WebAssembly.Memory,
      });
    })();
    cache.set(name, p);
  }
  return p;
}

/**
 * 文档站只在浏览器里跑 Playground，没有同步读文件的路径。
 * 保留该导出只为与库的模块形状对齐。
 */
export function loadWasmSync(name: WasmAlgo): WasmModule {
  assertAlgo(name);
  throw new Error('loadWasmSync: 文档站运行在浏览器中，请改用 `await loadWasm()`');
}

/** 语义化别名，与库一致。 */
export function getCachedWasm(name: WasmAlgo): Promise<WasmModule> {
  return loadWasm(name);
}

/** 清空缓存（调试用）。 */
export function _resetCacheForTests(): void {
  cache.clear();
}

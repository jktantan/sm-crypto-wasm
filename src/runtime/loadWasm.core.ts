/**
 * WASM 加载器共享核心（Node 版与浏览器版共用）。
 *
 * ## 为什么要拆 core
 *
 * `node:*` 内置模块**不能出现在浏览器构建的模块图里**：打包器（Webpack 5 /
 * esbuild / Rspack）在**解析期**就会因 `node:fs` 之类的裸模块报错中止，而
 * tree-shaking 帮不上忙 —— 解析先于摇树。所以：
 *
 * - Node 侧（读文件）实现放 `loadWasm.ts`；
 * - 浏览器侧（fetch）实现放 `loadWasm.browser.ts`；
 * - 由 package.json 的 `browser` 字段在打包时做文件替换；
 * - **本文件两者共用，且零 `node:*` 引用**。
 *
 * WASM loader shared core (used by both the Node and the browser version).
 *
 * ## Why a separate core
 *
 * `node:*` built-in modules **must not appear in the browser bundle's module graph**:
 * bundlers (Webpack 5 / esbuild / Rspack) abort at **resolve time** on a bare module
 * such as `node:fs`, and tree-shaking cannot help — resolution happens before shaking.
 * Therefore:
 *
 * - the Node side (reading files) lives in `loadWasm.ts`;
 * - the browser side (fetch) lives in `loadWasm.browser.ts`;
 * - the `browser` field in package.json swaps the file at bundle time;
 * - **this file is shared by both and has zero `node:*` references**.
 */

/** 算法白名单：确保非法 `name` 在到达文件系统 / 网络前被拒绝。
 *
 * Algorithm allow-list: an illegal `name` is rejected before it ever reaches the
 * filesystem or the network.
 */
const WASM_ALGOS = ['sm2', 'sm3', 'sm4', 'sm9', 'zuc'] as const;
/** 白名单里的算法名类型（由 `WASM_ALGOS` 推导，新增/删除算法时自动跟随）。
 *
 * The type of the names in the allow-list (derived from `WASM_ALGOS`, so it follows
 * automatically when an algorithm is added or removed).
 */
export type WasmAlgo = (typeof WASM_ALGOS)[number];

/**
 * 判定值是否为受支持的算法名。
 *
 * Checks whether a value is a supported algorithm name.
 */
export function isWasmAlgo(name: unknown): name is WasmAlgo {
  return typeof name === 'string' && (WASM_ALGOS as readonly string[]).includes(name);
}

/**
 * 对未知算法名抛出 `RangeError`（加载器的不可达保护）。
 *
 * Throws `RangeError` for an unknown algorithm name (loader guard).
 */
export function rejectBadName(name: unknown): never {
  const got = typeof name === 'string' ? `"${name}"` : typeof name;
  throw new RangeError(
    `loadWasm: 未知算法 ${got}，期望 ${WASM_ALGOS.map((a) => `"${a}"`).join(' | ')}`,
  );
}

/** 加载完成后的 WASM 模块封装。`exports` 已类型化为 `WebAssembly.Exports`。
 *
 * Wrapper around a loaded WASM module. `exports` is typed as
 * `WebAssembly.Exports`.
 */
export interface WasmModule {
  readonly exports: WebAssembly.Exports;
  readonly memory: WebAssembly.Memory;
}

/** ASC 默认产物会导入 `env` 模块（abort / trace / __assert_fail）。
 *
 * The default ASC artifact imports an `env` module (abort / trace /
 * __assert_fail).
 */
export const ASC_ENV: WebAssembly.Imports = {
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

/**
 * 同步实例化 wasm。失败抛 WebAssembly 自身的 CompileError / LinkError。
 *
 * @param buf wasm 字节。
 *
 * Instantiate wasm synchronously. Failures surface as WebAssembly's own
 * CompileError / LinkError.
 *
 * @param buf The wasm bytes.
 */
export function instantiateFromBuffer(buf: ArrayBuffer): WasmModule {
  const mod = new WebAssembly.Module(buf);
  const inst = new WebAssembly.Instance(mod, ASC_ENV);
  const exports = inst.exports as WebAssembly.Exports;
  const memory =
    (exports.memory as WebAssembly.Memory | undefined) ?? new WebAssembly.Memory({ initial: 1 });
  return Object.freeze({ exports, memory });
}

/** 模块缓存。key = 算法名，value = 已 memoize 的 Promise。
 *
 * Module cache. key = algorithm name, value = the memoized Promise.
 */
const cache = new Map<WasmAlgo, Promise<WasmModule>>();

/**
 * 按算法名记忆化加载：同名的第二次调用复用第一次的 Promise，并发安全
 * （不会重复 instantiate）。
 *
 * @param name 算法名（调用方已校验）。
 * @param loader 实际取字节 + 实例化的实现（Node / 浏览器各不相同）。
 *
 * Memoized load by algorithm name: a second call with the same name reuses the
 * first Promise and is concurrency-safe (no duplicate instantiation).
 *
 * @param name Algorithm name (already validated by the caller).
 * @param loader The implementation that actually fetches the bytes and instantiates
 *   (differs between Node and the browser).
 */
export function memoizeLoad(
  name: WasmAlgo,
  loader: (name: WasmAlgo) => Promise<WasmModule>,
): Promise<WasmModule> {
  let p = cache.get(name);
  if (!p) {
    p = loader(name);
    cache.set(name, p);
  }
  return p;
}

/**
 * 清空缓存。仅供测试使用 —— 单元测试需要测并发安全场景时必须能重置状态。
 *
 * Clear the cache. Test-only — unit tests that exercise concurrency safety need the
 * ability to reset state.
 */
export function resetCacheForTests(): void {
  cache.clear();
}

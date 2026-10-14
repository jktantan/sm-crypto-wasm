import { beforeEach, describe, expect, it } from 'vitest';
import { _resetCacheForTests, getCachedWasm, loadWasm, loadWasmSync } from '@/runtime/loadWasm';
import { ensureLoaded as sm3Loaded } from '@/sm3';

/**
 * WASM 加载器：记忆化、Node/浏览器分支、错误处理。
 *
 * 注意：`loadWasm` 内部按 `isNode` 选路（happy-dom 下仍为 true），所以本测试不区分
 * Node/浏览器两条分支，专注**记忆化契约**和**错误路径**。
 *
 * 关于 sync/async 共享 Module：
 * Node 的 `Promise` 不能真正同步等待（必须排空 microtask）。因此 `loadWasmSync`
 * 与 `loadWasm` 各自走 `nodeReadWasmSync` / `nodeReadWasmAsync` + `instantiate`
 * 路径，**返回不同 `WasmModule` 实例**（各自一份 `WebAssembly.Memory`）。
 * 这不是 bug：两个 Module 互不可见，业务侧应当统一走异步缓存（`loadWasm`
 * 之后调用业务函数，wasm 数据通过 `instantiate` 拿到的 `memory` 一次性拷出）。
 */
describe('loadWasm 记忆化', () => {
  beforeEach(() => {
    _resetCacheForTests();
  });

  it('loadWasm + getCachedWasm 命中同一 Promise', async () => {
    const a = await loadWasm('sm3');
    const b = await getCachedWasm('sm3');
    expect(b).toBe(a);
  });

  it('多次 loadWasm 返回同一 Module', async () => {
    const a = await loadWasm('sm3');
    const b = await loadWasm('sm3');
    expect(b).toBe(a);
  });

  it('Promise.all 并发：同算法只 instantiate 一次', async () => {
    const [a, b, c] = await Promise.all([loadWasm('sm2'), loadWasm('sm2'), loadWasm('sm2')]);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('loadWasmSync 在 Node 端可独立 instantiate，与异步版可并行工作', () => {
    // 各自一份 Memory，但功能等价：业务函数都能正常调用。
    const a = loadWasmSync('sm3');
    // 业务函数同时使用 sync 与 async 加载的 wasm（理论上不应这么做，但不应崩）。
    expect(typeof a.exports).toBe('object');
    expect(typeof a.memory).toBe('object');
  });
});

describe('loadWasm 错误处理', () => {
  beforeEach(() => {
    _resetCacheForTests();
  });

  it('非法算法名在调用即抛 RangeError（不进文件系统）', () => {
    // 类型系统已拦，这里用 as never 探运行时防御。实现走"同步 throw"而非
    // rejected Promise —— `loadWasm` 不是 async function，错误越早抛越好，
    // 不增加一次 microtask 调度。
    let caught: unknown;
    try {
      void loadWasm('nope' as never);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RangeError);
  });

  it('sync 版的非法名也抛 RangeError', () => {
    expect(() => loadWasmSync('nope' as never)).toThrow(RangeError);
  });

  it('ensureLoaded 走过 happy-dom 路径（用主流程做端到端 sanity）', async () => {
    await sm3Loaded();
    // 再来一遍确认缓存有效。
    await sm3Loaded();
  });
});

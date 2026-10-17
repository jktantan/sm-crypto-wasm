/**
 * SM9 WASM 模块的共享访问层。
 *
 * 把 `ensureLoaded` / `getModule` / 内存视图从业务 API 中拆出来，供
 * `index.ts`、`kem.ts`、`hybrid.ts` 共用，避免模块间循环依赖。
 *
 * spec/plan 对应：`docs/superpowers/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`。
 */

import { loadWasm } from '../runtime/loadWasm.js';

/** SM9 曲线阶 n。 */
export const N = BigInt('0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25');

/** WASM 导出的最小子集。诊断入口的子集。 */
export interface Sm9Exports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly signPubOut: (ksPtr: number, outPtr: number) => void;
  readonly encPubOut: (kePtr: number, outPtr: number) => void;
  readonly signDsOut: (ksPtr: number, idPtr: number, idLen: number, outPtr: number) => void;
  readonly encDeOut: (kePtr: number, idPtr: number, idLen: number, outPtr: number) => void;
  readonly sm9VerifyPubOut: (
    pubPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
  ) => number;
  readonly sm9EncryptPubOut: (
    pubPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    rPtr: number,
    outPtr: number,
    outCap: number,
  ) => number;
  readonly sm9UserEncPubOut: (pubPtr: number, idPtr: number, idLen: number, outPtr: number) => void;
  readonly sm9UserSignPubOut: (
    pubPtr: number,
    idPtr: number,
    idLen: number,
    outPtr: number,
  ) => void;
  readonly sm9SignOut: (
    ksPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    rPtr: number,
    outPtr: number,
  ) => void;
  readonly sm9VerifyOut: (
    ksPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
  ) => number;
  readonly sm9EncryptOut: (
    kePtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    rPtr: number,
    outPtr: number,
    outCap: number,
  ) => number;
  readonly sm9DecryptOut: (
    kePtr: number,
    idPtr: number,
    idLen: number,
    ctPtr: number,
    ctLen: number,
    outPtr: number,
  ) => number;
  readonly sm9KemEncryptOut: (
    kePtr: number,
    idPtr: number,
    idLen: number,
    rPtr: number,
    klen: number,
    c1Ptr: number,
    kPtr: number,
  ) => number;
  /** 用加密主公钥（G1 仿射 64B）做 KEM 封装。 */
  readonly sm9KemEncryptPubOut: (
    pubPtr: number,
    idPtr: number,
    idLen: number,
    rPtr: number,
    klen: number,
    c1Ptr: number,
    kPtr: number,
  ) => number;
  readonly sm9KemDecryptOut: (
    kePtr: number,
    idPtr: number,
    idLen: number,
    c1Ptr: number,
    klen: number,
    kPtr: number,
  ) => number;
  readonly sm9ExchEphemeralOut: (
    kePtr: number,
    peerIdPtr: number,
    peerIdLen: number,
    rPtr: number,
    outPtr: number,
  ) => void;
  readonly sm9ExchKeyOut: (
    kePtr: number,
    isInitiator: number,
    selfIdPtr: number,
    selfIdLen: number,
    peerIdPtr: number,
    peerIdLen: number,
    rPtr: number,
    selfRPtr: number,
    peerRPtr: number,
    klen: number,
    outPtr: number,
  ) => number;
  readonly sm9ExchConfirmOut: (
    kePtr: number,
    isInitiator: number,
    selfIdPtr: number,
    selfIdLen: number,
    peerIdPtr: number,
    peerIdLen: number,
    rPtr: number,
    selfRPtr: number,
    peerRPtr: number,
    prefix: number,
    outPtr: number,
  ) => void;
  readonly sm9ExchAllOut: (
    kePtr: number,
    isInitiator: number,
    selfIdPtr: number,
    selfIdLen: number,
    peerIdPtr: number,
    peerIdLen: number,
    rPtr: number,
    selfRPtr: number,
    peerRPtr: number,
    klen: number,
    saPtr: number,
    sbPtr: number,
    kPtr: number,
  ) => number;
  /** 诊断：cyclotomic 平方自测（随机子群元素上 cyc 平方 vs 通用平方）。1=一致。 */
  readonly sqrCycSelfTestOut: (seed: number) => number;
  readonly memory: WebAssembly.Memory;
}

export interface Sm9Module {
  exports: Sm9Exports;
  memory: WebAssembly.Memory;
}

/** 预热 WASM 模块。 */
export async function ensureLoaded(): Promise<void> {
  if ((globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm) return;
  const mod = await loadWasm('sm9');
  (globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm = {
    exports: mod.exports as unknown as Sm9Exports,
    memory: mod.memory,
  };
}

/** 取已加载的模块；未预热时抛错（调用方应先 `await ensureLoaded()`）。 */
export function getModule(): Sm9Module {
  const m = (globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm;
  if (!m) throw new Error('sm9: 未初始化，请先 `await ensureLoaded()`。');
  return m;
}

/** WASM 线性内存视图（每次现取，避免 memory.grow 后旧视图失效）。 */
export function mem(): Uint8Array {
  return new Uint8Array(getModule().memory.buffer);
}

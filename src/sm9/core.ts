/**
 * SM9 WASM 模块的共享访问层。
 *
 * 把 `ensureLoaded` / `getModule` / 内存视图从业务 API 中拆出来，供
 * `index.ts`、`kem.ts`、`hybrid.ts` 共用，避免模块间循环依赖。
 *
 * spec/plan 对应：`docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`。
 *
 * Shared access layer for the SM9 WASM module.
 *
 * Splits `ensureLoaded` / `getModule` / the memory view out of the business API so
 * `index.ts`, `kem.ts`, and `hybrid.ts` can share them without circular imports.
 *
 * Spec / plan: `docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`.
 */

import { loadWasm } from '../runtime/loadWasm.js';

/**
 * SM9 曲线阶 n（签名 / 加密主私钥与随机数的标量模数）。
 *
 * The order n of the SM9 curve (the scalar modulus for signing / encryption
 * master private keys and nonces).
 */
export const N = BigInt('0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25');

/**
 * SM9 wasm 导出子集：密钥派生、签名/验签、加解密、KEM 与密钥交换。
 *
 * Subset of SM9 wasm exports: key derivation, sign/verify, encrypt/decrypt,
 * KEM, and key exchange.
 */
export interface Sm9Exports extends WebAssembly.Exports {
  // WASM 侧内存管理：`alloc` 从 AS 堆取 n 字节并重置 arena，`freeAll` 释放全部
  // 缓冲并重置 arena；两者在每个调用点成对使用（`finally` 里释放）。
  //
  // WASM-side memory management: `alloc` takes n bytes from the AS heap and rewinds
  // the arena; `freeAll` releases every buffer and rewinds the arena. The two are
  // used as a pair at each call site (released in `finally`).
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  // 密钥派生：主密钥 → 主公钥 / 用户私钥。
  //
  // Key derivation: master key → master public key / user private key.
  readonly signPubOut: (ksPtr: number, outPtr: number) => void;
  readonly encPubOut: (kePtr: number, outPtr: number) => void;
  readonly signDsOut: (ksPtr: number, idPtr: number, idLen: number, outPtr: number) => void;
  readonly encDeOut: (kePtr: number, idPtr: number, idLen: number, outPtr: number) => void;
  // 验签。
  //
  // Verification.
  readonly sm9VerifyPubOut: (
    pubPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
  ) => number;
  // 用主公钥加密。
  //
  // Encryption with the master public key.
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
  // 用户公钥派生。
  //
  // User public-key derivation.
  readonly sm9UserEncPubOut: (pubPtr: number, idPtr: number, idLen: number, outPtr: number) => void;
  readonly sm9UserSignPubOut: (
    pubPtr: number,
    idPtr: number,
    idLen: number,
    outPtr: number,
  ) => void;
  // 用主私钥签名。
  //
  // Signing with the master private key.
  readonly sm9SignOut: (
    ksPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    rPtr: number,
    outPtr: number,
  ) => void;
  // 验签（从主私钥派生主公钥）。
  //
  // Verification (derives the master public key from the private key).
  readonly sm9VerifyOut: (
    ksPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
  ) => number;
  // 加密（从主私钥派生主公钥）。
  //
  // Encryption (derives the master public key from the private key).
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
  // 解密。
  //
  // Decryption.
  readonly sm9DecryptOut: (
    kePtr: number,
    idPtr: number,
    idLen: number,
    ctPtr: number,
    ctLen: number,
    outPtr: number,
  ) => number;
  // KEM 封装。
  //
  // KEM encapsulation.
  readonly sm9KemEncryptOut: (
    kePtr: number,
    idPtr: number,
    idLen: number,
    rPtr: number,
    klen: number,
    c1Ptr: number,
    kPtr: number,
  ) => number;
  /**
   * 用加密主公钥（G1 仿射 64B）做 KEM 封装。
   *
   * KEM encapsulation with the encryption master public key (G1 affine, 64 bytes).
   */
  readonly sm9KemEncryptPubOut: (
    pubPtr: number,
    idPtr: number,
    idLen: number,
    rPtr: number,
    klen: number,
    c1Ptr: number,
    kPtr: number,
  ) => number;
  // KEM 解封装。
  //
  // KEM decapsulation.
  readonly sm9KemDecryptOut: (
    kePtr: number,
    idPtr: number,
    idLen: number,
    c1Ptr: number,
    klen: number,
    kPtr: number,
  ) => number;
  // 密钥交换：临时公钥、共享密钥与确认值。
  //
  // Key exchange: ephemeral key, shared key, and confirmation value.
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
  /**
   * 诊断：cyclotomic 平方自测（随机子群元素上 cyc 平方 vs 通用平方）。1=一致。
   *
   * Diagnostic: cyclotomic squaring self-test (cyclotomic versus generic squaring
   * on a random subgroup element). 1 = consistent.
   */
  readonly sqrCycSelfTestOut: (seed: number) => number;
  readonly memory: WebAssembly.Memory;
}

/**
 * 已加载的 SM9 wasm 模块：导出函数表与线性内存。
 *
 * A loaded SM9 wasm module: its export table and its linear memory.
 */
export interface Sm9Module {
  exports: Sm9Exports;
  memory: WebAssembly.Memory;
}

/**
 * 预热 WASM 模块。
 *
 * 结果缓存在 `globalThis.__sm9Wasm`，已预热时直接返回、不再实例化。
 *
 * Preloads the WASM module.
 *
 * The result is cached on `globalThis.__sm9Wasm`, so a second call returns
 * immediately instead of instantiating again.
 */
export async function ensureLoaded(): Promise<void> {
  if ((globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm) return;
  const mod = await loadWasm('sm9');
  (globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm = {
    exports: mod.exports as unknown as Sm9Exports,
    memory: mod.memory,
  };
}

/**
 * 取已加载的模块；未预热时抛错（调用方应先 `await ensureLoaded()`）。
 *
 * Returns the already-loaded module; throws when it was not preloaded (callers
 * should `await ensureLoaded()` first).
 */
export function getModule(): Sm9Module {
  const m = (globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm;
  if (!m) throw new Error('sm9: 未初始化，请先 `await ensureLoaded()`。');
  return m;
}

/**
 * WASM 线性内存视图（每次现取，避免 memory.grow 后旧视图失效）。
 *
 * A fresh view over the WASM linear memory; read it again on every use so a
 * `memory.grow` cannot leave a stale view behind.
 */
export function mem(): Uint8Array {
  return new Uint8Array(getModule().memory.buffer);
}

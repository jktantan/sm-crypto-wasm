/**
 * SM4 业务 API（TS 胶水层，调 WASM）。
 *
 * 支持模式：ECB / CBC / CTR / CFB / OFB / GCM。
 * 除底层单块入口 `sm4Block` 外，CBC/CTR/CFB/OFB/GCM 均调用 wasm 侧的整段模式
 * 函数，循环在 WASM 内完成，避免逐块跨界开销。
 *
 * spec/plan 对应：plan Task 9；spec §6 API。
 *
 * SM4 business API (TypeScript glue layer calling WASM).
 *
 * Supported modes: ECB / CBC / CTR / CFB / OFB / GCM.
 * Except for the low-level single-block `sm4Block`, the other modes call
 * whole-buffer wasm entry points, keeping the loop inside WASM and avoiding
 * per-block boundary overhead.
 *
 * Spec/plan: plan Task 9; spec §6 API.
 */

import { fromBytes, toBytes } from '../runtime/convert.js';
import {
  CiphertextError,
  DecryptionError,
  InvalidCiphertextError,
  InvalidKeyError,
} from '../runtime/errors.js';
import { loadWasm } from '../runtime/loadWasm.js';

/**
 * wasm 侧 `dist/sm4/sm4.wasm` 的导出签名。
 *
 * 指针都是 wasm 线性内存里的字节偏移，长度单位为字节；
 * 单块入口固定 16 字节，批量入口的长度约由调用方保证。
 *
 * Export signatures of `dist/sm4/sm4.wasm`.
 *
 * Pointers are byte offsets into the wasm linear memory and lengths are in
 * bytes; the single-block entries are fixed at 16 bytes, while the batch
 * entries rely on the caller for any length constraint.
 */
interface Sm4Exports extends WebAssembly.Exports {
  /**
   * 从 wasm 堆分配 n 字节，返回字节偏移。
   *
   * Allocate n bytes from the wasm heap and return the byte offset.
   */
  readonly alloc: (n: number) => number;
  /**
   * 释放全部 `alloc` 出来的缓冲。
   *
   * Release every buffer handed out by `alloc`.
   */
  readonly freeAll: () => void;
  /**
   * 批量 ECB 加密（inLen 为 16 的倍数）。
   *
   * Whole-buffer ECB encryption (inLen is a multiple of 16).
   */
  readonly sm4EncryptECB: (keyPtr: number, inPtr: number, inLen: number, outPtr: number) => void;
  /**
   * 批量 ECB 解密（inLen 为 16 的倍数）。
   *
   * Whole-buffer ECB decryption (inLen is a multiple of 16).
   */
  readonly sm4DecryptECB: (keyPtr: number, inPtr: number, inLen: number, outPtr: number) => void;
  /**
   * 单块加密 / 解密（`decrypt` 非 0 即解密）。
   *
   * Single-block encrypt/decrypt (a non-zero `decrypt` means decryption).
   */
  readonly sm4Block: (keyPtr: number, inPtr: number, outPtr: number, decrypt: number) => void;
  /**
   * GCM 加密：密文写 `outPtr`，16 字节标签写 `tagPtr`。
   *
   * GCM encryption: ciphertext into `outPtr`, the 16-byte tag into `tagPtr`.
   */
  readonly sm4GcmEncrypt: (
    keyPtr: number,
    ivPtr: number,
    ivLen: number,
    aadPtr: number,
    aadLen: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
    tagPtr: number,
  ) => void;
  /**
   * GCM 解密 + 认证：返回非 0 表示标签校验失败。
   *
   * GCM decryption plus authentication; a non-zero return means the tag check
   * failed.
   */
  readonly sm4GcmDecrypt: (
    keyPtr: number,
    ivPtr: number,
    ivLen: number,
    aadPtr: number,
    aadLen: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
    tagPtr: number,
  ) => number;
  /**
   * 批量 CBC 加密/解密（整段一次调用，循环在 wasm 内）。
   *
   * Whole-buffer CBC encrypt/decrypt in a single call (the loop runs in wasm).
   */
  readonly sm4CbcEncrypt: (
    keyPtr: number,
    ivPtr: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
  ) => void;
  /**
   * 批量 CBC 解密（整段一次调用，循环在 wasm 内）。
   *
   * Whole-buffer CBC decryption in a single call (the loop runs in wasm).
   */
  readonly sm4CbcDecrypt: (
    keyPtr: number,
    ivPtr: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
  ) => void;
  /**
   * 批量 CTR（自反，长度任意）。
   *
   * Whole-buffer CTR (self-inverse, any length).
   */
  readonly sm4CtrCrypt: (
    keyPtr: number,
    ivPtr: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
  ) => void;
  /**
   * 批量 CFB128（加密 / 解密；反馈取密文段）。
   *
   * Whole-buffer CFB128 (encrypt/decrypt; the feedback is the ciphertext
   * segment).
   */
  readonly sm4CfbEncrypt: (
    keyPtr: number,
    ivPtr: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
  ) => void;
  /**
   * 批量 CFB128 解密（反馈取密文段）。
   *
   * Whole-buffer CFB128 decryption (the feedback is the ciphertext segment).
   */
  readonly sm4CfbDecrypt: (
    keyPtr: number,
    ivPtr: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
  ) => void;
  /**
   * 批量 OFB（自反，长度任意）。
   *
   * Whole-buffer OFB (self-inverse, any length).
   */
  readonly sm4OfbCrypt: (
    keyPtr: number,
    ivPtr: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
  ) => void;
  /**
   * wasm 线性内存句柄；调用方据此建 `Uint8Array` 视图读写上面各指针指向的缓冲。
   *
   * The wasm linear-memory handle; callers build `Uint8Array` views on it to
   * read and write the buffers the pointers above address.
   */
  readonly memory: WebAssembly.Memory;
}

/**
 * 已缓存的 wasm 实例：导出表 + 内存句柄。
 *
 * The cached wasm instance: its export table plus the memory handle.
 */
interface Sm4Module {
  exports: Sm4Exports;
  memory: WebAssembly.Memory;
}

/**
 * 预热 WASM 模块。
 *
 * 实例缓存在 `globalThis.__sm4Wasm` 上，后面的同步 API 直接复用；
 * 加载失败由 `loadWasm` 原样抛出，不做兜底。
 *
 * Warm up the WASM module.
 *
 * The instance is cached on `globalThis.__sm4Wasm` and reused by the
 * synchronous APIs below; load failures propagate from `loadWasm` unchanged.
 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('sm4');
  (globalThis as { __sm4Wasm?: Sm4Module }).__sm4Wasm = {
    exports: mod.exports as unknown as Sm4Exports,
    memory: mod.memory,
  };
}

/**
 * 取出已缓存的 wasm 实例。
 *
 * 未调用 `ensureLoaded()` 时抛错：同步 API 不做隐式加载，以免在同步路径上
 * 引入隐式 await。
 *
 * Return the cached wasm instance.
 *
 * Throws when `ensureLoaded()` has not run: the synchronous APIs never load
 * implicitly, so no hidden await is introduced on the sync path.
 */
function getModule(): Sm4Module {
  const mod = (globalThis as { __sm4Wasm?: Sm4Module }).__sm4Wasm;
  if (!mod) {
    throw new Error('sm4: 未初始化，请先 `await ensureLoaded()`。');
  }
  return mod;
}

/**
 * 在 wasm 内存里临时铺三个缓冲，用完自动 freeAll。
 *
 * key 固定 16 字节；`data` 为空时仍分配 1 字节，保证指针可写；
 * 无论回调是否抛错都会走 `freeAll`。
 *
 * Lay out three temporary buffers in wasm memory and always `freeAll` after.
 *
 * The key is always 16 bytes; when `data` is empty a 1-byte buffer is
 * allocated anyway so the pointer stays writable; `freeAll` runs even if the
 * callback throws.
 */
function withBuffers<T>(
  key: Uint8Array,
  data: Uint8Array,
  outLen: number,
  fn: (keyPtr: number, inPtr: number, outPtr: number) => T,
): T {
  const { exports, memory } = getModule();
  const keyPtr = exports.alloc(16);
  const inPtr = exports.alloc(data.length === 0 ? 1 : data.length);
  const outPtr = exports.alloc(outLen);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(key, keyPtr);
    mem.set(data, inPtr);
    return fn(keyPtr, inPtr, outPtr);
  } finally {
    exports.freeAll();
  }
}

/**
 * ECB 加密（多块）。
 *
 * 输入长度必须是 16 的非零倍数；返回 hex。
 *
 * ECB encryption over multiple blocks.
 *
 * The input length must be a non-zero multiple of 16; returns hex.
 */
export function encryptECB(key: string | Uint8Array, msg: string | Uint8Array): string {
  const k = toBytes(key, 'key');
  const m = toBytes(msg, 'msg');
  if (k.length !== 16) throw new InvalidKeyError('sm4: key must be 16 bytes');
  if (m.length % 16 !== 0 || m.length === 0) {
    throw new RangeError('sm4 ECB: 明文长度必须是 16 的非零倍数');
  }
  const out = withBuffers(k, m, m.length, (kp, ip, op) => {
    const { exports } = getModule();
    exports.sm4EncryptECB(kp, ip, m.length, op);
    return new Uint8Array(getModule().memory.buffer, op, m.length).slice();
  });
  return fromBytes(out, 'hex');
}

/**
 * ECB 解密（多块）。
 *
 * 密文长度必须是 16 的非零倍数；返回 hex。
 *
 * ECB decryption over multiple blocks.
 *
 * The ciphertext length must be a non-zero multiple of 16; returns hex.
 */
export function decryptECB(key: string | Uint8Array, ct: string | Uint8Array): string {
  const k = toBytes(key, 'key');
  const c = toBytes(ct, 'ct');
  if (k.length !== 16) throw new InvalidKeyError('sm4: key must be 16 bytes');
  if (c.length % 16 !== 0 || c.length === 0) {
    throw new InvalidCiphertextError('sm4 ECB: 密文长度必须是 16 的非零倍数');
  }
  const out = withBuffers(k, c, c.length, (kp, ip, op) => {
    const { exports } = getModule();
    exports.sm4DecryptECB(kp, ip, c.length, op);
    return new Uint8Array(getModule().memory.buffer, op, c.length).slice();
  });
  return fromBytes(out, 'hex');
}

// 注：原先 CFB / OFB 是逐块调用 `encryptBlock`（内部再调 wasm 的 `sm4Block`），
// 1 KB 就要 64 次跨界；改成批量导出后这两个单块包装已无调用者，随删。
// wasm 侧的 `sm4Block` 导出本身保留 —— 它仍是对外暴露的底层单块能力。
//
// Note: CFB / OFB used to call `encryptBlock` per block (which in turn called
// the wasm `sm4Block`), costing 64 crossings per KB. Once the batch exports
// landed these two single-block wrappers had no callers left, so they were
// deleted along with them. The wasm-side `sm4Block` export itself stays: it is
// still the low-level single-block capability exposed to callers.

/**
 * 16 字节按字节异或（保留的工具函数，当前无调用者）。
 *
 * Byte-wise XOR of 16 bytes (a retained helper; currently unused).
 */
function _xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  return out;
}

/**
 * CBC 加密（PKCS#7 填充）。
 *
 * 明文先补 PKCS#7 到 16 的倍数（已对齐的明文也会多出一整块），
 * 再由 wasm 侧一次加密整段。
 *
 * CBC encryption with PKCS#7 padding.
 *
 * The plaintext is PKCS#7-padded to a multiple of 16 (already aligned input
 * still gains a full padding block) and then encrypted in one wasm call.
 */
export function encryptCBC(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const m = toBytes(msg, 'msg');
  if (k.length !== 16 || v.length !== 16)
    throw new InvalidKeyError('sm4 CBC: key/iv must be 16 bytes');
  const padded = pkcs7Pad(m);
  const out = withBuffers(k, padded, padded.length, (kp, ip, op) => {
    const { exports, memory } = getModule();
    const ivPtr = exports.alloc(16);
    new Uint8Array(memory.buffer).set(v, ivPtr);
    exports.sm4CbcEncrypt(kp, ivPtr, ip, padded.length, op);
    return new Uint8Array(memory.buffer, op, padded.length).slice();
  });
  return fromBytes(out, 'hex');
}

/**
 * CBC 解密。
 *
 * 输入长度必须是 16 的倍数；解密后校验并去掉 PKCS#7 填充。
 *
 * CBC decryption.
 *
 * The input length must be a multiple of 16; the PKCS#7 padding is validated
 * and stripped afterwards.
 */
export function decryptCBC(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const c = toBytes(ct, 'ct');
  if (k.length !== 16 || v.length !== 16)
    throw new InvalidKeyError('sm4 CBC: key/iv must be 16 bytes');
  if (c.length % 16 !== 0) throw new InvalidCiphertextError('sm4 CBC: 密文长度必须是 16 的倍数');
  const out = withBuffers(k, c, c.length, (kp, ip, op) => {
    const { exports, memory } = getModule();
    const ivPtr = exports.alloc(16);
    new Uint8Array(memory.buffer).set(v, ivPtr);
    exports.sm4CbcDecrypt(kp, ivPtr, ip, c.length, op);
    return new Uint8Array(memory.buffer, op, c.length).slice();
  });
  const unpadded = pkcs7Unpad(out);
  return fromBytes(unpadded, 'hex');
}

/**
 * CTR 加密/解密（流式，无需填充）。
 *
 * 空输入直接返回空 hex，不进入 wasm。
 *
 * CTR encryption/decryption (streaming, no padding).
 *
 * Empty input returns empty hex without entering wasm.
 */
export function cryptCTR(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const d = toBytes(data, 'data');
  if (k.length !== 16 || v.length !== 16)
    throw new InvalidKeyError('sm4 CTR: key/iv must be 16 bytes');
  if (d.length === 0) return fromBytes(new Uint8Array(0), 'hex');
  const out = withBuffers(k, d, d.length, (kp, ip, op) => {
    const { exports, memory } = getModule();
    const ivPtr = exports.alloc(16);
    new Uint8Array(memory.buffer).set(v, ivPtr);
    exports.sm4CtrCrypt(kp, ivPtr, ip, d.length, op);
    return new Uint8Array(memory.buffer, op, d.length).slice();
  });
  return fromBytes(out, 'hex');
}

/**
 * CFB 加密。
 *
 * CFB encryption.
 */
export function encryptCFB(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
): string {
  return cfb(key, iv, msg, true);
}

/**
 * CFB 解密。
 *
 * CFB decryption.
 */
export function decryptCFB(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
): string {
  return cfb(key, iv, ct, false);
}

/**
 * CFB 的公共实现：加解密共用一条路径，只由 `encrypt` 选择 wasm 导出。
 *
 * Shared CFB implementation: encryption and decryption share one path and
 * differ only in which wasm export `encrypt` selects.
 */
function cfb(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  encrypt: boolean,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const d = toBytes(data, 'data');
  if (k.length !== 16 || v.length !== 16)
    throw new InvalidKeyError('sm4 CFB: key/iv must be 16 bytes');
  if (d.length === 0) return fromBytes(new Uint8Array(0), 'hex');
  // 整段交给 wasm（循环在 wasm 内），避免原先逐块调用 `sm4Block` 的跨界开销。
  //
  // The whole buffer goes to wasm (the loop runs there), avoiding the crossing
  // cost of the earlier per-block `sm4Block` calls.
  const out = withBuffers(k, d, d.length, (kp, ip, op) => {
    const { exports, memory } = getModule();
    const ivPtr = exports.alloc(16);
    new Uint8Array(memory.buffer).set(v, ivPtr);
    if (encrypt) exports.sm4CfbEncrypt(kp, ivPtr, ip, d.length, op);
    else exports.sm4CfbDecrypt(kp, ivPtr, ip, d.length, op);
    return new Uint8Array(memory.buffer, op, d.length).slice();
  });
  return fromBytes(out, 'hex');
}

/**
 * OFB 加密/解密（对称）。
 *
 * OFB encryption/decryption (symmetric: the same call does both).
 */
export function cryptOFB(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const d = toBytes(data, 'data');
  if (k.length !== 16 || v.length !== 16)
    throw new InvalidKeyError('sm4 OFB: key/iv must be 16 bytes');
  if (d.length === 0) return fromBytes(new Uint8Array(0), 'hex');
  // 同 CFB：整段一次调用，循环在 wasm 内。
  //
  // Same as CFB: one call for the whole buffer, the loop runs in wasm.
  const out = withBuffers(k, d, d.length, (kp, ip, op) => {
    const { exports, memory } = getModule();
    const ivPtr = exports.alloc(16);
    new Uint8Array(memory.buffer).set(v, ivPtr);
    exports.sm4OfbCrypt(kp, ivPtr, ip, d.length, op);
    return new Uint8Array(memory.buffer, op, d.length).slice();
  });
  return fromBytes(out, 'hex');
}

// ---------- 命名别名 ----------
// 现名 `cryptCTR` / `cryptOFB` 来自实现历史，保留为主名；下面给出 spec §6 与
// plan Task 9 写的方法名，两者指向同一实现（CTR/OFB 加解密同构）。
//
// ---------- Named aliases ----------
// The current names `cryptCTR` / `cryptOFB` come from the implementation
// history and stay the primary names. The names written in spec §6 and plan
// Task 9 are exported below; both point at the same implementation, because
// CTR/OFB encryption and decryption are the same operation.
export {
  cryptCTR as encryptCTR,
  cryptCTR as decryptCTR,
  cryptOFB as encryptOFB,
  cryptOFB as decryptOFB,
};

// ---------- PKCS#7 ----------

/**
 * PKCS#7 填充：补满到 16 的倍数，补几字节就填几。
 *
 * PKCS#7 padding: pad up to a multiple of 16, filling with the pad length.
 */
function pkcs7Pad(m: Uint8Array): Uint8Array {
  const padLen = 16 - (m.length % 16);
  const out = new Uint8Array(m.length + padLen);
  out.set(m);
  out.fill(padLen, m.length);
  return out;
}

/**
 * 去掉 PKCS#7 填充。
 *
 * 只校验填充长度字段（1..16），不逐字节比对填充内容——与既有行为保持一致；
 * 长度非法抛 `DecryptionError`。
 *
 * Strip the PKCS#7 padding.
 *
 * Only the pad-length byte (1..16) is validated, not the padding bytes
 * themselves, matching the existing behaviour; an invalid length throws
 * `DecryptionError`.
 */
function pkcs7Unpad(m: Uint8Array): Uint8Array {
  if (m.length === 0) throw new RangeError('sm4 CBC: 空输出');
  const padLen = m[m.length - 1] ?? 0;
  if (padLen < 1 || padLen > 16) throw new DecryptionError('sm4 CBC: 非法 PKCS#7 填充');
  return m.subarray(0, m.length - padLen);
}

// ---------- GCM ----------

/**
 * GCM 允许空明文 / 空 AAD，而 `toBytes` 对空输入抛错；这里做一层归一化。
 *
 * GCM allows an empty plaintext / empty AAD, while `toBytes` throws on empty
 * input, so this normalises both into a (possibly empty) byte array.
 */
function optionalBytes(v: string | Uint8Array | undefined, label: string): Uint8Array {
  if (v === undefined) return new Uint8Array(0);
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (v.length === 0) return new Uint8Array(0);
  return toBytes(v, label);
}

/**
 * GCM 输入校验与归一化。
 *
 * key 必为 16 字节，iv 不得为空（SM4-GCM 不接受空 IV）；aad 可省略。
 *
 * Validate and normalise GCM inputs.
 *
 * The key must be 16 bytes and the IV must not be empty (SM4-GCM does not
 * accept an empty IV); the AAD may be omitted.
 */
function gcmInputs(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  aad: string | Uint8Array | undefined,
) {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const a = optionalBytes(aad, 'aad');
  if (k.length !== 16) throw new InvalidKeyError('sm4 GCM: key must be 16 bytes');
  if (v.length === 0) throw new InvalidKeyError('sm4 GCM: iv 不能为空');
  return { k, v, a };
}

/**
 * 在 WASM 内存里铺 GCM 的 6 个缓冲，用完自动 freeAll。
 *
 * 空 iv / aad / data 仍各分配 1 字节，避免把固定小地址当缓冲区；
 * 指针组合通过对象回调交给调用方。
 *
 * Lay out GCM's six buffers in WASM memory and always `freeAll` afterwards.
 *
 * Empty iv / aad / data still get a 1-byte allocation so that no fixed
 * low address is used as a buffer; the pointer bundle is handed to the caller
 * through an object callback.
 */
function withGcmBuffers<T>(
  k: Uint8Array,
  v: Uint8Array,
  a: Uint8Array,
  data: Uint8Array,
  fn: (ptrs: {
    keyPtr: number;
    ivPtr: number;
    aadPtr: number;
    inPtr: number;
    outPtr: number;
    tagPtr: number;
  }) => T,
): T {
  const { exports, memory } = getModule();
  const keyPtr = exports.alloc(16);
  const ivPtr = exports.alloc(v.length === 0 ? 1 : v.length);
  const aadPtr = exports.alloc(a.length === 0 ? 1 : a.length);
  const inPtr = exports.alloc(data.length === 0 ? 1 : data.length);
  const outPtr = exports.alloc(data.length === 0 ? 1 : data.length);
  const tagPtr = exports.alloc(16);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(k, keyPtr);
    mem.set(v, ivPtr);
    if (a.length !== 0) mem.set(a, aadPtr);
    if (data.length !== 0) mem.set(data, inPtr);
    return fn({ keyPtr, ivPtr, aadPtr, inPtr, outPtr, tagPtr });
  } finally {
    exports.freeAll();
  }
}

/**
 * SM4-GCM 加密（AEAD）。
 *
 * @param key 16 字节密钥。
 * @param iv 初始向量，常用 12（96 bit）；其它长度按 GCM 规范走 GHASH 派生。
 * @param msg 明文，可为空。
 * @param aad 附加认证数据，可为空 / 省略。
 * @returns `{ ct, tag }`，均为 hex；`tag` 16 字节。
 *
 * SM4-GCM encryption (AEAD).
 *
 * @param key The 16-byte key.
 * @param iv The initial vector, usually 12 bytes (96 bit); any other length is
 * derived through GHASH as the GCM spec prescribes.
 * @param msg The plaintext; may be empty.
 * @param aad Additional authenticated data; may be empty or omitted.
 * @returns `{ ct, tag }`, both hex; `tag` is 16 bytes.
 */
export function encryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
  aad?: string | Uint8Array,
): { ct: string; tag: string } {
  const { k, v, a } = gcmInputs(key, iv, aad);
  const m = optionalBytes(msg, 'msg');
  return withGcmBuffers(k, v, a, m, (p) => {
    const { exports, memory } = getModule();
    exports.sm4GcmEncrypt(
      p.keyPtr,
      p.ivPtr,
      v.length,
      p.aadPtr,
      a.length,
      p.inPtr,
      m.length,
      p.outPtr,
      p.tagPtr,
    );
    // 调用可能触发 WASM 内存增长，必须重新取 buffer 视图。
    //
    // The call may grow WASM memory, so the buffer view must be re-acquired.
    const mem = new Uint8Array(memory.buffer);
    const ct = new Uint8Array(mem.buffer, p.outPtr, m.length).slice();
    const tag = new Uint8Array(mem.buffer, p.tagPtr, 16).slice();
    return { ct: fromBytes(ct, 'hex'), tag: fromBytes(tag, 'hex') };
  });
}

/**
 * `decryptGCM` 的选项对象形态（替代位置参数 `aad`）。
 *
 * The options-object form of `decryptGCM` (replaces the positional `aad`
 * argument).
 */
export interface Sm4GcmDecryptOptions {
  /**
   * 附加认证数据。
   *
   * Additional authenticated data.
   */
  aad?: string | Uint8Array;
  /**
   * 认证失败时返回 `null` 而不抛错。
   *
   * Return `null` instead of throwing when authentication fails.
   */
  safeMode?: boolean;
}

/**
 * SM4-GCM 解密 + 认证。
 *
 * @param key 16 字节密钥。
 * @param iv 初始向量（与加密一致）。
 * @param ct 密文，可为空（空明文时）。
 * @param tag 16 字节认证标签（hex / base64 / Uint8Array）。
 * @param aad 附加认证数据，可为空 / 省略。
 * @returns 明文 hex。
 * @throws Error 标签校验失败（密文/标签/AAD 任一被篡改）。
 *
 * SM4-GCM decryption plus authentication.
 *
 * @param key The 16-byte key.
 * @param iv The initial vector (the same one used for encryption).
 * @param ct The ciphertext; may be empty (when the plaintext was empty).
 * @param tag The 16-byte authentication tag (hex / base64 / Uint8Array).
 * @param aad Additional authenticated data; may be empty or omitted.
 * @returns The plaintext as hex.
 * @throws Error When the tag check fails (ciphertext, tag or AAD was tampered
 * with).
 */
export function decryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
  tag: string | Uint8Array,
  opts: Sm4GcmDecryptOptions & { safeMode: true },
): string | null;
export function decryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
  tag: string | Uint8Array,
  aad?: string | Uint8Array | Sm4GcmDecryptOptions,
): string;
/**
 * `decryptGCM` 的实作：认证失败抛 `DecryptionError`，`safeMode` 时由门面转为 `null`。
 *
 * The implementation behind `decryptGCM`; authentication failures surface as
 * `DecryptionError`, which the facade turns into `null` under `safeMode`.
 */
export function decryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
  tag: string | Uint8Array,
  aadOrOptions?: string | Uint8Array | Sm4GcmDecryptOptions,
): string | null {
  const opts: Sm4GcmDecryptOptions =
    typeof aadOrOptions === 'object' &&
    aadOrOptions !== null &&
    !(aadOrOptions instanceof Uint8Array)
      ? aadOrOptions
      : { aad: aadOrOptions };
  try {
    return decryptGcmUnsafe(key, iv, ct, tag, opts.aad);
  } catch (err) {
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

/**
 * `decryptGCM` 的实作：认证失败抛 `DecryptionError`。
 *
 * The implementation behind `decryptGCM`; throws `DecryptionError` when
 * authentication fails.
 */
function decryptGcmUnsafe(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
  tag: string | Uint8Array,
  aad?: string | Uint8Array,
): string {
  const { k, v, a } = gcmInputs(key, iv, aad);
  const c = optionalBytes(ct, 'ct');
  const t = toBytes(tag, 'tag');
  if (t.length !== 16) throw new InvalidCiphertextError('sm4 GCM: tag must be 16 bytes');
  return withGcmBuffers(k, v, a, c, (p) => {
    const { exports, memory } = getModule();
    const mem = new Uint8Array(memory.buffer);
    mem.set(t, p.tagPtr);
    const ok = exports.sm4GcmDecrypt(
      p.keyPtr,
      p.ivPtr,
      v.length,
      p.aadPtr,
      a.length,
      p.inPtr,
      c.length,
      p.outPtr,
      p.tagPtr,
    );
    if (ok !== 0) throw new DecryptionError('sm4 GCM: 认证标签校验失败');
    const out = new Uint8Array(memory.buffer);
    const pt = new Uint8Array(out.buffer, p.outPtr, c.length).slice();
    return fromBytes(pt, 'hex');
  });
}

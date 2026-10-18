/**
 * ZUC 业务 API（TS 胶水层，调 WASM）。
 *
 * 支持：
 * - `zucKeystream(key, iv, nBytes)`：生成 nBytes 字节密钥流
 * - `zucEncrypt(key, iv, data, counter?)`：EEA3 加密（带 (key,iv,counter) 复用保护）
 * - `zucDecrypt(key, iv, data, counter?)`：EEA3 解密（异或密钥流，自反；豁免复用保护）
 * - `zucMac(key, iv, msg, bitLength?, tagBits?)`：EIA3 完整性标签（GM/T 0001.3-2012）
 *
 * spec/plan 对应：plan Task 11；spec §3 算法清单、§6 API。
 *
 * ZUC business API (TypeScript glue layer calling WASM).
 *
 * Provides:
 * - `zucKeystream(key, iv, nBytes)`: generate nBytes of keystream;
 * - `zucEncrypt(key, iv, data, counter?)`: EEA3 encryption (with (key, iv, counter)
 *   reuse protection);
 * - `zucDecrypt(key, iv, data, counter?)`: EEA3 decryption (XOR with the keystream,
 *   self-inverse; exempt from reuse protection);
 * - `zucMac(key, iv, msg, bitLength?, tagBits?)`: EIA3 integrity tag
 *   (GM/T 0001.3-2012).
 *
 * Spec/plan: plan Task 11; spec §3 algorithm list, §6 API.
 */

import { bytesToHex, toBytes } from '../runtime/convert.js';
import { InvalidKeyError } from '../runtime/errors.js';
import { loadWasm } from '../runtime/loadWasm.js';

/**
 * WASM 暴露的导出类型。
 *
 * Export types exposed by the WASM module.
 */
interface ZucExports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly zucKeystream: (keyPtr: number, ivPtr: number, outPtr: number, nbytes: number) => void;
  readonly zucEia3Out: (
    keyPtr: number,
    ivPtr: number,
    msgPtr: number,
    msgLen: number,
    nbits: number,
    macPtr: number,
  ) => void;
  readonly memory: WebAssembly.Memory;
}

/**
 * 预热后的模块句柄：导出表 + 线性内存。
 *
 * Preloaded module handle: export table plus linear memory.
 */
interface ZucModule {
  exports: ZucExports;
  memory: WebAssembly.Memory;
}

/**
 * 预热 WASM 模块。
 *
 * Preload the WASM module.
 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('zuc');
  (globalThis as { __zucWasm?: ZucModule }).__zucWasm = {
    exports: mod.exports as unknown as ZucExports,
    memory: mod.memory,
  };
}

/**
 * 取已预热的模块句柄；未预热时抛错，避免在空句柄上继续执行。
 *
 * Fetch the preloaded module handle; throws when nothing was preloaded so the
 * caller never proceeds on an empty handle.
 */
function getModule(): ZucModule {
  const mod = (globalThis as { __zucWasm?: ZucModule }).__zucWasm;
  if (!mod) throw new Error('zuc: 未初始化，请先 `await ensureLoaded()`。');
  return mod;
}

/**
 * 校验 16 字节 key / iv 并归一化为字节数组。
 *
 * Validate that key and iv are 16 bytes each and normalise them to byte arrays.
 */
function keyIv(
  key: string | Uint8Array,
  iv: string | Uint8Array,
): { k: Uint8Array; v: Uint8Array } {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  if (k.length !== 16) throw new InvalidKeyError('zuc: key must be 16 bytes');
  if (v.length !== 16) throw new InvalidKeyError('zuc: iv must be 16 bytes');
  return { k, v };
}

/**
 * 生成 ZUC-128 密钥流。
 *
 * @param key 16 字节密钥。
 * @param iv 16 字节 IV。
 * @param nBytes 输出字节数。
 * @returns 密钥流字节数组。
 *
 * Generate a ZUC-128 keystream.
 *
 * @param key The 16-byte key.
 * @param iv The 16-byte IV.
 * @param nBytes Number of output bytes.
 * @returns The keystream as a byte array.
 */
export function zucKeystream(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  nBytes: number,
): Uint8Array {
  const { k, v } = keyIv(key, iv);
  if (!Number.isInteger(nBytes) || nBytes < 0) throw new RangeError('zuc: bad nBytes');
  if (nBytes === 0) return new Uint8Array(0);
  const { exports, memory } = getModule();
  const keyPtr = exports.alloc(16);
  const ivPtr = exports.alloc(16);
  const outPtr = exports.alloc(nBytes);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(k, keyPtr);
    mem.set(v, ivPtr);
    exports.zucKeystream(keyPtr, ivPtr, outPtr, nBytes);
    return new Uint8Array(memory.buffer, outPtr, nBytes).slice();
  } finally {
    exports.freeAll();
  }
}

// ---------------- EIA3 完整性算法（GM/T 0001.3-2012） ----------------
// ---------------- EIA3 integrity algorithm (GM/T 0001.3-2012) ----------------

/**
 * `zucMac` 选项。位置参数与 options 对象等价；对象形式给将来的扩展留位。
 *
 * Options for `zucMac`. The positional arguments are equivalent to this object;
 * the object form leaves room for future additions.
 */
export interface ZucMacOptions {
  /**
   * 参与计算的消息比特数，默认 `msg.length * 8`。
   *
   * Number of message bits covered; defaults to `msg.length * 8`.
   */
  bitLength?: number;
  /**
   * 标签位数。当前只支持 32（ZUC-256 的 64/128 位属 Non-Goals）。
   *
   * Tag length in bits. Only 32 is supported today (the 64/128-bit ZUC-256 variants
   * are non-goals).
   */
  tagBits?: number;
}

/**
 * 计算 EIA3 完整性标签（GM/T 0001.3-2012 / 3GPP TS 35.221）。
 *
 * IV 由调用方按 `COUNT(32) || BEARER(5) || DIRECTION(1) || 0(26)` 两段等长
 * 结构组装后传入（与 GmSSL `zuc_set_eia_iv` 一致），因此本函数对
 * LTE 场景与裸 IV 场景都可用。
 *
 * @param key 16 字节完整性密钥。
 * @param iv 16 字节 IV。
 * @param msg 消息（hex / base64 / Uint8Array）。
 * @param bitLength 参与计算的消息比特数，默认取完整字节长度 `msg.length * 8`；
 *   非整字节消息（如 577 位）需显式给值。
 * @param tagBits MAC 长度，**仅支持 32**（ZUC-256 的 64/128 位属 Non-Goals）。
 * @returns 4 字节（32 位）标签，大端。
 *
 * Compute an EIA3 integrity tag (GM/T 0001.3-2012 / 3GPP TS 35.221).
 *
 * The caller assembles the IV from `COUNT(32) || BEARER(5) || DIRECTION(1) || 0(26)` as two
 * equal-length halves and passes it in (matching GmSSL `zuc_set_eia_iv`), so this
 * function works both for LTE scenarios and for a raw IV.
 *
 * @param key The 16-byte integrity key.
 * @param iv The 16-byte IV.
 * @param msg The message (hex / base64 / Uint8Array).
 * @param bitLength Number of message bits covered; defaults to the full byte length
 *   `msg.length * 8`. Messages that are not a whole number of bytes (for example
 *   577 bits) must pass it explicitly.
 * @param tagBits MAC length, **32 only** (the 64/128-bit ZUC-256 variants are non-goals).
 * @returns The 4-byte (32-bit) tag, big-endian.
 */
export function zucMac(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
  bitLengthOrOptions?: number | ZucMacOptions,
  tagBits?: number,
): Uint8Array {
  const opts: ZucMacOptions =
    typeof bitLengthOrOptions === 'object' && bitLengthOrOptions !== null
      ? bitLengthOrOptions
      : { bitLength: bitLengthOrOptions, tagBits };
  const resolvedTagBits = opts.tagBits ?? 32;
  if (resolvedTagBits !== 32) {
    throw new RangeError(
      `zuc EIA3: 仅支持 32 位标签，收到 ${resolvedTagBits}（ZUC-256 的 64/128 位不在本期范围）`,
    );
  }
  const { k, v } = keyIv(key, iv);
  const m = toBytes(msg, 'msg');
  const nbits = opts.bitLength ?? m.length * 8;
  if (!Number.isInteger(nbits) || nbits < 0 || nbits > m.length * 8) {
    throw new RangeError(`zuc EIA3: bitLength 必须是 [0, ${m.length * 8}] 内的整数，收到 ${nbits}`);
  }

  const { exports, memory } = getModule();
  const keyPtr = exports.alloc(16);
  const ivPtr = exports.alloc(16);
  const msgPtr = exports.alloc(m.length === 0 ? 1 : m.length);
  const macPtr = exports.alloc(4);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(k, keyPtr);
    mem.set(v, ivPtr);
    mem.set(m, msgPtr);
    exports.zucEia3Out(keyPtr, ivPtr, msgPtr, m.length, nbits, macPtr);
    return new Uint8Array(memory.buffer, macPtr, 4).slice();
  } finally {
    exports.freeAll();
  }
}

/**
 * 按 GM/T 0001.3-2012 / 3GPP TS 35.221 的布局，把 COUNT / BEARER / DIRECTION
 * 组装成 EIA3 的 16 字节 IV（两段等长的 64-bit 结构，见 GmSSL `zuc_set_eia_iv`）。
 *
 * @param count 32 位计数器。
 * @param bearer 5 位承载标识（0..31）。
 * @param direction 方向位（0 或 1）。
 * @returns 16 字节 IV，可直接交给 `zucMac`。
 *
 * Assemble the 16-byte EIA3 IV from COUNT / BEARER / DIRECTION following the layout of
 * GM/T 0001.3-2012 / 3GPP TS 35.221 (two equal 64-bit halves, see GmSSL `zuc_set_eia_iv`).
 *
 * @param count The 32-bit counter.
 * @param bearer The 5-bit bearer identity (0..31).
 * @param direction The direction bit (0 or 1).
 * @returns A 16-byte IV that `zucMac` accepts directly.
 */
export function zucEia3Iv(count: number, bearer: number, direction: number): Uint8Array {
  if (!Number.isInteger(count) || count < 0 || count > 0xffffffff) {
    throw new RangeError(`zuc EIA3: count 必须是 32 位无符号整数，收到 ${count}`);
  }
  if (!Number.isInteger(bearer) || bearer < 0 || bearer > 31) {
    throw new RangeError(`zuc EIA3: bearer 必须是 0..31，收到 ${bearer}`);
  }
  if (direction !== 0 && direction !== 1) {
    throw new RangeError(`zuc EIA3: direction 必须是 0 或 1，收到 ${direction}`);
  }
  const iv = new Uint8Array(16);
  iv[0] = (count >>> 24) & 0xff;
  iv[1] = iv[9] = (count >>> 16) & 0xff;
  iv[2] = iv[10] = (count >>> 8) & 0xff;
  iv[3] = iv[11] = count & 0xff;
  iv[4] = iv[12] = (bearer << 3) & 0xff;
  iv[8] = (iv[0] ?? 0) ^ ((direction << 7) & 0xff);
  iv[14] = (direction << 7) & 0xff;
  return iv;
}

// ---------------- EEA3 机密性算法（GM/T 0001.2-2012） ----------------
// ---------------- EEA3 confidentiality algorithm (GM/T 0001.2-2012) ----------------

/**
 * 已使用过的 (key, iv, counter) 组合。
 *
 * 密钥流重复使用是机密性事故（同密钥流异或两条明文即泄露异或值），
 * 因此加密路径显式拒绝复用，而不是静默放行。
 *
 * Already-used (key, iv, counter) combinations.
 *
 * Reusing a keystream is a confidentiality incident (XOR-ing two plaintexts under the
 * same keystream reveals their XOR), so the encryption path explicitly rejects reuse
 * instead of silently allowing it.
 */
const usedNonces = new Map<string, true>();

/**
 * 复用保护的默认容量上限（FIFO 淘汰最旧一条），可用 `configureReuseGuard` 调整。
 *
 * Default capacity cap for the reuse guard (FIFO-evicts the oldest entry); adjustable
 * through `configureReuseGuard`.
 */
const DEFAULT_REUSE_GUARD_CAPACITY = 4096;

// 运行时开关与容量：`configureReuseGuard` 修改，`zucEncrypt` 读取。
//
// Runtime switch and capacity: mutated by `configureReuseGuard`, read by `zucEncrypt`.
let reuseGuardEnabled = true;
let reuseGuardCapacity = DEFAULT_REUSE_GUARD_CAPACITY;

/**
 * `configureReuseGuard` 的选项。
 *
 * Options for `configureReuseGuard`.
 */
export interface ReuseGuardOptions {
  /**
   * 是否启用复用保护（默认 true）。关掉后同一 (key, iv, counter) 可重复加密。
   *
   * Whether reuse protection is on (default true). Once off, the same
   * (key, iv, counter) may be reused for encryption.
   */
  enabled?: boolean;
  /**
   * 记录上限，超出后 FIFO 淘汰最旧一条（默认 4096）。记录必须有界。
   *
   * Record cap; once exceeded, the oldest entry is evicted FIFO (default 4096). The
   * record must stay bounded.
   */
  capacity?: number;
}

/**
 * 调整 ZUC 复用保护策略。
 *
 * 默认 `{ enabled: true, capacity: 4096 }`。关掉保护只应在"按协议保证不重复使用
 * 同一密钥流"的场景里做，例如密钥/IV 由外部计数器严格管理。
 *
 * Adjust the ZUC reuse-protection policy.
 *
 * The default is `{ enabled: true, capacity: 4096 }`. Turning protection off should only
 * happen where the protocol guarantees the same keystream is never reused, for example
 * when the key/IV are strictly managed by an external counter.
 */
export function configureReuseGuard(opts: ReuseGuardOptions): void {
  if (opts.capacity !== undefined) {
    if (!Number.isInteger(opts.capacity) || opts.capacity < 1) {
      throw new RangeError(`zuc: capacity 必须是正整数，收到 ${opts.capacity}`);
    }
    reuseGuardCapacity = opts.capacity;
  }
  if (opts.enabled !== undefined) reuseGuardEnabled = opts.enabled;
  evictOverflow();
}

/**
 * 把 (key, iv, counter) 拼成复用记录的键（key / iv 转 hex 以免二进制比较）。
 *
 * Build the reuse-record key for (key, iv, counter); key and iv become hex so no
 * binary comparison is needed.
 */
function nonceId(k: Uint8Array, v: Uint8Array, counter: number): string {
  return `${bytesToHex(k)}:${bytesToHex(v)}:${counter}`;
}

/**
 * FIFO 淘汰多余记录，保证表有界。
 *
 * Evict surplus records FIFO so the table stays bounded.
 */
function evictOverflow(): void {
  while (usedNonces.size > reuseGuardCapacity) {
    const oldest = usedNonces.keys().next();
    if (oldest.done) break;
    usedNonces.delete(oldest.value);
  }
}

/**
 * 记录一条已用过的 (key, iv, counter)。
 *
 * Record one already-used (key, iv, counter).
 */
function rememberNonce(id: string): void {
  usedNonces.set(id, true);
  evictOverflow();
}

/**
 * 清空 (key, iv, counter) 复用记录。仅供测试与明确的密钥轮换场景使用。
 *
 * Clear the (key, iv, counter) reuse records. Intended only for tests and explicit key
 * rotation scenarios.
 */
export function resetReuseGuard(): void {
  usedNonces.clear();
}

/**
 * 异或密钥流（EEA3 的加解密本体）。
 *
 * XOR with the keystream (the actual EEA3 encryption/decryption step).
 */
function xorKeystream(k: Uint8Array, v: Uint8Array, data: string | Uint8Array): Uint8Array {
  const bytes = toBytes(data, 'data');
  const ks = zucKeystream(k, v, bytes.length);
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = (bytes[i] ?? 0) ^ (ks[i] ?? 0);
  return out;
}

/**
 * `zucEncrypt` 选项。
 *
 * Options for `zucEncrypt`.
 */
export interface ZucEncryptOptions {
  /**
   * 本次调用是否参与复用保护（默认 true；全局开关见 `configureReuseGuard`）。
   *
   * Whether this call takes part in reuse protection (default true; the global switch is
   * `configureReuseGuard`).
   */
  reuseGuard?: boolean;
}

/**
 * ZUC-128 EEA3 加密。
 *
 * 同一 (key, iv, counter) 只允许加密一次：重复调用抛错（Review Focus #5）。
 * 解密请用 `zucDecrypt`。
 *
 * @param key 16 字节密钥。
 * @param iv 16 字节 IV。
 * @param data 明文。
 * @param counter 计数器，参与复用判定（默认 0）。
 * @param opts `reuseGuard: false` 可显式跳过本次复用保护。
 * @throws InvalidKeyError 当 (key, iv, counter) 已被使用过。
 *
 * ZUC-128 EEA3 encryption.
 *
 * The same (key, iv, counter) may encrypt only once: a repeated call throws (Review
 * Focus #5). Use `zucDecrypt` for decryption.
 *
 * @param key The 16-byte key.
 * @param iv The 16-byte IV.
 * @param data The plaintext.
 * @param counter Counter used in the reuse check (default 0).
 * @param opts `reuseGuard: false` explicitly skips reuse protection for this call.
 * @throws InvalidKeyError When (key, iv, counter) has already been used.
 */
export function zucEncrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  counter = 0,
  opts: ZucEncryptOptions = {},
): Uint8Array {
  const { k, v } = keyIv(key, iv);
  if (!Number.isInteger(counter) || counter < 0) {
    throw new RangeError(`zuc: counter 必须是非负整数，收到 ${counter}`);
  }
  if (!(opts.reuseGuard ?? true) || !reuseGuardEnabled) {
    return xorKeystream(k, v, data);
  }
  const id = nonceId(k, v, counter);
  if (usedNonces.has(id)) {
    throw new InvalidKeyError(
      `zuc: (key, iv, counter) 复用拒绝 —— 该组合已加密过一次（counter=${counter}）；` +
        '重复使用同一密钥流会破坏机密性。解密请用 zucDecrypt()，' +
        '确有需要可传 { reuseGuard: false } 或 configureReuseGuard({ enabled: false })。',
    );
  }
  const out = xorKeystream(k, v, data);
  rememberNonce(id);
  return out;
}

/**
 * ZUC-128 EEA3 解密（异或密钥流，自反）。
 *
 * 解密路径豁免复用保护：密文可能被多次校验/重放处理。
 *
 * @param key 16 字节密钥。
 * @param iv 16 字节 IV。
 * @param data 密文。
 * @param counter 与加密时一致的计数器（保留参数，解密不参与判定）。
 *
 * ZUC-128 EEA3 decryption (XOR with the keystream, self-inverse).
 *
 * The decryption path is exempt from reuse protection: ciphertext may be verified or
 * replayed more than once.
 *
 * @param key The 16-byte key.
 * @param iv The 16-byte IV.
 * @param data The ciphertext.
 * @param counter The counter matching encryption (kept for symmetry; decryption does
 *   not take part in the reuse check).
 */
export function zucDecrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  counter = 0,
): Uint8Array {
  void counter;
  const { k, v } = keyIv(key, iv);
  return xorKeystream(k, v, data);
}

// ---------------- 命名别名 ----------------
// ---------------- Named aliases ----------------
// 现名 `zucEncrypt` / `zucDecrypt` / `zucKeystream` / `zucMac` 保留为主名；
// 下面给出 spec §3/§6 与 plan Task 11 写的方法名，指向同一实现。
//
// The current names `zucEncrypt` / `zucDecrypt` / `zucKeystream` / `zucMac` stay
// primary; the aliases below carry the method names written in spec §3/§6 and plan
// Task 11 and point at the same implementations.
export {
  zucDecrypt as decrypt,
  zucEncrypt as encrypt,
  zucKeystream as generateKeystream,
  zucMac as mac,
  zucMac as eia3,
};

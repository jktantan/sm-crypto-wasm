/**
 * SM2 业务 API（TS 胶水层，调 WASM）。
 *
 * 提供的通用能力：
 * - `getPublicKey(privateKey)`：从私钥派生公钥
 * - `sign(privateKey, message, options?)`：签名
 * - `verify(publicKey, message, signature)`：验签
 * - `encrypt(publicKey, message, options?)`：加密（默认 C1C3C2）
 * - `decrypt(privateKey, ciphertext)`：解密
 * - `kemEncrypt` / `kemDecrypt`：KEM（用公钥保护随机对称密钥，见 `./kem.ts`）
 * - `hybridEncrypt` / `hybridDecrypt`：KEM + SM4-GCM 混合加密（见 `./hybrid.ts`）
 *
 * 说明：
 * - 密钥输入同时接受裸字节（hex）与 PEM（PKCS#8/SEC1 私钥、SPKI 公钥）。
 * - PEM 编解码（PKCS#8/SPKI）在 `src/pem/`；`generateKeyPair` 返回 PEM，密钥入参也接受 PEM。
 *   PEM encoding/decoding lives in `src/pem/`; `generateKeyPair` returns PEM and
 *   key-accepting APIs also accept PEM input.
 * - **随机数一律走宿主 CSPRNG**（`src/runtime/random.ts`）。
 *
 * spec/plan 对应：plan Task 6/8；spec §6 API、§12.1 Q1（默认 C1C3C2）。
 *
 * SM2 business API (TypeScript glue layer calling WASM).
 *
 * General capabilities:
 * - `getPublicKey(privateKey)`: derive the public key from a private key
 * - `sign(privateKey, message, options?)`: sign
 * - `verify(publicKey, message, signature)`: verify
 * - `encrypt(publicKey, message, options?)`: encrypt (C1C3C2 by default)
 * - `decrypt(privateKey, ciphertext)`: decrypt
 * - `kemEncrypt` / `kemDecrypt`: KEM (protect a random symmetric key, see `./kem.ts`)
 * - `hybridEncrypt` / `hybridDecrypt`: KEM + SM4-GCM hybrid encryption (see `./hybrid.ts`)
 *
 * Notes:
 * - key inputs accept both raw bytes (hex) and PEM (PKCS#8/SEC1 private keys, SPKI
 *   public keys); the PEM note above applies unchanged.
 * - **all randomness comes from the host CSPRNG** (`src/runtime/random.ts`).
 *
 * Spec/plan: plan Task 6/8; spec §6 API, §12.1 Q1 (C1C3C2 by default).
 */

import { encodeSm2PrivateKeyPem, encodeSm2PublicKeyPem } from '../pem/sm2.js';
import { bytesToHex, fromBytes, toBytes } from '../runtime/convert.js';
import {
  CiphertextError,
  DecryptionError,
  InvalidCiphertextError,
  InvalidPublicKeyError,
} from '../runtime/errors.js';
import { loadWasm } from '../runtime/loadWasm.js';
import { randomScalarBelow } from '../runtime/random.js';
import { toPrivateKeyBytes, toPublicKeyBytes } from './keyInput.js';

/**
 * WASM 暴露的导出类型。
 *
 * Export types exposed by the WASM module.
 */
interface Sm2Exports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly publicKeyOut: (dPtr: number, outPtr: number) => void;
  readonly signOut: (
    privPtr: number,
    pubXPtr: number,
    pubYPtr: number,
    msgPtr: number,
    msgLen: number,
    kPtr: number,
    outPtr: number,
  ) => number;
  readonly signWithPointOut: (
    privPtr: number,
    pubXPtr: number,
    pubYPtr: number,
    msgPtr: number,
    msgLen: number,
    kPtr: number,
    kxPtr: number,
    outPtr: number,
  ) => number;
  readonly signWithIDOut: (
    privPtr: number,
    pubXPtr: number,
    pubYPtr: number,
    idPtr: number,
    idLen: number,
    msgPtr: number,
    msgLen: number,
    kPtr: number,
    outPtr: number,
  ) => number;
  readonly scalarMulGOut: (kPtr: number, outPtr: number) => void;
  readonly verifyOut: (
    pubXPtr: number,
    pubYPtr: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
  ) => number;
  readonly verifyWithZOut: (
    pubXPtr: number,
    pubYPtr: number,
    zPtr: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
  ) => number;
  readonly computeZIdOut: (
    pubXPtr: number,
    pubYPtr: number,
    idPtr: number,
    idLen: number,
    outPtr: number,
  ) => void;
  readonly encryptOut: (
    pubXPtr: number,
    pubYPtr: number,
    msgPtr: number,
    msgLen: number,
    kPtr: number,
    outPtr: number,
  ) => number;
  readonly prepareCombOut: (pubXPtr: number, pubYPtr: number, capacity: number) => number;
  readonly setCombCapacityOut: (capacity: number) => void;
  readonly clearComb: () => void;
  readonly combSlotKeyOut: (slot: number, outPtr: number) => number;
  readonly decryptOut: (privPtr: number, ctPtr: number, ctLen: number, outPtr: number) => number;
  readonly memory: WebAssembly.Memory;
}

/**
 * 预热后的模块句柄：导出表 + 线性内存。
 *
 * Preloaded module handle: export table plus linear memory.
 */
interface Sm2Module {
  exports: Sm2Exports;
  memory: WebAssembly.Memory;
}

/**
 * 曲线阶 n（SM2），用于随机数范围。
 *
 * The curve order n (SM2), used as the range for random scalars.
 */
const N = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');

/**
 * 素域特征 p。
 *
 * The prime field characteristic p.
 */
const CURVE_P = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF');

/**
 * 曲线系数 a = p - 3。
 *
 * Curve coefficient a = p - 3.
 */
const CURVE_A = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC');

/**
 * 曲线系数 b。
 *
 * Curve coefficient b.
 */
const CURVE_B = BigInt('0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93');

/**
 * 大端字节 → bigint。
 *
 * Big-endian bytes to bigint.
 */
function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i] ?? 0);
  return v;
}

/**
 * 公钥点是否在 SM2 曲线上：`y² ≡ x³ + ax + b (mod p)`，且两坐标都落在 Fp 内。
 *
 * 使用前拒绝坏点可以挡掉"错误子群 / 无效曲线点"这类攻击面（plan Review Focus #3）。
 *
 * Whether the public-key point lies on the SM2 curve: `y² ≡ x³ + ax + b (mod p)`, with
 * both coordinates inside Fp.
 *
 * Rejecting bad points up front shuts down attack surfaces such as “wrong subgroup /
 * invalid curve point” (plan Review Focus #3).
 */
function isOnCurve(x: Uint8Array, y: Uint8Array): boolean {
  const X = bytesToBigInt(x);
  const Y = bytesToBigInt(y);
  if (X >= CURVE_P || Y >= CURVE_P) return false;
  const lhs = (Y * Y) % CURVE_P;
  const x3 = (((X * X) % CURVE_P) * X) % CURVE_P;
  const rhs = (x3 + ((CURVE_A * X) % CURVE_P) + CURVE_B) % CURVE_P;
  return lhs === rhs;
}

/**
 * 预热 WASM 模块。
 *
 * Preload the WASM module.
 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('sm2');
  (globalThis as { __sm2Wasm?: Sm2Module }).__sm2Wasm = {
    exports: mod.exports as unknown as Sm2Exports,
    memory: mod.memory,
  };
}

/**
 * 取已预热的模块句柄；未预热时抛错，避免在空句柄上继续执行。
 *
 * Fetch the preloaded module handle; throws when nothing was preloaded so the caller
 * never proceeds on an empty handle.
 */
function getModule(): Sm2Module {
  const mod = (globalThis as { __sm2Wasm?: Sm2Module }).__sm2Wasm;
  if (!mod) throw new Error('sm2: 未初始化，请先 `await ensureLoaded()`。');
  return mod;
}

/**
 * 现取 WASM memory 视图。
 *
 * **每次都用**，绝不在多次 `alloc` / wasm 调用之间缓存 `new Uint8Array(memory.buffer)`：
 * 任何一次分配都可能让 WASM 堆增长（`memory.grow`），旧的 ArrayBuffer 会被 detach，
 * 复用旧视图会抛 `TypeError: Cannot perform Construct on a detached ArrayBuffer`。
 *
 * Take a fresh view of WASM memory.
 *
 * **Always take a fresh view**; never cache `new Uint8Array(memory.buffer)` across
 * `alloc` calls or wasm calls: any allocation may grow the WASM heap (`memory.grow`),
 * which detaches the old ArrayBuffer, and reusing the stale view throws
 * `TypeError: Cannot perform Construct on a detached ArrayBuffer`.
 */
function memView(): Uint8Array {
  return new Uint8Array(getModule().memory.buffer);
}

/**
 * 写入字节到 WASM 内存（现取视图）。
 *
 * Write bytes into WASM memory (fresh view).
 */
function putBytes(b: Uint8Array, ptr: number): void {
  memView().set(b, ptr);
}

/**
 * 读出 WASM 内存的拷贝（现取视图后 slice，不向上层交出会失效的视图）。
 *
 * Copy bytes out of WASM memory (fresh view, then slice, so no caller ever holds a view
 * that can go stale).
 */
function readBytes(ptr: number, len: number): Uint8Array {
  return new Uint8Array(getModule().memory.buffer, ptr, len).slice();
}

/**
 * 从私钥派生公钥。
 *
 * @param privateKey 32 字节私钥（hex / Uint8Array）。
 * @returns 公钥 hex（128 字符，x || y）。
 *
 * Derive the public key from a private key.
 *
 * @param privateKey The 32-byte private key (hex / Uint8Array).
 * @returns The public key as hex (128 characters, x || y).
 */
export function getPublicKey(privateKey: string | Uint8Array): string {
  return fromBytes(derivePublicKeyRaw(toPrivateKeyBytes(privateKey)), 'hex');
}

/**
 * 真算一次固定基点标量乘，返回公钥 64 字节 `x || y`。**不做任何缓存**。
 *
 * `getPublicKey` 与缓存未命中时的 `derivePublicKeyBytes` 都走这里。
 *
 * Run one real fixed-base scalar multiplication and return the 64-byte public key
 * `x || y`. **Nothing is cached.**
 *
 * Both `getPublicKey` and `derivePublicKeyBytes` (on a cache miss) go through here.
 */
function derivePublicKeyRaw(d: Uint8Array): Uint8Array {
  const { exports } = getModule();
  const dp = exports.alloc(32);
  const op = exports.alloc(64);
  try {
    putBytes(d, dp);
    exports.publicKeyOut(dp, op);
    return readBytes(op, 64);
  } finally {
    exports.freeAll();
  }
}

/**
 * 私钥（hex）→ 公钥（64 字节 x||y）的进程内缓存。
 *
 * `sign` 需要公钥来算 Z 值，而公钥只依赖私钥 —— 原先每次签名都重新派生一次，
 * 即每次重做一遍固定基点标量乘（实测约 105µs，占一次签名 ~250µs 的 41%）。
 *
 * 取舍：
 * - 键是私钥的 hex，等于让"私钥的派生结果"（以及私钥本身的 hex 形态）在进程内存
 *   里驻留 —— 不接受这一点的调用方用 `configurePublicKeyCache({ enabled: false })`
 *   关掉，即回到"每次都重算"的无状态行为；
 * - 条目有固定上限（默认 32），满时按插入顺序淘汰最旧一条（FIFO，不做 LRU ——
 *   不需要命中统计，且密钥集合通常很小）；
 * - **只服务内部派生路径**：公开的 `getPublicKey` 仍然每次真算，保持
 *   "派生公钥"这个操作的语义，以及 `bench` 里这一项的可测性。
 *
 * In-process cache mapping a private key (hex) to its public key (64-byte x||y).
 *
 * `sign` needs the public key to compute the Z value, and the public key depends only on
 * the private key — the first version re-derived it on every signature, i.e. redid one
 * fixed-base scalar multiplication each time (measured ≈105µs, 41% of a ≈250µs
 * signature).
 *
 * Trade-offs:
 * - the key is the private key's hex, so the derived result (and the private key's hex
 *   form) stays resident in process memory — callers who cannot accept that switch it
 *   off with `configurePublicKeyCache({ enabled: false })` and get back the stateless
 *   "recompute every time" behaviour;
 * - entries have a fixed cap (32 by default); when full, the oldest entry is evicted in
 *   insertion order (FIFO, not LRU — no hit statistics are needed and key sets are
 *   usually small);
 * - it **only serves internal derivation**: the public `getPublicKey` still computes
 *   every time, preserving the semantics of "derive a public key" and keeping that
 *   `bench` entry measurable.
 */
const PUB_CACHE = new Map<string, Uint8Array>();

/**
 * 最后一次 `preparePublicKey` 的公钥（hex，x || y），没有则为 `null`。
 *
 * 只用于单数查询接口；多槽的真实状态在 wasm 侧（指纹 + LRU），正确性不依赖它。
 *
 * The public key (hex, x || y) of the last `preparePublicKey`, or `null`.
 *
 * Used only by the singular query API; the real multi-slot state (fingerprints + LRU)
 * lives on the wasm side and correctness never depends on this value.
 */
let PREPARED_PUB: string | null = null;

/**
 * 多槽公钥缓存的槽位上限（1..8，默认 8）。wasm 未加载时先记在这里。
 *
 * Upper bound on the multi-slot public-key cache (1..8, 8 by default). Recorded here
 * while wasm is not yet loaded.
 */
let preparedCapacity = 8;

// 公钥派生缓存的运行时开关与容量：`configurePublicKeyCache` 修改，`derivePublicKeyBytes` 读取。
//
// Runtime switch and capacity of the public-key derivation cache: mutated by
// `configurePublicKeyCache`, read by `derivePublicKeyBytes`.
let cacheEnabled = true;
let cacheCapacity = 32;

/**
 * `configurePublicKeyCache` 的选项。
 *
 * Options for `configurePublicKeyCache`.
 */
export interface PublicKeyCacheOptions {
  /**
   * 是否缓存私钥→公钥的派生结果（默认 true）。关掉后 `sign` 每次重算公钥。
   *
   * Whether to cache private-key → public-key derivations (default true). Once off,
   * `sign` recomputes the public key every time.
   */
  enabled?: boolean;
  /**
   * 缓存条目上限，超出后 FIFO 淘汰最旧一条（默认 32）。
   *
   * Cache entry cap; when exceeded the oldest entry is evicted FIFO (default 32).
   */
  capacity?: number;
}

/**
 * 调整 SM2 公钥派生缓存策略。
 *
 * 默认 `{ enabled: true, capacity: 32 }`。缓存省下的是 `sign` 里重复的固定基点
 * 标量乘（实测 41%）；关掉它只应在"不允许私钥派生结果驻留进程内存"的安全模型下做。
 *
 * Adjust the SM2 public-key derivation cache policy.
 *
 * The default is `{ enabled: true, capacity: 32 }`. What the cache saves is the repeated
 * fixed-base scalar multiplication inside `sign` (measured 41%); switching it off should
 * only happen under a security model that forbids private-key derivation results from
 * residing in process memory.
 */
export function configurePublicKeyCache(opts: PublicKeyCacheOptions): void {
  if (opts.capacity !== undefined) {
    if (!Number.isInteger(opts.capacity) || opts.capacity < 1) {
      throw new RangeError(`sm2: capacity 必须是正整数，收到 ${opts.capacity}`);
    }
    cacheCapacity = opts.capacity;
  }
  if (opts.enabled !== undefined) cacheEnabled = opts.enabled;
  evictPubCache();
}

/**
 * 清空公钥缓存（不改变开关与容量）。
 *
 * Clear the public-key cache (leaves the switch and capacity unchanged).
 */
export function clearPublicKeyCache(): void {
  PUB_CACHE.clear();
}

/**
 * FIFO 淘汰多余条目，保证缓存有界。
 *
 * Evict surplus entries FIFO so the cache stays bounded.
 */
function evictPubCache(): void {
  while (PUB_CACHE.size > cacheCapacity) {
    const oldest = PUB_CACHE.keys().next();
    if (oldest.done) break;
    PUB_CACHE.delete(oldest.value);
  }
}

/**
 * 私钥 → 公钥（64 字节 x||y）；启用缓存时（默认）命中即不做标量乘。
 *
 * Private key → public key (64-byte x||y); with the cache enabled (the default) a hit
 * skips the scalar multiplication.
 */
function derivePublicKeyBytes(d: Uint8Array): Uint8Array {
  if (!cacheEnabled) return derivePublicKeyRaw(d);
  const key = bytesToHex(d);
  const hit = PUB_CACHE.get(key);
  if (hit !== undefined) return hit;
  const pub = derivePublicKeyRaw(d);
  PUB_CACHE.set(key, pub);
  evictPubCache();
  return pub;
}

/**
 * SM2 密钥对（PEM 形态：PKCS#8 私钥 + SPKI 公钥）。
 *
 * An SM2 key pair in PEM form: a PKCS#8 private key plus an SPKI public key.
 */
export interface Sm2KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

/**
 * SM2 密文分量顺序。
 *
 * The order of the SM2 ciphertext components.
 */
export type Sm2CipherFormat = 'C1C3C2' | 'C1C2C3';

/**
 * `encrypt` 选项。
 *
 * Options for `encrypt`.
 */
export interface Sm2EncryptOptions {
  /**
   * 输出顺序，默认 `C1C3C2`（spec §12.1 Q1）。
   *
   * Output order, `C1C3C2` by default (spec §12.1 Q1).
   */
  outputFormat?: Sm2CipherFormat;
}

/**
 * `decrypt` 选项。
 *
 * Options for `decrypt`.
 */
export interface Sm2DecryptOptions {
  /**
   * 输入顺序，默认 `auto`（先按 C1C3C2 解，失败再按 C1C2C3 重排重试）。
   *
   * Input order, `auto` by default (try C1C3C2 first, then reorder to C1C2C3 and retry
   * on failure).
   */
  inputFormat?: Sm2CipherFormat | 'auto';
  /**
   * 解密失败时返回 `null` 而不抛错（plan Review Focus #4）。
   *
   * 覆盖密文支错误（`CiphertextError`：密文结构错 + C3 校验失败）；
   * 参数类型错误（`TypeError` / `RangeError`）仍会抛出。
   *
   * Return `null` instead of throwing when decryption fails (plan Review Focus #4).
   *
   * Covers ciphertext-branch errors (`CiphertextError`: bad ciphertext structure plus C3
   * check failure); argument type errors (`TypeError` / `RangeError`) still throw.
   */
  safeMode?: boolean;
}

/**
 * 生成 SM2 密钥对（异步：含 wasm 实例化 + 宿主 CSPRNG 取 d）。
 *
 * @returns PKCS#8 私钥 PEM 与 SPKI 公钥 PEM。
 *
 * Generate an SM2 key pair (async: instantiates wasm and draws d from the host CSPRNG).
 *
 * @returns A PKCS#8 private-key PEM and an SPKI public-key PEM.
 */
export async function generateKeyPair(): Promise<Sm2KeyPair> {
  await ensureLoaded();
  const d = randomScalarBelow(N).toString(16).padStart(64, '0');
  const pub = getPublicKey(d);
  return {
    privateKeyPem: encodeSm2PrivateKeyPem(d, pub),
    publicKeyPem: encodeSm2PublicKeyPem(pub),
  };
}

/**
 * C1C3C2 → C1C2C3（返回新数组，不改动入参）。
 *
 * C1C3C2 → C1C2C3 (returns a new array, does not modify the input).
 */
function c1c3c2ToC1c2c3(ct: Uint8Array): Uint8Array {
  const n = ct.length - 97;
  const out = new Uint8Array(ct.length);
  out.set(ct.subarray(0, 65), 0);
  out.set(ct.subarray(97, 97 + n), 65);
  out.set(ct.subarray(65, 97), 65 + n);
  return out;
}

/**
 * C1C2C3 → C1C3C2（返回新数组，不改动入参）。
 *
 * C1C2C3 → C1C3C2 (returns a new array, does not modify the input).
 */
function c1c2c3ToC1c3c2(ct: Uint8Array): Uint8Array {
  const n = ct.length - 97;
  const out = new Uint8Array(ct.length);
  out.set(ct.subarray(0, 65), 0);
  out.set(ct.subarray(65 + n, 65 + n + 32), 65);
  out.set(ct.subarray(65, 65 + n), 97);
  return out;
}

/**
 * 把公钥拆成 32 字节的 x 与 y 两个子视图（不复制）。
 *
 * Split a public key into 32-byte x and y sub-views (no copy).
 */
function splitPub(pub: string | Uint8Array): { x: Uint8Array; y: Uint8Array } {
  const b = toPublicKeyBytes(pub);
  return { x: b.subarray(0, 32), y: b.subarray(32, 64) };
}

/**
 * 取一个 [1, n-1] 的随机标量，写成 32 字节大端数组（签名 / 加密用的 k）。
 *
 * Draw a random scalar in [1, n-1] and write it as a 32-byte big-endian array (the k used
 * for signing / encryption).
 */
function randomK(): Uint8Array {
  const k = randomScalarBelow(N);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[31 - i] = Number((k >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

/**
 * 池中的一个预计算签名点。
 *
 * `point`（`k·G` 的坐标）是公开信息；**`k` 被封在模块内部**，外部读不到，被
 * `sign()` 取走后立刻从索引中摘除并抹掉字节 —— 所以"复用同一个 `k`"在 API 层面
 * 就不可能发生，调用方不需要（也无法）自己去保证这一点。
 *
 * One precomputed signature point in the pool.
 *
 * `point` (the coordinates of `k·G`) is public information; **`k` is sealed inside the
 * module** and unreachable from outside. As soon as `sign()` takes it, the point is
 * removed from the index and its bytes are wiped — so “reusing the same `k`” is
 * impossible at the API level, and callers neither need to nor can guarantee it
 * themselves.
 */
export class SignaturePoint {
  /**
   * `k·G` 的仿射坐标 `x ‖ y`（64 字节 hex）。公开信息，可用于审计。
   *
   * The affine coordinates `x ‖ y` of `k·G` (64-byte hex). Public information, usable
   * for auditing.
   */
  readonly point: string;

  /**
   * 只允许本模块的 `createSignaturePointPool` 构造。
   *
   * Only `createSignaturePointPool` in this module may construct one.
   */
  private constructor(point: string) {
    this.point = point;
  }

  /**
   * @internal 仅供 `createSignaturePointPool` 使用。
   *
   * @internal Only for `createSignaturePointPool`.
   */
  static _create(nonce: Uint8Array, point: string): SignaturePoint {
    const p = new SignaturePoint(point);
    POINT_NONCE.set(p, nonce);
    return p;
  }
}

/**
 * 点位 → 一次性 `k`。取走即 `delete`：同一个点位对象无论被谁持有引用，都只能
 * 取到一次 `k`。用 `WeakMap` 而非对象属性，是为了连"枚举键名"都做不到。
 *
 * Point → one-time `k`. Taking it `delete`s the entry: however many references a point
 * object has, `k` can be obtained only once. A `WeakMap` rather than an object property
 * means not even key names can be enumerated.
 */
const POINT_NONCE = new WeakMap<SignaturePoint, Uint8Array>();

/**
 * 取走签名点的一次性 `k`。
 *
 * 索引里没有（已被取过，或不是本库产出的伪造对象）就抛错 —— 于是"同一个点签两次"
 * 会当场失败，而不是悄悄复用 `k` 把私钥送出去。
 *
 * Take the one-time `k` of a signature point.
 *
 * When the index has no entry (already taken, or a forged object not produced by this
 * library) it throws — so “sign twice with the same point” fails immediately instead of
 * silently reusing `k` and giving the private key away.
 */
function takeNonce(p: SignaturePoint): Uint8Array {
  const nonce = POINT_NONCE.get(p);
  if (nonce === undefined) {
    throw new Error(
      'sm2: 该签名点不可用（已被使用过，或不是 createSignaturePointPool 产出的）；签名点是一次性的。',
    );
  }
  POINT_NONCE.delete(p);
  return nonce;
}

/**
 * `sign` 的选项。
 *
 * Options for `sign`.
 */
export interface SignOptions {
  /**
   * 预计算的签名点池（见 `createSignaturePointPool`）。
   *
   * 命中时省掉本次签名的固定基点标量乘（实测占单次签名的 56%）；池被取空后
   * 自动回退到现算。**该数组会被原地消费**（每签一次 `pop()` 一个点），
   * 调用方无需自己维护游标。
   *
   * Precomputed signature points (see `createSignaturePointPool`).
   *
   * A hit saves this signature's fixed-base scalar multiplication (measured 56% of one
   * signature); once the pool is empty the code falls back to computing it live. **The
   * array is consumed in place** (each signature `pop()`s one point), so the caller
   * needs no cursor of its own.
   */
  pointPool?: SignaturePoint[];
}

/**
 * 预计算 `n` 个签名点，供 `sign()` 的 `pointPool` 选项消费。
 *
 * 每个点 = 一次 `k·G`（本机约 130 µs）。批量签名时把这些固定基点标量乘提前
 * 摊销，签名的关键路径只剩 `e = SM3(Z ‖ M)` 与两条模运算 —— 实测快 5.9×。
 *
 * `k` 取自宿主 CSPRNG，并由本模块独占保管：调用方拿不到它，也就无从误用成复用。
 * 唯一的约定是"同一个点只喂一次"，而真喂两次会直接抛错。
 *
 * @param n 生成个数。
 * @returns `n` 个签名点。
 *
 * Precompute `n` signature points for the `pointPool` option of `sign()`.
 *
 * Each point costs one `k·G` (about 130 µs on this machine). For batch signing these
 * fixed-base scalar multiplications are amortised up front, leaving only
 * `e = SM3(Z ‖ M)` and two modular operations on the critical path — measured 5.9×
 * faster.
 *
 * `k` comes from the host CSPRNG and is held exclusively by this module: callers cannot
 * obtain it and therefore cannot misuse it by reusing it. The only convention is “feed
 * each point once”, and feeding one twice throws.
 *
 * @param n How many points to generate.
 * @returns `n` signature points.
 */
export async function createSignaturePointPool(n: number): Promise<SignaturePoint[]> {
  if (!Number.isInteger(n) || n < 0) {
    throw new RangeError(`sm2: 签名点池大小必须是非负整数，收到 ${String(n)}`);
  }
  await ensureLoaded();
  const { exports, memory } = getModule();
  const pool: SignaturePoint[] = [];
  for (let i = 0; i < n; i++) {
    const nonce = randomK();
    const kPtr = exports.alloc(32);
    const ptPtr = exports.alloc(64);
    try {
      new Uint8Array(memory.buffer, kPtr, 32).set(nonce);
      exports.scalarMulGOut(kPtr, ptPtr);
      pool.push(
        SignaturePoint._create(
          nonce,
          fromBytes(new Uint8Array(memory.buffer, ptPtr, 64).slice(), 'hex'),
        ),
      );
    } finally {
      exports.freeAll();
    }
  }
  return pool;
}

/**
 * SM2 签名（默认 SM3withSM2、默认用户标识）。
 *
 * @param privateKey 32 字节私钥。
 * @param message 待签名消息。
 * @param opts `pointPool`：预计算的签名点池（见 `createSignaturePointPool`）。
 * @returns 64 字节签名（r || s）的 hex。
 *
 * SM2 signature (SM3withSM2 with the default user identity).
 *
 * @param privateKey The 32-byte private key.
 * @param message The message to sign.
 * @param opts `pointPool`: precomputed signature points (see `createSignaturePointPool`).
 * @returns The 64-byte signature (r || s) as hex.
 */
export function sign(
  privateKey: string | Uint8Array,
  message: string | Uint8Array,
  opts: SignOptions = {},
): string {
  const d = toPrivateKeyBytes(privateKey);
  const m = toBytes(message, 'message');
  const pub = derivePublicKeyBytes(d);
  const { exports, memory } = getModule();
  const dp = exports.alloc(32);
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const mp = exports.alloc(m.length);
  const kp = exports.alloc(32);
  const xp = exports.alloc(32);
  const op = exports.alloc(64);
  const pool = opts.pointPool;
  try {
    putBytes(d, dp);
    putBytes(pub.subarray(0, 32), pxp);
    putBytes(pub.subarray(32, 64), pyp);
    putBytes(m, mp);
    // 最多重试几次 k（极小概率 r/s 为 0 或 r+k==n）。池命中时每轮换一个点。
    //
    // Retry a few times on k (a tiny chance that r/s is 0 or r+k==n). On a pool hit each
    // round takes another point.
    for (let attempt = 0; attempt < 16; attempt++) {
      const pooled = pool?.pop();
      let rc: number;
      if (pooled !== undefined) {
        // 一次性取走 k；此处之后该点不可再用（再喂会抛错）。
        //
        // Take k once; after this the point is unusable (feeding it again throws).
        const nonce = takeNonce(pooled);
        putBytes(nonce, kp);
        nonce.fill(0); // JS 侧那份随即抹掉
        //
        // wipe the JS-side copy right away
        new Uint8Array(memory.buffer, xp, 32).set(toBytes(pooled.point, 'point').subarray(0, 32));
        rc = exports.signWithPointOut(dp, pxp, pyp, mp, m.length, kp, xp, op);
      } else {
        putBytes(randomK(), kp);
        rc = exports.signOut(dp, pxp, pyp, mp, m.length, kp, op);
      }
      if (rc === 0) {
        return fromBytes(readBytes(op, 64), 'hex');
      }
    }
    throw new Error('sm2.sign: failed to produce a valid signature after retries');
  } finally {
    // 抹掉 WASM 内存里那份 k（缓冲区在 freeAll 前仍可写）
    //
    // Wipe the k inside WASM memory (the buffer is still writable before freeAll)
    new Uint8Array(memory.buffer, kp, 32).fill(0);
    exports.freeAll();
  }
}

/**
 * SM2 签名（自定义用户标识）。
 *
 * 与 `sign` 的区别仅在于 Z 值使用 `userID` 计算。X.509 签发需要它：
 * OpenSSL 的 X.509 路径默认使用空标识，GM/T 证书使用 `1234567812345678`。
 *
 * 不支持 `pointPool`（签发场景不需要；需要时用 `sign` 的默认标识路径）。
 *
 * @param privateKey 32 字节私钥（hex / Uint8Array / PEM）。
 * @param message 待签名消息。
 * @param userID 用户标识（可为空数组）。
 * @returns 64 字节签名 `r ‖ s` 的 hex。
 *
 * SM2 signature with a custom user identity.
 *
 * The only difference from `sign` is that the Z value is computed with `userID`. X.509
 * issuance needs it: OpenSSL's X.509 path uses an empty identity by default, while GM/T
 * certificates use `1234567812345678`.
 *
 * `pointPool` is not supported (issuance does not need it; use `sign`'s
 * default-identity path when it is needed).
 *
 * @param privateKey The 32-byte private key (hex / Uint8Array / PEM).
 * @param message The message to sign.
 * @param userID The user identity (may be an empty array).
 * @returns The 64-byte signature `r ‖ s` as hex.
 */
export function signWithID(
  privateKey: string | Uint8Array,
  message: string | Uint8Array,
  userID: Uint8Array,
): string {
  const d = toPrivateKeyBytes(privateKey);
  const m = toBytes(message, 'message');
  const id = userID instanceof Uint8Array ? userID : new Uint8Array(0);
  const pub = derivePublicKeyBytes(d);
  const { exports, memory } = getModule();
  const dp = exports.alloc(32);
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const idp = exports.alloc(id.length === 0 ? 1 : id.length);
  const mp = exports.alloc(m.length === 0 ? 1 : m.length);
  const kp = exports.alloc(32);
  const op = exports.alloc(64);
  try {
    putBytes(d, dp);
    putBytes(pub.subarray(0, 32), pxp);
    putBytes(pub.subarray(32, 64), pyp);
    if (id.length > 0) putBytes(id, idp);
    putBytes(m, mp);
    for (let attempt = 0; attempt < 16; attempt++) {
      putBytes(randomK(), kp);
      const rc = exports.signWithIDOut(dp, pxp, pyp, idp, id.length, mp, m.length, kp, op);
      if (rc === 0) return fromBytes(readBytes(op, 64), 'hex');
    }
    throw new Error('sm2.signWithID: failed to produce a valid signature after retries');
  } finally {
    new Uint8Array(memory.buffer, kp, 32).fill(0);
    exports.freeAll();
  }
}

/**
 * SM2 验签。
 *
 * @returns true 有效。
 *
 * SM2 signature verification.
 *
 * @returns true when valid.
 */
export function verify(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  signature: string | Uint8Array,
): boolean {
  const { x, y } = splitPub(publicKey);
  // 公钥不合法时按"验签不通过"处理，不抛错（plan Review Focus #3）。
  //
  // Treat an invalid public key as “verification failed” instead of throwing
  // (plan Review Focus #3).
  if (!isOnCurve(x, y)) return false;
  const m = toBytes(message, 'message');
  const sig = toBytes(signature, 'signature');
  if (sig.length !== 64) throw new InvalidCiphertextError('sm2: signature must be 64 bytes');
  const { exports } = getModule();
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const mp = exports.alloc(m.length);
  const sigp = exports.alloc(64);
  try {
    putBytes(x, pxp);
    putBytes(y, pyp);
    putBytes(m, mp);
    putBytes(sig, sigp);
    return exports.verifyOut(pxp, pyp, mp, m.length, sigp) === 1;
  } finally {
    exports.freeAll();
  }
}

/**
 * SM2 验签（自定义用户标识）。
 *
 * 与 `verify` 的区别仅在于 Z 值使用 `userID` 计算。X.509 证书签名需要它：
 * GM/T 证书使用默认标识 `1234567812345678`，而 OpenSSL 的 X.509 路径
 * 默认使用空标识。
 *
 * @param publicKey 64/65 字节公钥。
 * @param message 消息。
 * @param signature 64 字节 `r ‖ s`。
 * @param userID 用户标识（可为空数组）。
 * @returns true 有效。
 *
 * SM2 signature verification with a custom user identity.
 *
 * The only difference from `verify` is that the Z value is computed with `userID`. X.509
 * certificate signatures need it: GM/T certificates use the default identity
 * `1234567812345678`, while OpenSSL's X.509 path uses an empty identity by default.
 *
 * @param publicKey A 64/65-byte public key.
 * @param message The message.
 * @param signature The 64-byte `r ‖ s`.
 * @param userID The user identity (may be an empty array).
 * @returns true when valid.
 */
export function verifyWithID(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  signature: string | Uint8Array,
  userID: Uint8Array,
): boolean {
  const { x, y } = splitPub(publicKey);
  if (!isOnCurve(x, y)) return false;
  const m = toBytes(message, 'message');
  const sig = toBytes(signature, 'signature');
  if (sig.length !== 64) throw new InvalidCiphertextError('sm2: signature must be 64 bytes');
  const id = userID instanceof Uint8Array ? userID : new Uint8Array(0);
  const { exports } = getModule();
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const idp = exports.alloc(id.length === 0 ? 1 : id.length);
  const mp = exports.alloc(m.length === 0 ? 1 : m.length);
  const sigp = exports.alloc(64);
  const zp = exports.alloc(32);
  try {
    putBytes(x, pxp);
    putBytes(y, pyp);
    if (id.length > 0) putBytes(id, idp);
    putBytes(m, mp);
    putBytes(sig, sigp);
    exports.computeZIdOut(pxp, pyp, idp, id.length, zp);
    return exports.verifyWithZOut(pxp, pyp, zp, mp, m.length, sigp) === 1;
  } finally {
    exports.freeAll();
  }
}

/**
 * 多槽公钥缓存的配置。
 *
 * Configuration for the multi-slot public-key cache.
 */
export interface PreparedKeyCacheOptions {
  /**
   * 槽位上限，1..8，默认 8。
   *
   * Slot cap, 1..8, 8 by default.
   */
  capacity?: number;
}

/**
 * 配置多槽公钥缓存（默认 8 槽，满了按 LRU 淘汰）。
 *
 * 缩小容量不会立即清除高槽位，只是之后的查找与 `getPreparedPublicKeys` 不再考虑它们；
 * 需要释放时调用 `clearPreparedPublicKeys()`。wasm 未加载时只记录，首次
 * `preparePublicKey` 会应用。
 *
 * Configure the multi-slot public-key cache (8 slots by default, LRU-evicted when full).
 *
 * Shrinking the capacity does not clear higher slots immediately; later lookups and
 * `getPreparedPublicKeys` simply stop considering them. Call
 * `clearPreparedPublicKeys()` to release them. While wasm is not loaded the value is
 * only recorded and applied by the first `preparePublicKey`.
 */
export function configurePreparedKeyCache(opts: PreparedKeyCacheOptions = {}): void {
  const capacity = opts.capacity ?? 8;
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > 8) {
    throw new RangeError(
      `sm2.configurePreparedKeyCache: capacity 必须是 1..8 的整数，收到 ${String(capacity)}`,
    );
  }
  preparedCapacity = capacity;
  const mod = (globalThis as { __sm2Wasm?: Sm2Module }).__sm2Wasm;
  if (mod) mod.exports.setCombCapacityOut(capacity);
}

/**
 * 为一对**固定公钥**预计算 comb 表（默认 8 槽，满了 LRU 淘汰）。
 *
 * 之后 `encrypt` / `kemEncrypt` / `hybridEncrypt` 对该公钥会把 `k·P` 从 wNAF
 * （256 次倍点）切到 comb（52 次倍点）：本机端到端约 486 → 260 µs。建表一次性
 * 约 280 µs，**约 1.2 次加密回本**。
 *
 * **只有显式 prepare 才会建表**：`encrypt` 命中就走 comb，不命中直接回退 wNAF，
 * 绝不隐式建表 —— 否则外部可控的公钥能反复触发建表，形成放大面。
 *
 * 公钥是公开信息，缓存它不引入新的密钥材料驻留；8 槽共占 wasm 永久区固定 24 KiB。
 *
 * @param publicKey 64/65 字节公钥（hex / Uint8Array / PEM）。
 * @throws {InvalidPublicKeyError} 公钥不在 SM2 曲线上。
 *
 * Precompute a comb table for one **fixed public key** (8 slots by default, LRU-evicted
 * when full).
 *
 * Afterwards `encrypt` / `kemEncrypt` / `hybridEncrypt` switch `k·P` for that key from
 * wNAF (256 doublings) to comb (52 doublings): about 486 → 260 µs end to end here.
 * Building the table costs about 280 µs once, so **it pays back after about 1.2
 * encryptions**.
 *
 * **A table is only built by an explicit prepare**: on a hit `encrypt` uses comb, on a
 * miss it falls back to wNAF and never builds implicitly — otherwise an externally
 * controlled public key could repeatedly trigger table builds, creating an amplification
 * surface.
 *
 * A public key is public information, so caching it introduces no new key-material
 * residency; the 8 slots occupy a fixed 24 KiB of wasm permanent memory.
 *
 * @param publicKey A 64/65-byte public key (hex / Uint8Array / PEM).
 * @throws {InvalidPublicKeyError} When the public key is not a point on the SM2 curve.
 */
export async function preparePublicKey(publicKey: string | Uint8Array): Promise<void> {
  await ensureLoaded();
  const { x, y } = splitPub(publicKey);
  if (!isOnCurve(x, y)) {
    throw new InvalidPublicKeyError(
      'sm2.preparePublicKey: public key is not a point on the SM2 curve',
    );
  }
  const hexPub = bytesToHex(x) + bytesToHex(y);

  const { exports } = getModule();
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  try {
    putBytes(x, pxp);
    putBytes(y, pyp);
    exports.setCombCapacityOut(preparedCapacity);
    exports.prepareCombOut(pxp, pyp, preparedCapacity);
    PREPARED_PUB = hexPub;
  } finally {
    exports.freeAll();
  }
}

/**
 * 清空所有公钥预计算槽，之后的 `encrypt` 全部回退到 wNAF。未加载 wasm 时也安全。
 *
 * Clear every public-key precomputation slot; all later `encrypt` calls fall back to
 * wNAF. Safe while wasm is not loaded.
 */
export function clearPreparedPublicKeys(): void {
  PREPARED_PUB = null;
  const mod = (globalThis as { __sm2Wasm?: Sm2Module }).__sm2Wasm;
  if (mod) mod.exports.clearComb();
}

/**
 * @deprecated 用 `clearPreparedPublicKeys()`（保留单数别名）。
 *
 * @deprecated Use `clearPreparedPublicKeys()` (singular alias kept for compatibility).
 */
export function clearPreparedPublicKey(): void {
  clearPreparedPublicKeys();
}

/**
 * 当前槽位中的公钥（hex，按槽序）。
 *
 * wasm 未加载时返回空数组。
 *
 * The public keys currently in the slots (hex, in slot order).
 *
 * Returns an empty array while wasm is not loaded.
 */
export function getPreparedPublicKeys(): string[] {
  const mod = (globalThis as { __sm2Wasm?: Sm2Module }).__sm2Wasm;
  if (!mod) return [];
  const out = mod.exports.alloc(64);
  const keys: string[] = [];
  try {
    for (let s = 0; s < preparedCapacity; s++) {
      if (mod.exports.combSlotKeyOut(s, out) === 1) {
        keys.push(bytesToHex(new Uint8Array(mod.memory.buffer, out, 64).slice()));
      }
    }
  } finally {
    mod.exports.freeAll();
  }
  return keys;
}

/**
 * 最后一次 `preparePublicKey` 的公钥（hex）；没有则为 `null`。
 *
 * The public key of the last `preparePublicKey` (hex); `null` when there is none.
 */
export function getPreparedPublicKey(): string | null {
  return PREPARED_PUB;
}

/**
 * SM2 加密。
 *
 * @param publicKey 64 或 65 字节公钥（hex / Uint8Array / PEM）。
 * @param message 明文。
 * @param opts `outputFormat`：`'C1C3C2'`（默认）或 `'C1C2C3'`。
 * @returns 密文 hex，默认按 C1(65) || C3(32) || C2 组装。
 *
 * SM2 encryption.
 *
 * @param publicKey A 64- or 65-byte public key (hex / Uint8Array / PEM).
 * @param message The plaintext.
 * @param opts `outputFormat`: `'C1C3C2'` (default) or `'C1C2C3'`.
 * @returns Ciphertext hex, assembled as C1(65) || C3(32) || C2 by default.
 */
export function encrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts: Sm2EncryptOptions = {},
): string {
  const format = opts.outputFormat ?? 'C1C3C2';
  if (format !== 'C1C3C2' && format !== 'C1C2C3') {
    throw new RangeError(`sm2.encrypt: 未知的 outputFormat ${String(format)}`);
  }
  const { x, y } = splitPub(publicKey);
  if (!isOnCurve(x, y)) {
    throw new InvalidPublicKeyError('sm2.encrypt: public key is not a point on the SM2 curve');
  }
  const m = toBytes(message, 'message');
  const { exports } = getModule();
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const mp = exports.alloc(m.length);
  const kp = exports.alloc(32);
  const ctp = exports.alloc(97 + m.length);
  try {
    putBytes(x, pxp);
    putBytes(y, pyp);
    putBytes(m, mp);
    for (let attempt = 0; attempt < 16; attempt++) {
      putBytes(randomK(), kp);
      const rc = exports.encryptOut(pxp, pyp, mp, m.length, kp, ctp);
      if (rc === 1) {
        const raw = readBytes(ctp, 97 + m.length);
        return fromBytes(format === 'C1C2C3' ? c1c3c2ToC1c2c3(raw) : raw, 'hex');
      }
    }
    throw new Error('sm2.encrypt: KDF produced all-zero output after retries');
  } finally {
    exports.freeAll();
  }
}

/**
 * SM2 解密。
 *
 * 默认自动识别密文顺序：先按 C1C3C2 解，C3 校验失败且密文含 C2 时，
 * 再按 C1C2C3 重排重试（spec §12.1 Q1「解密端按输入自动识别」）。
 *
 * @param privateKey 32 字节私钥（hex / Uint8Array / PEM）。
 * @param ciphertext 密文。
 * @param opts `inputFormat`，默认 `'auto'`。
 * @returns 明文的 hex。
 *
 * SM2 decryption.
 *
 * The ciphertext order is detected automatically by default: try C1C3C2 first, and when
 * the C3 check fails and the ciphertext carries a C2, reorder to C1C2C3 and retry (spec
 * §12.1 Q1 “the decrypting side detects the input order”).
 *
 * @param privateKey The 32-byte private key (hex / Uint8Array / PEM).
 * @param ciphertext The ciphertext.
 * @param opts `inputFormat`, `'auto'` by default.
 * @returns The plaintext in hex.
 */
export function decrypt(
  privateKey: string | Uint8Array,
  ciphertext: string | Uint8Array,
  opts: Sm2DecryptOptions & { safeMode: true },
): string | null;
export function decrypt(
  privateKey: string | Uint8Array,
  ciphertext: string | Uint8Array,
  opts?: Sm2DecryptOptions,
): string;
export function decrypt(
  privateKey: string | Uint8Array,
  ciphertext: string | Uint8Array,
  opts: Sm2DecryptOptions = {},
): string | null {
  try {
    return decryptUnsafe(privateKey, ciphertext, opts);
  } catch (err) {
    // safeMode 只吞"密文支"失败（结构错 + 校验失败）；参数类型错等仍然抛。
    //
    // safeMode only swallows “ciphertext branch” failures (bad structure + failed check);
    // argument type errors and the like still throw.
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

/**
 * `decrypt` 的实作：失败时按错误类型抛出。
 *
 * The implementation behind `decrypt`: throws by error type on failure.
 */
function decryptUnsafe(
  privateKey: string | Uint8Array,
  ciphertext: string | Uint8Array,
  opts: Sm2DecryptOptions,
): string {
  const d = toPrivateKeyBytes(privateKey);
  const ct = toBytes(ciphertext, 'ciphertext');
  if (ct.length < 97) throw new InvalidCiphertextError('sm2: ciphertext too short');

  const format = opts.inputFormat ?? 'auto';
  if (format === 'C1C3C2') return decryptRaw(d, ct);
  if (format === 'C1C2C3') return decryptRaw(d, c1c2c3ToC1c3c2(ct));
  if (format !== 'auto') {
    throw new RangeError(`sm2.decrypt: 未知的 inputFormat ${String(format)}`);
  }
  try {
    return decryptRaw(d, ct);
  } catch (err) {
    // 空 C2 时两种顺序字节相同，重试没有意义。
    //
    // With an empty C2 both orders are byte-identical, so retrying is pointless.
    if (ct.length > 97) {
      try {
        return decryptRaw(d, c1c2c3ToC1c3c2(ct));
      } catch {
        // 两种顺序都不成立：抛原始错误，保留 C1C3C2 路径的诊断信息。
        //
        // Neither order works: throw the original error to keep the C1C3C2 diagnostic.
      }
    }
    throw err;
  }
}

/**
 * 按 C1C3C2 布局解密（wasm 侧约定的布局）。
 *
 * Decrypt assuming the C1C3C2 layout (the layout the wasm side expects).
 */
function decryptRaw(d: Uint8Array, ct: Uint8Array): string {
  const { exports } = getModule();
  const dp = exports.alloc(32);
  const ctp = exports.alloc(ct.length);
  const outLen = ct.length - 97;
  const ptp = exports.alloc(outLen === 0 ? 1 : outLen);
  try {
    putBytes(d, dp);
    putBytes(ct, ctp);
    const rc = exports.decryptOut(dp, ctp, ct.length, ptp);
    if (rc !== 1) throw new DecryptionError('sm2.decrypt: C3 verification failed');
    return fromBytes(readBytes(ptp, outLen), 'hex');
  } finally {
    exports.freeAll();
  }
}

// SM2 密钥交换协议（GM/T 0003.3-2014）：createExchangeInitiator /
// createExchangeResponder 由 `./exchange` 提供，在此并入 sm2 命名空间。
//
// SM2 key exchange (GM/T 0003.3-2014): createExchangeInitiator /
// createExchangeResponder come from `./exchange` and are merged into the sm2 namespace.
export * from './exchange.js';
// SM2 KEM（用公钥保护随机对称密钥）与混合加密（KEM + SM4-GCM）。
//
// SM2 KEM (protect a random symmetric key with a public key) and hybrid encryption
// (KEM + SM4-GCM).
export * from './hybrid.js';
export * from './kem.js';

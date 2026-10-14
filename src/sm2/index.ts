/**
 * SM2 业务 API（TS 胶水层，调 WASM）。
 *
 * 提供的通用能力：
 * - `getPublicKey(privateKey)`：从私钥派生公钥
 * - `sign(privateKey, message, options?)`：签名
 * - `verify(publicKey, message, signature)`：验签
 * - `encrypt(publicKey, message, options?)`：加密（默认 C1C3C2）
 * - `decrypt(privateKey, ciphertext)`：解密
 *
 * 说明：
 * - 密钥输入同时接受裸字节（hex）与 PEM（PKCS#8/SEC1 私钥、SPKI 公钥）。
 * - PEM 编解码（PKCS#8/SPKI）在 `src/pem/` 已有基础；高层 PEM API 见后续迭代。
 * - **随机数一律走宿主 CSPRNG**（`src/runtime/random.ts`）。
 *
 * spec/plan 对应：plan Task 6/8；spec §6 API、§12.1 Q1（默认 C1C3C2）。
 */

import { encodeSm2PrivateKeyPem, encodeSm2PublicKeyPem } from '../pem/sm2.js';
import { fromBytes, toBytes } from '../runtime/convert.js';
import {
  CiphertextError,
  DecryptionError,
  InvalidCiphertextError,
  InvalidPublicKeyError,
} from '../runtime/errors.js';
import { loadWasm } from '../runtime/loadWasm.js';
import { randomScalarBelow } from '../runtime/random.js';
import { toPrivateKeyBytes, toPublicKeyBytes } from './keyInput.js';

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
  readonly verifyOut: (
    pubXPtr: number,
    pubYPtr: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
  ) => number;
  readonly encryptOut: (
    pubXPtr: number,
    pubYPtr: number,
    msgPtr: number,
    msgLen: number,
    kPtr: number,
    outPtr: number,
  ) => number;
  readonly decryptOut: (privPtr: number, ctPtr: number, ctLen: number, outPtr: number) => number;
  readonly memory: WebAssembly.Memory;
}

interface Sm2Module {
  exports: Sm2Exports;
  memory: WebAssembly.Memory;
}

/** 曲线阶 n（SM2），用于随机数范围。 */
const N = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');

/** 素域特征 p。 */
const CURVE_P = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF');

/** 曲线系数 a = p - 3。 */
const CURVE_A = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC');

/** 曲线系数 b。 */
const CURVE_B = BigInt('0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93');

/** 大端字节 → bigint。 */
function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i] ?? 0);
  return v;
}

/**
 * 公钥点是否在 SM2 曲线上：`y² ≡ x³ + ax + b (mod p)`，且两坐标都落在 Fp 内。
 *
 * 使用前拒绝坏点可以挡掉"错误子群 / 无效曲线点"这类攻击面（plan Review Focus #3）。
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

/** 预热 WASM 模块。 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('sm2');
  (globalThis as { __sm2Wasm?: Sm2Module }).__sm2Wasm = {
    exports: mod.exports as unknown as Sm2Exports,
    memory: mod.memory,
  };
}

function getModule(): Sm2Module {
  const mod = (globalThis as { __sm2Wasm?: Sm2Module }).__sm2Wasm;
  if (!mod) throw new Error('sm2: 未初始化，请先 `await ensureLoaded()`。');
  return mod;
}

/** 把 32/64 字节数据写进 wasm 内存。 */
function _putHex(hex: string, ptr: number, len: number): void {
  const mem = new Uint8Array(getModule().memory.buffer);
  mem.set(Buffer.from(hex, 'hex'), ptr);
  void len;
}

/**
 * 从私钥派生公钥。
 *
 * @param privateKey 32 字节私钥（hex / Uint8Array）。
 * @returns 公钥 hex（128 字符，x || y）。
 */
export function getPublicKey(privateKey: string | Uint8Array): string {
  const d = toPrivateKeyBytes(privateKey);
  const { exports } = getModule();
  const dp = exports.alloc(32);
  const op = exports.alloc(64);
  try {
    new Uint8Array(getModule().memory.buffer).set(d, dp);
    exports.publicKeyOut(dp, op);
    return fromBytes(new Uint8Array(getModule().memory.buffer, op, 64).slice(), 'hex');
  } finally {
    exports.freeAll();
  }
}

/** SM2 密钥对（PEM 形态：PKCS#8 私钥 + SPKI 公钥）。 */
export interface Sm2KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

/** SM2 密文分量顺序。 */
export type Sm2CipherFormat = 'C1C3C2' | 'C1C2C3';

/** `encrypt` 选项。 */
export interface Sm2EncryptOptions {
  /** 输出顺序，默认 `C1C3C2`（spec §12.1 Q1）。 */
  outputFormat?: Sm2CipherFormat;
}

/** `decrypt` 选项。 */
export interface Sm2DecryptOptions {
  /** 输入顺序，默认 `auto`（先按 C1C3C2 解，失败再按 C1C2C3 重排重试）。 */
  inputFormat?: Sm2CipherFormat | 'auto';
  /**
   * 解密失败时返回 `null` 而不抛错（plan Review Focus #4）。
   *
   * 覆盖密文支错误（`CiphertextError`：密文结构错 + C3 校验失败）；
   * 参数类型错误（`TypeError` / `RangeError`）仍会抛出。
   */
  safeMode?: boolean;
}

/**
 * 生成 SM2 密钥对（异步：含 wasm 实例化 + 宿主 CSPRNG 取 d）。
 *
 * @returns PKCS#8 私钥 PEM 与 SPKI 公钥 PEM。
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

/** C1C3C2 → C1C2C3（返回新数组，不改动入参）。 */
function c1c3c2ToC1c2c3(ct: Uint8Array): Uint8Array {
  const n = ct.length - 97;
  const out = new Uint8Array(ct.length);
  out.set(ct.subarray(0, 65), 0);
  out.set(ct.subarray(97, 97 + n), 65);
  out.set(ct.subarray(65, 97), 65 + n);
  return out;
}

/** C1C2C3 → C1C3C2（返回新数组，不改动入参）。 */
function c1c2c3ToC1c3c2(ct: Uint8Array): Uint8Array {
  const n = ct.length - 97;
  const out = new Uint8Array(ct.length);
  out.set(ct.subarray(0, 65), 0);
  out.set(ct.subarray(65 + n, 65 + n + 32), 65);
  out.set(ct.subarray(65, 65 + n), 97);
  return out;
}

function splitPub(pub: string | Uint8Array): { x: Uint8Array; y: Uint8Array } {
  const b = toPublicKeyBytes(pub);
  return { x: b.subarray(0, 32), y: b.subarray(32, 64) };
}

function randomK(): Uint8Array {
  const k = randomScalarBelow(N);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[31 - i] = Number((k >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

/**
 * SM2 签名（默认 SM3withSM2、默认用户标识）。
 *
 * @param privateKey 32 字节私钥。
 * @param message 待签名消息。
 * @returns 64 字节签名（r || s）的 hex。
 */
export function sign(privateKey: string | Uint8Array, message: string | Uint8Array): string {
  const d = toPrivateKeyBytes(privateKey);
  const m = toBytes(message, 'message');
  const pub = toBytes(getPublicKey(d), 'pub');
  const { exports } = getModule();
  const mem = new Uint8Array(getModule().memory.buffer);
  const dp = exports.alloc(32);
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const mp = exports.alloc(m.length);
  const kp = exports.alloc(32);
  const op = exports.alloc(64);
  try {
    mem.set(d, dp);
    mem.set(pub.subarray(0, 32), pxp);
    mem.set(pub.subarray(32, 64), pyp);
    mem.set(m, mp);
    // 最多重试几次 k（极小概率 r/s 为 0 或 r+k==n）。
    for (let attempt = 0; attempt < 16; attempt++) {
      const k = randomK();
      mem.set(k, kp);
      const rc = exports.signOut(dp, pxp, pyp, mp, m.length, kp, op);
      if (rc === 0) {
        return fromBytes(new Uint8Array(mem.buffer, op, 64).slice(), 'hex');
      }
    }
    throw new Error('sm2.sign: failed to produce a valid signature after retries');
  } finally {
    exports.freeAll();
  }
}

/**
 * SM2 验签。
 *
 * @returns true 有效。
 */
export function verify(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  signature: string | Uint8Array,
): boolean {
  const { x, y } = splitPub(publicKey);
  // 公钥不合法时按"验签不通过"处理，不抛错（plan Review Focus #3）。
  if (!isOnCurve(x, y)) return false;
  const m = toBytes(message, 'message');
  const sig = toBytes(signature, 'signature');
  if (sig.length !== 64) throw new InvalidCiphertextError('sm2: signature must be 64 bytes');
  const { exports } = getModule();
  const mem = new Uint8Array(getModule().memory.buffer);
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const mp = exports.alloc(m.length);
  const sigp = exports.alloc(64);
  try {
    mem.set(x, pxp);
    mem.set(y, pyp);
    mem.set(m, mp);
    mem.set(sig, sigp);
    return exports.verifyOut(pxp, pyp, mp, m.length, sigp) === 1;
  } finally {
    exports.freeAll();
  }
}

/**
 * SM2 加密。
 *
 * @param publicKey 64 或 65 字节公钥（hex / Uint8Array / PEM）。
 * @param message 明文。
 * @param opts `outputFormat`：`'C1C3C2'`（默认）或 `'C1C2C3'`。
 * @returns 密文 hex，默认按 C1(65) || C3(32) || C2 组装。
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
  const mem = new Uint8Array(getModule().memory.buffer);
  const pxp = exports.alloc(32);
  const pyp = exports.alloc(32);
  const mp = exports.alloc(m.length);
  const kp = exports.alloc(32);
  const ctp = exports.alloc(97 + m.length);
  try {
    mem.set(x, pxp);
    mem.set(y, pyp);
    mem.set(m, mp);
    for (let attempt = 0; attempt < 16; attempt++) {
      mem.set(randomK(), kp);
      const rc = exports.encryptOut(pxp, pyp, mp, m.length, kp, ctp);
      if (rc === 1) {
        const raw = new Uint8Array(mem.buffer, ctp, 97 + m.length).slice();
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
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

/** `decrypt` 的实作：失败时按错误类型抛出。 */
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
    if (ct.length > 97) {
      try {
        return decryptRaw(d, c1c2c3ToC1c3c2(ct));
      } catch {
        // 两种顺序都不成立：抛原始错误，保留 C1C3C2 路径的诊断信息。
      }
    }
    throw err;
  }
}

/** 按 C1C3C2 布局解密（wasm 侧约定的布局）。 */
function decryptRaw(d: Uint8Array, ct: Uint8Array): string {
  const { exports } = getModule();
  const mem = new Uint8Array(getModule().memory.buffer);
  const dp = exports.alloc(32);
  const ctp = exports.alloc(ct.length);
  const outLen = ct.length - 97;
  const ptp = exports.alloc(outLen === 0 ? 1 : outLen);
  try {
    mem.set(d, dp);
    mem.set(ct, ctp);
    const rc = exports.decryptOut(dp, ctp, ct.length, ptp);
    if (rc !== 1) throw new DecryptionError('sm2.decrypt: C3 verification failed');
    return fromBytes(new Uint8Array(mem.buffer, ptp, outLen).slice(), 'hex');
  } finally {
    exports.freeAll();
  }
}

// SM2 密钥交换协议（GM/T 0003.3-2014）：createExchangeInitiator /
// createExchangeResponder 由 `./exchange` 提供，在此并入 sm2 命名空间。
export * from './exchange.js';

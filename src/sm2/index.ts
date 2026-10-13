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
 * - 当前返回/接受 64/65 字节的裸字节（hex）密钥与密文。
 * - PEM 编解码（PKCS#8/SPKI）在 `src/pem/` 已有基础；高层 PEM API 见后续迭代。
 * - **随机数一律走宿主 CSPRNG**（`src/runtime/random.ts`）。
 *
 * spec/plan 对应：plan Task 6/8；spec §6 API、§12.1 Q1（默认 C1C3C2）。
 */
import { loadWasm } from '../runtime/loadWasm.js';
import { fromBytes, toBytes } from '../runtime/convert.js';
import { randomScalarBelow } from '../runtime/random.js';

interface Sm2Exports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly publicKeyOut: (dPtr: number, outPtr: number) => void;
  readonly signOut: (
    privPtr: number, pubXPtr: number, pubYPtr: number,
    msgPtr: number, msgLen: number, kPtr: number, outPtr: number,
  ) => number;
  readonly verifyOut: (
    pubXPtr: number, pubYPtr: number, msgPtr: number, msgLen: number, sigPtr: number,
  ) => number;
  readonly encryptOut: (
    pubXPtr: number, pubYPtr: number, msgPtr: number, msgLen: number, kPtr: number, outPtr: number,
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
function putHex(hex: string, ptr: number, len: number): void {
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
  const d = toBytes(privateKey, 'privateKey');
  if (d.length !== 32) throw new RangeError('sm2: privateKey must be 32 bytes');
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

function splitPub(pub: string | Uint8Array): { x: Uint8Array; y: Uint8Array } {
  let b = toBytes(pub, 'publicKey');
  if (b.length === 65 && b[0] === 0x04) b = b.subarray(1);
  if (b.length !== 64) throw new RangeError('sm2: publicKey must be 64 or 65 bytes');
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
  const d = toBytes(privateKey, 'privateKey');
  const m = toBytes(message, 'message');
  if (d.length !== 32) throw new RangeError('sm2: privateKey must be 32 bytes');
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
  const m = toBytes(message, 'message');
  const sig = toBytes(signature, 'signature');
  if (sig.length !== 64) throw new RangeError('sm2: signature must be 64 bytes');
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
 * @param publicKey 64 或 65 字节公钥。
 * @param message 明文。
 * @returns 密文 hex（C1C3C2：C1(65) || C3(32) || C2）。
 */
export function encrypt(publicKey: string | Uint8Array, message: string | Uint8Array): string {
  const { x, y } = splitPub(publicKey);
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
        return fromBytes(new Uint8Array(mem.buffer, ctp, 97 + m.length).slice(), 'hex');
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
 * @returns 明文的 hex。
 */
export function decrypt(privateKey: string | Uint8Array, ciphertext: string | Uint8Array): string {
  const d = toBytes(privateKey, 'privateKey');
  const ct = toBytes(ciphertext, 'ciphertext');
  if (d.length !== 32) throw new RangeError('sm2: privateKey must be 32 bytes');
  if (ct.length < 97) throw new RangeError('sm2: ciphertext too short');
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
    if (rc !== 1) throw new Error('sm2.decrypt: C3 verification failed');
    return fromBytes(new Uint8Array(mem.buffer, ptp, outLen).slice(), 'hex');
  } finally {
    exports.freeAll();
  }
}
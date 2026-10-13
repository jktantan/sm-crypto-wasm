/**
 * SM9 业务 API（TS 胶水层，调 WASM）。
 *
 * 提供的高层能力：
 * - `ensureLoaded()`：加载 sm9.wasm
 * - `getSignPublicKey(ks)`：从签名主私钥 ks 派生签名主公钥 [ks]P2（128B G2 仿射）
 * - `getEncPublicKey(ke)`：从加密主私钥 ke 派生加密主公钥 [ke]P1（64B G1 仿射）
 * - `sign(ks, id, msg, r?)`：SM9 签名（GM/T 0044 §5），输出 96B 签 hex
 * - `verify(ks, id, msg, sig)`：SM9 验签，通过返回 true
 * - `encrypt(ke, id, msg, r?)`：SM9 加密，输出 C1||C3||C2 hex（C1=65B, C3=32B, C2=|msg|）
 * - `decrypt(ke, id, ct)`：SM9 解密，输出明文 hex；C3 HMAC 校验失败抛错
 *
 * 输入/输出 hex 全部不带 0x 前缀。
 * r 不传时由宿主 CSPRNG 提供（Node: crypto.randomBytes / 浏览器: crypto.getRandomValues）。
 *
 * 字节序约定（与 GmSSL C sm9test.c 一致）：
 *   Fp2 序列化: a1||a0（a1 在前）
 *   Fp12 序列化: a2||a1||a0
 *   G2 仿射: X[1]||X[0]||Y[1]||Y[0]（Fp2 各 64 字节）
 *   签名: h(32)||Sx(32)||Sy(32)
 *   密文: C1(65B 压缩 G1)||C3(32B HMAC-SM3)||C2(|msg|B XOR KDF)
 *
 * spec/plan 对应：plan Task 10；spec §6 API、§12.1 Q2（同步优先）、Q3（PKCS#8 + SM9 OID）。
 */
import { loadWasm } from '../runtime/loadWasm.js';
import { randomScalarBelow } from '../runtime/random.js';

/** SM9 曲线阶 n。 */
const N = BigInt('0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25');

/** WASM 导出的最小子集。诊断入口的子集。 */
interface Sm9Exports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly signPubOut: (ksPtr: number, outPtr: number) => void;
  readonly encPubOut: (kePtr: number, outPtr: number) => void;
  readonly sm9SignOut: (
    ksPtr: number, idPtr: number, idLen: number,
    msgPtr: number, msgLen: number, rPtr: number, outPtr: number,
  ) => void;
  readonly sm9VerifyOut: (
    ksPtr: number, idPtr: number, idLen: number,
    msgPtr: number, msgLen: number, sigPtr: number,
  ) => number;
  readonly sm9EncryptOut: (
    kePtr: number, idPtr: number, idLen: number,
    msgPtr: number, msgLen: number, rPtr: number, outPtr: number,
  ) => number;
  readonly sm9DecryptOut: (
    kePtr: number, idPtr: number, idLen: number,
    ctPtr: number, ctLen: number, outPtr: number,
  ) => number;
  readonly memory: WebAssembly.Memory;
}

interface Sm9Module {
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

function getModule(): Sm9Module {
  const m = (globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm;
  if (!m) throw new Error('sm9: 未初始化，请先 `await ensureLoaded()`。');
  return m;
}

// ---------------- 工具 ----------------

/** 任意输入 → Uint8Array。
 *  - Uint8Array: 拷一份
 *  - string 且看起来是 hex（偶数长度 + 全部 0-9a-fA-F）：按 hex 解
 *  - 其他 string：按 UTF-8 编码（用于 id、msg 等人类可读输入）
 * 失败抛 TypeError。 */
function toBytes(input: string | Uint8Array, label: string): Uint8Array {
  if (input instanceof Uint8Array) return new Uint8Array(input);
  if (typeof input !== 'string') throw new TypeError(`sm9: ${label} 必须是字符串或 Uint8Array`);
  if (input.startsWith('0x') || /^[0-9a-fA-F]+$/.test(input)) {
    const s = input.startsWith('0x') ? input.slice(2) : input;
    if (s.length % 2 !== 0) throw new TypeError(`sm9: ${label} hex 长度必须为偶数`);
    return new Uint8Array(Buffer.from(s, 'hex'));
  }
  return new TextEncoder().encode(input);
}

function requireLen(b: Uint8Array, n: number, label: string): void {
  if (b.length !== n) throw new RangeError(`sm9: ${label} 必须是 ${n} 字节，实际 ${b.length}`);
}

function mem(): Uint8Array {
  return new Uint8Array(getModule().memory.buffer);
}

function allocBytes(n: number): number {
  return getModule().exports.alloc(n);
}

function putHex(hex: string, ptr: number): void {
  mem().set(Buffer.from(hex, 'hex'), ptr);
}

function putBytes(b: Uint8Array, ptr: number): void {
  mem().set(b, ptr);
}

function readHex(ptr: number, len: number): string {
  return Buffer.from(mem().subarray(ptr, ptr + len)).toString('hex');
}

function randomRHex(): string {
  return randomScalarBelow(N).toString(16).padStart(64, '0');
}

// ---------------- API ----------------

/** 32 字节签名主私钥 ks → 256 字节 G2 仿射（X[1]||X[0]||Y[1]||Y[0]）= 128 字节 hex。 */
export function getSignPublicKey(ks: string | Uint8Array): string {
  const k = toBytes(ks, 'ks');
  requireLen(k, 32, 'ks');
  const { exports } = getModule();
  const kp = exports.alloc(32);
  const op = exports.alloc(128);
  try {
    putBytes(k, kp);
    exports.signPubOut(kp, op);
    return readHex(op, 128);
  } finally {
    exports.freeAll();
  }
}

/** 32 字节加密主私钥 ke → 64 字节 G1 仿射（x||y）= 128 字符 hex。 */
export function getEncPublicKey(ke: string | Uint8Array): string {
  const k = toBytes(ke, 'ke');
  requireLen(k, 32, 'ke');
  const { exports } = getModule();
  const kp = exports.alloc(32);
  const op = exports.alloc(64);
  try {
    putBytes(k, kp);
    exports.encPubOut(kp, op);
    return readHex(op, 64);
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 签名（GM/T 0044 §5）。
 * @param ks  32 字节签名主私钥 hex
 * @param id  用户标识字符串（如 'Alice'）或 Uint8Array
 * @param msg 消息字符串（UTF-8）/ Uint8Array / hex 字符串
 * @param r   32 字节随机数 hex（可选；不传则由宿主 CSPRNG 提供）
 * @returns   192 字符 hex 签（h||Sx||Sy）
 */
export function sign(
  ks: string | Uint8Array,
  id: string | Uint8Array,
  msg: string | Uint8Array,
  r?: string | Uint8Array,
): string {
  const ksB = toBytes(ks, 'ks'); requireLen(ksB, 32, 'ks');
  const idB = toBytes(id, 'id');
  const msgB = toBytes(msg, 'msg');
  const rB = r !== undefined ? toBytes(r, 'r') : toBytes(randomRHex(), 'r');
  requireLen(rB, 32, 'r');

  const { exports } = getModule();
  const ksP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const msgP = exports.alloc(msgB.length);
  const rP = exports.alloc(32);
  const sigP = exports.alloc(96);
  try {
    putBytes(ksB, ksP);
    putBytes(idB, idP);
    putBytes(msgB, msgP);
    putBytes(rB, rP);
    exports.sm9SignOut(ksP, idP, idB.length, msgP, msgB.length, rP, sigP);
    return readHex(sigP, 96);
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 验签。内部用 ks 重新派生 ppubs。
 * @returns true = 通过；false = 拒绝（签错、id 错、msg 错、tampered）
 */
export function verify(
  ks: string | Uint8Array,
  id: string | Uint8Array,
  msg: string | Uint8Array,
  sig: string | Uint8Array,
): boolean {
  const ksB = toBytes(ks, 'ks'); requireLen(ksB, 32, 'ks');
  const idB = toBytes(id, 'id');
  const msgB = toBytes(msg, 'msg');
  const sigB = toBytes(sig, 'sig');
  requireLen(sigB, 96, 'sig');

  const { exports } = getModule();
  const ksP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const msgP = exports.alloc(msgB.length);
  const sigP = exports.alloc(96);
  try {
    putBytes(ksB, ksP);
    putBytes(idB, idP);
    putBytes(msgB, msgP);
    putBytes(sigB, sigP);
    return exports.sm9VerifyOut(ksP, idP, idB.length, msgP, msgB.length, sigP) === 1;
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 加密（GM/T 0044 §6）。
 * @param ke  32 字节加密主私钥 hex
 * @param id  接收方标识
 * @param msg 明文（字符串按 UTF-8；也可传 Uint8Array 或 hex）
 * @param r   32 字节随机数 hex（可选）
 * @returns   密文 hex（C1=65B + C3=32B + C2=|msg|B = 65+32+|msg| 字节）
 */
export function encrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  msg: string | Uint8Array,
  r?: string | Uint8Array,
): string {
  const keB = toBytes(ke, 'ke'); requireLen(keB, 32, 'ke');
  const idB = toBytes(id, 'id');
  const msgB = toBytes(msg, 'msg');
  const rB = r !== undefined ? toBytes(r, 'r') : toBytes(randomRHex(), 'r');
  requireLen(rB, 32, 'r');

  const { exports } = getModule();
  const keP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const msgP = exports.alloc(msgB.length);
  const rP = exports.alloc(32);
  const ctP = exports.alloc(4096);
  try {
    putBytes(keB, keP);
    putBytes(idB, idP);
    putBytes(msgB, msgP);
    putBytes(rB, rP);
    const ctLen = exports.sm9EncryptOut(keP, idP, idB.length, msgP, msgB.length, rP, ctP);
    if (ctLen < 0) throw new Error('sm9: encrypt 失败');
    return readHex(ctP, ctLen);
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 解密。校验失败（C3 HMAC 不通过、长度错、首字节非 0x04 等）抛错。
 * @returns 明文 hex
 */
export function decrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  ct: string | Uint8Array,
): string {
  const keB = toBytes(ke, 'ke'); requireLen(keB, 32, 'ke');
  const idB = toBytes(id, 'id');
  const ctB = toBytes(ct, 'ct');
  if (ctB.length < 97) throw new RangeError('sm9: ct 长度必须 >= 97 字节 (C1=65 + C3=32)');

  const { exports } = getModule();
  const keP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const ctP = exports.alloc(ctB.length);
  const ptP = exports.alloc(ctB.length);
  try {
    putBytes(keB, keP);
    putBytes(idB, idP);
    putBytes(ctB, ctP);
    const ptLen = exports.sm9DecryptOut(keP, idP, idB.length, ctP, ctB.length, ptP);
    if (ptLen < 0) throw new Error('sm9: decrypt 失败（C3 HMAC 校验未通过 / 格式错误）');
    return readHex(ptP, ptLen);
  } finally {
    exports.freeAll();
  }
}

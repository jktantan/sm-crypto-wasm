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

import {
  encodeSm9PrivateKeyPem,
  encodeSm9PublicKeyPem,
  parseSm9PrivateKeyPem,
  parseSm9PublicKeyPem,
} from '../pem/sm9.js';
import {
  CiphertextError,
  DecryptionError,
  InvalidCiphertextError,
  InvalidKeyError,
} from '../runtime/errors.js';
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

interface Sm9Module {
  exports: Sm9Exports;
  memory: WebAssembly.Memory;
}

/** 预热 WASM 模块。 */
export async function ensureLoaded(): Promise<void> {  if ((globalThis as { __sm9Wasm?: Sm9Module }).__sm9Wasm) return;
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
/**
 * 通用输入归一化：Uint8Array 拷贝、hex 解码、其它按 UTF-8。
 *
 * **刻意不做 PEM 嗅探** —— PEM 只可能出现在密钥参数上，由 `masterPrivateBytes`
 * 显式处理；这样 id / msg 里出现 `-----BEGIN` 也不会被误吞。
 */
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

/**
 * 主私钥参数归一化：接受 32 字节（hex / Uint8Array）或 PKCS#8 私钥 PEM
 * （spec §12.1 Q3，算法 OID `1.2.156.10197.1.100`）。
 */
function masterPrivateBytes(input: string | Uint8Array, label: string): Uint8Array {
  let bytes: Uint8Array;
  if (typeof input === 'string' && input.includes('-----BEGIN')) {
    const parsed = parseSm9PrivateKeyPem(input);
    if (parsed.length !== 32) {
      throw new InvalidKeyError(`sm9: ${label} 作为 PEM 主私钥应为 32 字节，实际 ${parsed.length}`);
    }
    bytes = parsed;
  } else {
    const b = toBytes(input, label);
    if (b.length !== 32) {
      throw new InvalidKeyError(`sm9: ${label} 必须是 32 字节主私钥，实际 ${b.length}`);
    }
    bytes = b;
  }
  // 标量范围：SM9（GM/T 0044）要求 1 ≤ k ≤ n−1。
  // 越界值不会崩，但 wasm 侧的 addModN → modAdd 只做一次条件减、要求输入已
  // 约化（h1 + k < 2n），k ≥ n 时 k + h1 可能 ≥ 2n 而静默产出错值，故在此显式拒绝。
  const k = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
  if (k < 1n || k >= N) {
    throw new InvalidKeyError(`sm9: ${label} 必须在 [1, n−1] 范围内（SM9 主私钥标量）`);
  }
  return bytes;
}

/** 主公钥参数归一化：64（加密 G1）或 128（签名 G2）字节点，或 SPKI 主公钥 PEM。 */
function masterPublicBytes(input: string | Uint8Array, label: string): Uint8Array {
  if (typeof input === 'string' && input.includes('-----BEGIN')) {
    const pub = parseSm9PublicKeyPem(input);
    if (pub.length !== 64 && pub.length !== 128) {
      throw new InvalidKeyError(
        `sm9: ${label} 作为 PEM 主公钥必须是 64 或 128 字节，实际 ${pub.length}`,
      );
    }
    return pub;
  }
  const b = toBytes(input, label);
  if (b.length !== 64 && b.length !== 128) {
    throw new InvalidKeyError(
      `sm9: ${label} 必须是 64（加密）或 128（签名）字节主公钥，实际 ${b.length}`,
    );
  }
  return b;
}

/** `verify` / `encrypt` 第一参数的解析结果。 */
type KeyArg = { kind: 'secret'; bytes: Uint8Array } | { kind: 'public'; bytes: Uint8Array };

/**
 * 解析 `verify` / `encrypt` 的密钥参数：主私钥（32 字节 / PKCS#8 私钥 PEM）
 * 或主公钥（`publicLen` 字节点 / SPKI 公钥 PEM）。
 *
 * 两者的长度区间不重叠（主私钥恒为 32 字节），因此按长度即可判别。
 */
function keyArg(input: string | Uint8Array, publicLen: 64 | 128, label: string): KeyArg {
  if (typeof input === 'string' && input.includes('-----BEGIN')) {
    if (input.includes('BEGIN PUBLIC KEY')) {
      const pub = parseSm9PublicKeyPem(input);
      if (pub.length !== publicLen) {
        throw new InvalidKeyError(
          `sm9: ${label} 作为 PEM 主公钥应为 ${publicLen} 字节，实际 ${pub.length}`,
        );
      }
      return { kind: 'public', bytes: pub };
    }
    return { kind: 'secret', bytes: masterPrivateBytes(input, label) };
  }
  const b = toBytes(input, label);
  if (b.length === 32) return { kind: 'secret', bytes: b };
  if (b.length === publicLen) return { kind: 'public', bytes: b };
  throw new InvalidKeyError(
    `sm9: ${label} 必须是 32 字节主私钥或 ${publicLen} 字节主公钥，实际 ${b.length}`,
  );
}

/**
 * 校验字节长度。默认按**密钥支**（`InvalidKeyError`）抛错 —— SM9 各入口的参数绝大多数
 * 是主私钥 / 标量；密文、签名、协议消息的调用点显式传 `'cipher'`。
 */
function requireLen(b: Uint8Array, n: number, label: string, kind: 'key' | 'cipher' = 'key'): void {
  if (b.length === n) return;
  const msg = `sm9: ${label} 必须是 ${n} 字节，实际 ${b.length}`;
  if (kind === 'cipher') throw new InvalidCiphertextError(msg);
  throw new InvalidKeyError(msg);
}

function mem(): Uint8Array {
  return new Uint8Array(getModule().memory.buffer);
}

function _allocBytes(n: number): number {
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

/** SM9 主密钥用途。 */
export type Sm9KeyPurpose = 'sign' | 'enc';

/** `generateKeyPair` 选项。 */
export interface Sm9KeyPairOptions {
  /** 用户标识（用户私钥绑定到该 id）。 */
  id: string | Uint8Array;
  /** 主密钥用途：`'sign'`（默认）或 `'enc'`。 */
  purpose?: Sm9KeyPurpose;
}

/**
 * SM9 密钥对（PEM 形态：PKCS#8 私钥 / SPKI 公钥，算法 OID `1.2.156.10197.1.100`）。
 */
export interface Sm9KeyPair {
  /** 主私钥（32 字节标量：签名 ks / 加密 ke）。 */
  masterPrivatePem: string;
  /** 主公钥点：签名 `[ks]P2`（G2，128B）/ 加密 `[ke]P1`（G1，64B）。 */
  masterPublicPem: string;
  /** 用户私钥点：签名 ds（G1，64B）/ 加密 de（G2，128B）。 */
  userPrivatePem: string;
  /**
   * 用户公钥点 `Q = [H1(id,hid)]P1|P2 + Ppub`：签名（G2，128B）/ 加密（G1，64B）。
   *
   * 它是 `(id, 主公钥)` 的确定函数、不是独立秘密，第三方可用
   * `getUserPublicKey(masterPublicPem, id)` 自行复算。
   */
  userPublicPem: string;
}

/**
 * 生成 SM9 主密钥对与对应用户私钥（spec §6、§12.1 Q3）。
 *
 * 异步：含 wasm 实例化与宿主 CSPRNG 取主私钥。
 *
 * @param opts `id` 与 `purpose`（默认 `'sign'`）。
 */
export async function generateKeyPair(opts: Sm9KeyPairOptions): Promise<Sm9KeyPair> {
  await ensureLoaded();
  const purpose = opts.purpose ?? 'sign';
  if (purpose !== 'sign' && purpose !== 'enc') {
    throw new RangeError(`sm9.generateKeyPair: 未知的 purpose ${String(purpose)}`);
  }
  const idB = toBytes(opts.id, 'id');
  if (idB.length === 0) throw new RangeError('sm9.generateKeyPair: 用户标识不能为空');

  const masterHex = randomRHex();
  const { exports } = getModule();
  const masterPtr = exports.alloc(32);
  const idPtr = exports.alloc(idB.length);
  const pubPtr = exports.alloc(128);
  const userPtr = exports.alloc(128);
  const userPubPtr = exports.alloc(128);
  try {
    putHex(masterHex, masterPtr);
    putBytes(idB, idPtr);
    let pubLen: number;
    let userLen: number;
    if (purpose === 'sign') {
      exports.signPubOut(masterPtr, pubPtr); // [ks]P2 → 128B
      exports.signDsOut(masterPtr, idPtr, idB.length, userPtr); // ds → 64B
      pubLen = 128;
      userLen = 64;
    } else {
      exports.encPubOut(masterPtr, pubPtr); // [ke]P1 → 64B
      exports.encDeOut(masterPtr, idPtr, idB.length, userPtr); // de → 128B
      pubLen = 64;
      userLen = 128;
    }
    // 用户公钥 Q = [H1(id, hid)]P1|P2 + Ppub —— (id, 主公钥) 的确定函数。
    if (purpose === 'sign') {
      exports.sm9UserSignPubOut(pubPtr, idPtr, idB.length, userPubPtr);
    } else {
      exports.sm9UserEncPubOut(pubPtr, idPtr, idB.length, userPubPtr);
    }
    // 调用后重新取 buffer 视图：WASM 内存可能在分配后增长。
    const memView = mem();
    return {
      masterPrivatePem: encodeSm9PrivateKeyPem(Buffer.from(masterHex, 'hex')),
      masterPublicPem: encodeSm9PublicKeyPem(
        new Uint8Array(memView.buffer, pubPtr, pubLen).slice(),
      ),
      userPrivatePem: encodeSm9PrivateKeyPem(
        new Uint8Array(memView.buffer, userPtr, userLen).slice(),
      ),
      userPublicPem: encodeSm9PublicKeyPem(
        new Uint8Array(memView.buffer, userPubPtr, pubLen).slice(),
      ),
    };
  } finally {
    exports.freeAll();
  }
}

/** 32 字节签名主私钥 ks → 256 字节 G2 仿射（X[1]||X[0]||Y[1]||Y[0]）= 128 字节 hex。 */
export function getSignPublicKey(ks: string | Uint8Array): string {
  const k = masterPrivateBytes(ks, 'ks');
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
  const k = masterPrivateBytes(ke, 'ke');
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
 * 诊断（非公开 API，仅供测试/内部校验）：cyclotomic 平方自测。
 *
 * 对 `seed` 派生的伪随机 Fp12 送入 cyclotomic 子群后，用子群专用平方
 * （fp12SqrCycTo）与通用平方（fp12SqrTo）各算一次并逐字节比较，返回是否一致。
 * 用于覆盖 KAT 覆盖不到的随机子群元素。
 */
export function sqrCycSelfTest(seed: number): number {
  const { exports } = getModule();
  return exports.sqrCycSelfTestOut(seed | 0);
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
  const ksB = masterPrivateBytes(ks, 'ks');
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
 * SM9 验签（GM/T 0044 §5）。
 *
 * @param publicKey 32 字节签名主私钥（hex / PKCS#8 私钥 PEM），或 128 字节签名主公钥
 *   `[ks]P2`（点字节 / SPKI 公钥 PEM）—— 后者是 spec §6 里的形态，长度即可区分。
 * @returns true = 通过；false = 拒绝（签错、id 错、msg 错、tampered）
 */
export function verify(
  publicKey: string | Uint8Array,
  id: string | Uint8Array,
  msg: string | Uint8Array,
  sig: string | Uint8Array,
): boolean {
  const key = keyArg(publicKey, 128, 'publicKey');
  const idB = toBytes(id, 'id');
  const msgB = toBytes(msg, 'msg');
  const sigB = toBytes(sig, 'sig');
  requireLen(sigB, 96, 'sig', 'cipher');

  const { exports } = getModule();
  const idP = exports.alloc(idB.length);
  const msgP = exports.alloc(msgB.length);
  const sigP = exports.alloc(96);
  const keyP = exports.alloc(key.bytes.length);
  try {
    putBytes(idB, idP);
    putBytes(msgB, msgP);
    putBytes(sigB, sigP);
    putBytes(key.bytes, keyP);
    const ok =
      key.kind === 'public'
        ? exports.sm9VerifyPubOut(keyP, idP, idB.length, msgP, msgB.length, sigP)
        : exports.sm9VerifyOut(keyP, idP, idB.length, msgP, msgB.length, sigP);
    return ok === 1;
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 加密（GM/T 0044 §6）。
 *
 * @param publicKey 32 字节加密主私钥（hex / PKCS#8 私钥 PEM），或 64 字节加密主公钥
 *   `[ke]P1`（点字节 / SPKI 公钥 PEM）—— 后者是 spec §6 里的形态，长度即可区分。
 * @param id  接收方标识
 * @param msg 明文（字符串按 UTF-8；也可传 Uint8Array 或 hex）
 * @param r   32 字节随机数 hex（可选）
 * @returns   密文 hex（C1=65B + C3=32B + C2=|msg|B = 65+32+|msg| 字节）
 */
export function encrypt(
  publicKey: string | Uint8Array,
  id: string | Uint8Array,
  msg: string | Uint8Array,
  r?: string | Uint8Array,
): string {
  const key = keyArg(publicKey, 64, 'publicKey');
  const idB = toBytes(id, 'id');
  const msgB = toBytes(msg, 'msg');
  const rB = r !== undefined ? toBytes(r, 'r') : toBytes(randomRHex(), 'r');
  requireLen(rB, 32, 'r');

  const { exports } = getModule();
  const keyP = exports.alloc(key.bytes.length);
  const idP = exports.alloc(idB.length);
  const msgP = exports.alloc(msgB.length);
  const rP = exports.alloc(32);
  const ctP = exports.alloc(4096);
  try {
    putBytes(key.bytes, keyP);
    putBytes(idB, idP);
    putBytes(msgB, msgP);
    putBytes(rB, rP);
    const ctLen =
      key.kind === 'public'
        ? exports.sm9EncryptPubOut(keyP, idP, idB.length, msgP, msgB.length, rP, ctP)
        : exports.sm9EncryptOut(keyP, idP, idB.length, msgP, msgB.length, rP, ctP);
    if (ctLen < 0) throw new Error('sm9: encrypt 失败');
    return readHex(ctP, ctLen);
  } finally {
    exports.freeAll();
  }
}

/**
 * 从主公钥与用户标识推导用户公钥（PEM），第三方无需 KGC 参与即可复算。
 *
 * 签名主公钥（128B G2）→ `[H1(id, hid=1)]P2 + Ppub-s`（G2，128B）；
 * 加密主公钥（64B G1）→ `[H1(id, hid=3)]P1 + Ppub-e`（G1，64B）。
 *
 * @param masterPublicKey 主公钥（点字节 / SPKI 公钥 PEM）。
 * @param id 用户标识。
 */
export function getUserPublicKey(
  masterPublicKey: string | Uint8Array,
  id: string | Uint8Array,
): string {
  const pub = masterPublicBytes(masterPublicKey, 'masterPublicKey');
  const idB = toBytes(id, 'id');
  if (idB.length === 0) throw new RangeError('sm9.getUserPublicKey: 用户标识不能为空');
  const { exports } = getModule();
  const pubP = exports.alloc(pub.length);
  const idP = exports.alloc(idB.length);
  const userPubPtr = exports.alloc(128);
  try {
    putBytes(pub, pubP);
    putBytes(idB, idP);
    if (pub.length === 128) {
      exports.sm9UserSignPubOut(pubP, idP, idB.length, userPubPtr);
    } else {
      exports.sm9UserEncPubOut(pubP, idP, idB.length, userPubPtr);
    }
    return encodeSm9PublicKeyPem(new Uint8Array(mem().buffer, userPubPtr, pub.length).slice());
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 解密。校验失败（C3 HMAC 不通过、长度错、首字节非 0x04 等）抛错。
 * @returns 明文 hex
 */
/** `sm9.decrypt` 选项。 */
export interface Sm9DecryptOptions {
  /**
   * 解密失败时返回 `null` 而不抛错（plan Review Focus #4）。
   * 只覆盖密文支错误（`CiphertextError`）。
   */
  safeMode?: boolean;
}

export function decrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  ct: string | Uint8Array,
  opts: Sm9DecryptOptions & { safeMode: true },
): string | null;
export function decrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  ct: string | Uint8Array,
  opts?: Sm9DecryptOptions,
): string;
export function decrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  ct: string | Uint8Array,
  opts: Sm9DecryptOptions = {},
): string | null {
  try {
    return decryptUnsafe(ke, id, ct);
  } catch (err) {
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

/** `decrypt` 的实作：校验失败抛 `DecryptionError`。 */
function decryptUnsafe(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  ct: string | Uint8Array,
): string {
  const keB = masterPrivateBytes(ke, 'ke');
  const idB = toBytes(id, 'id');
  const ctB = toBytes(ct, 'ct');
  if (ctB.length < 97)
    throw new InvalidCiphertextError('sm9: ct 长度必须 >= 97 字节 (C1=65 + C3=32)');

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
    if (ptLen < 0) throw new DecryptionError('sm9: decrypt 失败（C3 HMAC 校验未通过 / 格式错误）');
    return readHex(ptP, ptLen);
  } finally {
    exports.freeAll();
  }
}

// ---------------- KEM（密钥封装机制，GM/T 0044.4） ----------------

/** KEM 封装结果。 */
export interface KemResult {
  /** 会话密钥 K（hex，长度为 `2*klen`）。 */
  key: string;
  /** 封装点 C1（65 字节未压缩 G1 点 hex：`04 || x || y`）。 */
  encapsulation: string;
}

/**
 * SM9 密钥封装（GM/T 0044.4）：用接收方 id 与其加密主公钥 [ke]P1 封装一个会话密钥。
 *
 * @param ke   32 字节加密主私钥 hex（用于派生主公钥 [ke]P1）
 * @param id   接收方标识
 * @param klen 会话密钥字节长度（默认 32）
 * @param r    32 字节随机数 hex（可选；不传则由宿主 CSPRNG 提供）
 * @returns    `{ key, encapsulation }`
 */
export function kemEncrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  klen = 32,
  r?: string | Uint8Array,
): KemResult {
  const keB = masterPrivateBytes(ke, 'ke');
  const idB = toBytes(id, 'id');
  const rB = r !== undefined ? toBytes(r, 'r') : toBytes(randomRHex(), 'r');
  requireLen(rB, 32, 'r');
  if (!Number.isInteger(klen) || klen <= 0) throw new RangeError('sm9: klen 必须为正整数');

  const { exports } = getModule();
  const keP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const rP = exports.alloc(32);
  const c1P = exports.alloc(65);
  const kP = exports.alloc(klen);
  try {
    putBytes(keB, keP);
    putBytes(idB, idP);
    putBytes(rB, rP);
    const rc = exports.sm9KemEncryptOut(keP, idP, idB.length, rP, klen, c1P, kP);
    if (rc !== 1) throw new Error('sm9: kemEncrypt 失败（K 全 0，需换随机数重试）');
    return { key: readHex(kP, klen), encapsulation: readHex(c1P, 65) };
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 密钥解封装：用本端加密主私钥 ke 与 id 从封装点 C1 恢复会话密钥。
 *
 * @param encapsulation 65 字节封装点 C1 hex
 * @returns 会话密钥 hex
 */
export function kemDecrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen = 32,
): string {
  const keB = masterPrivateBytes(ke, 'ke');
  const idB = toBytes(id, 'id');
  const c1B = toBytes(encapsulation, 'encapsulation');
  if (c1B.length !== 65)
    throw new RangeError(`sm9: encapsulation 必须是 65 字节，实际 ${c1B.length}`);
  if (!Number.isInteger(klen) || klen <= 0) throw new RangeError('sm9: klen 必须为正整数');

  const { exports } = getModule();
  const keP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const c1P = exports.alloc(65);
  const kP = exports.alloc(klen);
  try {
    putBytes(keB, keP);
    putBytes(idB, idP);
    putBytes(c1B, c1P);
    const rc = exports.sm9KemDecryptOut(keP, idP, idB.length, c1P, klen, kP);
    if (rc !== 1) throw new DecryptionError('sm9: kemDecrypt 失败（封装非法 / K 全 0）');
    return readHex(kP, klen);
  } finally {
    exports.freeAll();
  }
}

// ---------------- 密钥交换（GM/T 0044.3） ----------------

/** 密钥交换端点配置。 */
export interface Sm9ExchangeOptions {
  /** 会话密钥字节长度（默认 32）。 */
  kLen?: number;
  /** 测试注入：本端临时私钥 r（32 字节）。默认由宿主 CSPRNG 生成。 */
  ephemeral?: string | Uint8Array;
}

/** 阶段 1 消息：发起方临时点 RA（65 字节未压缩 G1 点 hex）。 */
export interface Sm9InitiatorMessage {
  ephemeral: string;
}
/** 阶段 2 消息：响应方临时点 RB + 确认值 SB。 */
export interface Sm9ResponderMessage extends Sm9InitiatorMessage {
  confirm: string;
}
/** 阶段 3 消息：发起方确认值 SA。 */
export interface Sm9InitiatorConfirm {
  confirm: string;
}

export interface Sm9KeyExchangeInitiator {
  initiate(): Sm9InitiatorMessage;
  confirm(msg: Sm9ResponderMessage): Sm9InitiatorConfirm;
  getSharedKey(msg: Sm9ResponderMessage, kLen?: number): string;
}
export interface Sm9KeyExchangeResponder {
  respond(msg: Sm9InitiatorMessage): Sm9ResponderMessage;
  getSharedKey(msg: Sm9InitiatorConfirm, kLen?: number): string;
}

function ctEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return d === 0;
}

function r32(options: Sm9ExchangeOptions): Uint8Array {
  const r =
    options.ephemeral !== undefined
      ? toBytes(options.ephemeral, 'ephemeral')
      : toBytes(randomRHex(), 'r');
  requireLen(r, 32, 'ephemeral');
  return r;
}

/** 本端临时点 R = [r](H1(ID_peer||hid,N)P1 + Ppube)，65 字节。 */
function exchEphemeral(ke: Uint8Array, peerId: Uint8Array, r: Uint8Array): Uint8Array {
  const { exports } = getModule();
  const keP = exports.alloc(32);
  const pidP = exports.alloc(peerId.length);
  const rP = exports.alloc(32);
  const outP = exports.alloc(65);
  try {
    putBytes(ke, keP);
    putBytes(peerId, pidP);
    putBytes(r, rP);
    exports.sm9ExchEphemeralOut(keP, pidP, peerId.length, rP, outP);
    return new Uint8Array(mem().subarray(outP, outP + 65));
  } finally {
    exports.freeAll();
  }
}

/** 一次算出的结果：SA(0x83)、SB(0x82) 与共享密钥。 */
interface ExchAll {
  sa: string;
  sb: string;
  key: string;
}

/**
 * 调用一次 wasm（`sm9ExchAllOut`）即得 SA/SB/共享密钥，避免重复 pairing。
 * SA 为发起方确认值（prefix 0x83）、SB 为响应方确认值（prefix 0x82）。
 */
function exchAll(
  ke: Uint8Array,
  isInitiator: boolean,
  selfId: Uint8Array,
  peerId: Uint8Array,
  r: Uint8Array,
  selfR: Uint8Array,
  peerR: Uint8Array,
  kLen: number,
): ExchAll {
  if (!Number.isInteger(kLen) || kLen <= 0) throw new RangeError('sm9.exch: kLen 必须为正整数');
  const { exports } = getModule();
  const keP = exports.alloc(32);
  const sidP = exports.alloc(selfId.length);
  const pidP = exports.alloc(peerId.length);
  const rP = exports.alloc(32);
  const srP = exports.alloc(65);
  const prP = exports.alloc(65);
  const saP = exports.alloc(32);
  const sbP = exports.alloc(32);
  const kP = exports.alloc(kLen);
  try {
    putBytes(ke, keP);
    putBytes(selfId, sidP);
    putBytes(peerId, pidP);
    putBytes(r, rP);
    putBytes(selfR, srP);
    putBytes(peerR, prP);
    const rc = exports.sm9ExchAllOut(
      keP,
      isInitiator ? 1 : 0,
      sidP,
      selfId.length,
      pidP,
      peerId.length,
      rP,
      srP,
      prP,
      kLen,
      saP,
      sbP,
      kP,
    );
    if (rc !== 1) throw new Error('sm9.exch: 共享密钥为全 0');
    return { sa: readHex(saP, 32), sb: readHex(sbP, 32), key: readHex(kP, kLen) };
  } finally {
    exports.freeAll();
  }
}

function readPoint65(b: string | Uint8Array, label: string): Uint8Array {
  const p = toBytes(b, label);
  if (p.length !== 65) throw new RangeError(`sm9.exch: ${label} 必须是 65 字节未压缩点`);
  return p;
}

/**
 * 构造 SM9 密钥交换发起方（GM/T 0044.3）。A 是发起方，B 是响应方。
 *
 * @param ke 本端（A）加密主私钥
 * @param selfId 本端标识 ID_A
 * @param peerId 对端标识 ID_B
 */
export async function createExchangeInitiator(
  ke: string | Uint8Array,
  selfId: string | Uint8Array,
  peerId: string | Uint8Array,
  options: Sm9ExchangeOptions = {},
): Promise<Sm9KeyExchangeInitiator> {
  await ensureLoaded();
  const keB = masterPrivateBytes(ke, 'ke');
  const selfIdB = toBytes(selfId, 'idSelf');
  const peerIdB = toBytes(peerId, 'idPeer');

  let rA: Uint8Array | null = null;
  let RA: Uint8Array | null = null;
  let cached: { all: ExchAll; kLen: number } | null = null;
  const defaultKL = options.kLen ?? 32;

  return {
    initiate(): Sm9InitiatorMessage {
      if (rA !== null) throw new Error('sm9.exch: initiate() 只能调用一次');
      rA = r32(options);
      RA = exchEphemeral(keB, peerIdB, rA);
      return { ephemeral: Buffer.from(RA).toString('hex') };
    },
    confirm(msg: Sm9ResponderMessage): Sm9InitiatorConfirm {
      const selfR = rA;
      const selfRA = RA;
      if (selfR === null || selfRA === null) throw new Error('sm9.exch: 需先调用 initiate()');
      const RB = readPoint65(msg.ephemeral, 'RB');
      const SB = toBytes(msg.confirm, 'SB');
      requireLen(SB, 32, 'SB', 'cipher');
      const all = exchAll(keB, true, selfIdB, peerIdB, selfR, selfRA, RB, defaultKL);
      if (!ctEq(SB, Buffer.from(all.sb, 'hex')))
        throw new Error('sm9.exch: 响应方确认值 S_B 校验失败');
      cached = { all, kLen: defaultKL };
      return { confirm: all.sa };
    },
    getSharedKey(msg: Sm9ResponderMessage, kLen = defaultKL): string {
      const selfR = rA;
      const selfRA = RA;
      if (selfR === null || selfRA === null) throw new Error('sm9.exch: 需先调用 initiate()');
      if (cached !== null && cached.kLen === kLen) return cached.all.key;
      const RB = readPoint65(msg.ephemeral, 'RB');
      return exchAll(keB, true, selfIdB, peerIdB, selfR, selfRA, RB, kLen).key;
    },
  };
}

/**
 * 构造 SM9 密钥交换响应方（GM/T 0044.3）。B 是响应方。
 *
 * @param ke 本端（B）加密主私钥
 * @param selfId 本端标识 ID_B
 * @param peerId 对端（A）标识 ID_A
 */
export async function createExchangeResponder(
  ke: string | Uint8Array,
  selfId: string | Uint8Array,
  peerId: string | Uint8Array,
  options: Sm9ExchangeOptions = {},
): Promise<Sm9KeyExchangeResponder> {
  await ensureLoaded();
  const keB = masterPrivateBytes(ke, 'ke');
  const selfIdB = toBytes(selfId, 'idSelf');
  const peerIdB = toBytes(peerId, 'idPeer');

  let rB: Uint8Array | null = null;
  let RB: Uint8Array | null = null;
  let RA: Uint8Array | null = null;
  let cached: { all: ExchAll; kLen: number } | null = null;
  const defaultKL = options.kLen ?? 32;

  return {
    respond(msg: Sm9InitiatorMessage): Sm9ResponderMessage {
      if (rB !== null) throw new Error('sm9.exch: respond() 只能调用一次');
      const incomingRA = readPoint65(msg.ephemeral, 'RA');
      rB = r32(options);
      RB = exchEphemeral(keB, peerIdB, rB);
      const all = exchAll(keB, false, selfIdB, peerIdB, rB, RB, incomingRA, defaultKL);
      RA = incomingRA;
      cached = { all, kLen: defaultKL };
      return { ephemeral: Buffer.from(RB).toString('hex'), confirm: all.sb };
    },
    getSharedKey(msg: Sm9InitiatorConfirm, kLen = defaultKL): string {
      const selfR = rB;
      const selfRB = RB;
      const selfRA = RA;
      if (selfR === null || selfRB === null || selfRA === null)
        throw new Error('sm9.exch: 需先调用 respond()');
      const SA = toBytes(msg.confirm, 'SA');
      requireLen(SA, 32, 'SA', 'cipher');
      const all =
        cached !== null && cached.kLen === kLen
          ? cached.all
          : exchAll(keB, false, selfIdB, peerIdB, selfR, selfRB, selfRA, kLen);
      if (!ctEq(SA, Buffer.from(all.sa, 'hex')))
        throw new Error('sm9.exch: 发起方确认值 S_A 校验失败');
      return all.key;
    },
  };
}

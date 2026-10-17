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
 * - `kemEncrypt` / `kemDecrypt`：KEM（GM/T 0044.4，见 `./kem.ts`）
 * - `hybridEncrypt` / `hybridDecrypt`：KEM + SM4-GCM 混合加密（见 `./hybrid.ts`）
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

import { encodeSm9PrivateKeyPem, encodeSm9PublicKeyPem } from '../pem/sm9.js';
import { bytesToHex, hexToBytes } from '../runtime/convert.js';
import { CiphertextError, DecryptionError, InvalidCiphertextError } from '../runtime/errors.js';
import { ensureLoaded, getModule, mem } from './core.js';
import {
  keyArg,
  masterPrivateBytes,
  masterPublicBytes,
  putBytes,
  putHex,
  randomRHex,
  readHex,
  requireLen,
  toBytes,
} from './input.js';

export { ensureLoaded };

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
      masterPrivatePem: encodeSm9PrivateKeyPem(hexToBytes(masterHex)),
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
  // 密文布局 C1(65) || C3(32) || C2(|msg|)，长度随明文增长 —— 按实际长度分配，
  // 并把容量一并交给 wasm 侧校验。曾硬编码 alloc(4096)：明文超过 3999 字节时
  // sm9Encrypt 会写越界、破坏 GC 堆（几轮后 RuntimeError: memory access out of bounds）。
  const ctCap = 65 + 32 + msgB.length;
  const ctP = exports.alloc(ctCap);
  try {
    putBytes(key.bytes, keyP);
    putBytes(idB, idP);
    putBytes(msgB, msgP);
    putBytes(rB, rP);
    const ctLen =
      key.kind === 'public'
        ? exports.sm9EncryptPubOut(keyP, idP, idB.length, msgP, msgB.length, rP, ctP, ctCap)
        : exports.sm9EncryptOut(keyP, idP, idB.length, msgP, msgB.length, rP, ctP, ctCap);
    if (ctLen < 0) throw new Error('sm9: encrypt 失败（密文缓冲容量不足）');
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

// KEM 实现拆到 ./kem.ts，供 hybrid.ts 复用且避免循环依赖。
export { type KemResult, kemDecrypt, kemEncrypt } from './kem.js';

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
      return { ephemeral: bytesToHex(RA) };
    },
    confirm(msg: Sm9ResponderMessage): Sm9InitiatorConfirm {
      const selfR = rA;
      const selfRA = RA;
      if (selfR === null || selfRA === null) throw new Error('sm9.exch: 需先调用 initiate()');
      const RB = readPoint65(msg.ephemeral, 'RB');
      const SB = toBytes(msg.confirm, 'SB');
      requireLen(SB, 32, 'SB', 'cipher');
      const all = exchAll(keB, true, selfIdB, peerIdB, selfR, selfRA, RB, defaultKL);
      if (!ctEq(SB, hexToBytes(all.sb))) throw new Error('sm9.exch: 响应方确认值 S_B 校验失败');
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
      return { ephemeral: bytesToHex(RB), confirm: all.sb };
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
      if (!ctEq(SA, hexToBytes(all.sa))) throw new Error('sm9.exch: 发起方确认值 S_A 校验失败');
      return all.key;
    },
  };
}

// SM9 混合加密（KEM + SM4-GCM）。
export * from './hybrid.js';

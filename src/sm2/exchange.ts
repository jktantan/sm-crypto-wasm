/**
 * SM2 密钥交换协议（GM/T 0003.3-2014 §6.4）。
 *
 * 参考实现：GmSSL `src/sm2_exch.c`（`sm2_key_exchange` /
 * `sm2_key_exchange_compute_confirm`）。协议为三消息流：
 *
 * ```
 *   1. A → B : RA = rA·G                      （发起方临时公钥）
 *   2. B → A : RB = rB·G, S_B                 （响应方临时公钥 + 确认值）
 *   3. A → B : S_A                            （发起方确认值）
 * ```
 *
 * 双方算出同一共享点（A 为发起方，B 为响应方）：
 * ```
 *   U = (x̄(RA)·rA + dA)·(PB + x̄(RB)·RB)
 *     = (x̄(RB)·rB + dB)·(PA + x̄(RA)·RA)
 * ```
 * 共享密钥：`K = KDF(Ux || Uy || ZA || ZB, kLen)`，其中
 * `ZA = Z(IDA, PA)`、`ZB = Z(IDB, PB)`。
 *
 * 确认值（`x̄(x) = 2^127 + (x mod 2^127)`）：
 * ```
 *   h   = SM3(Ux || ZA || ZB || RA || RB)
 *   S_A = SM3(0x03 || Uy || h)，  S_B = SM3(0x02 || Uy || h)
 * ```
 * 两式仅前缀不同 —— `ZA/ZB/RA/RB` 恒按「发起方 A 在前」的协议视角排列，
 * 这与 GmSSL 一致：无论从哪一端调用，`Z`/`R` 的归属都不翻转（见
 * `sm2_exch.c:208-224` 的 `is_initiator` 分支）。
 *
 * 本模块不 import `./index`（避免循环依赖），自行预热 sm2.wasm。
 *
 * spec/plan 对应：plan Task 8；spec §6 API、§12.1 Q2（协议流为 async）。
 */

import { bytesToHex, hexToBytes } from '../runtime/convert.js';
import { loadWasm } from '../runtime/loadWasm.js';
import { randomScalarBelow } from '../runtime/random.js';
import { toPrivateKeyBytes as prepPriv, toPublicKeyBytes as prepPub } from './keyInput.js';

/** SM2 子群阶 n，用于临时私钥采样范围。 */
const N = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');

/** SM2 默认用户标识（GB/T 32918.2 / GM/T 0009）。 */
const DEFAULT_ID = '1234567812345678';

/** 确认值前缀：发起方 S_A 用 0x03，响应方 S_B 用 0x02。 */
const S_PREFIX_INITIATOR = 0x03;
const S_PREFIX_RESPONDER = 0x02;

/** 密钥交换用到的 wasm 导出（sm2.wasm）。 */
interface KexExports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly publicKeyOut: (dPtr: number, outPtr: number) => void;
  readonly computeZIdOut: (
    pubXPtr: number,
    pubYPtr: number,
    idPtr: number,
    idLen: number,
    outPtr: number,
  ) => void;
  readonly kdfOut: (zPtr: number, zLen: number, outPtr: number, klen: number) => number;
  readonly kexComputeUOut: (
    privPtr: number,
    rSelfPtr: number,
    rSelfXYPtr: number,
    peerPubXYPtr: number,
    peerRXYPtr: number,
    outPtr: number,
  ) => number;
  readonly kexConfirmOut: (
    prefix: number,
    uPtr: number,
    zaPtr: number,
    zbPtr: number,
    raXYPtr: number,
    rbXYPtr: number,
    outPtr: number,
  ) => void;
}

interface KexModule {
  exports: KexExports;
  memory: WebAssembly.Memory;
}

function getModule(): KexModule {
  const mod = (globalThis as { __sm2Wasm?: KexModule }).__sm2Wasm;
  if (!mod) throw new Error('sm2.kex: 未初始化，请先 `await ensureLoaded()`。');
  return mod;
}

/** 预热 sm2 wasm（与 `./index` 的 `ensureLoaded` 等价；此处自足以避免循环依赖）。 */
async function ensureSm2Loaded(): Promise<void> {
  const mod = await loadWasm('sm2');
  (globalThis as { __sm2Wasm?: KexModule }).__sm2Wasm = {
    exports: mod.exports as unknown as KexExports,
    memory: mod.memory,
  };
}

// ---------- 输入归一化 ----------

function scalarToBytes(k: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[31 - i] = Number((k >> BigInt(i * 8)) & 0xffn);
  return out;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

function validateKLen(kLen: number): void {
  if (!Number.isInteger(kLen) || kLen <= 0) {
    throw new RangeError('sm2.kex: kLen 必须为正整数');
  }
}

// ---------- wasm 原语封装 ----------

/** 从私钥派生公钥（64 字节 x || y）。 */
function derivePublicKey(d: Uint8Array): Uint8Array {
  const { exports, memory } = getModule();
  const dp = exports.alloc(32);
  const op = exports.alloc(64);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(d, dp);
    exports.publicKeyOut(dp, op);
    return new Uint8Array(memory.buffer, op, 64).slice();
  } finally {
    exports.freeAll();
  }
}

/** Z = SM3(ENTLA || ID || a || b || Gx || Gy || Px || Py)（32 字节）。 */
function computeZ(pub64: Uint8Array, id: string): Uint8Array {
  const idBytes = new TextEncoder().encode(id);
  if (idBytes.length === 0) throw new RangeError('sm2.kex: 用户标识 ID 不能为空');
  const { exports, memory } = getModule();
  const px = exports.alloc(32);
  const py = exports.alloc(32);
  const ip = exports.alloc(idBytes.length);
  const op = exports.alloc(32);
  try {
    // alloc 之后再取视图，避免内存增长使旧视图失效。
    const mem = new Uint8Array(memory.buffer);
    mem.set(pub64.subarray(0, 32), px);
    mem.set(pub64.subarray(32, 64), py);
    mem.set(idBytes, ip);
    exports.computeZIdOut(px, py, ip, idBytes.length, op);
    return new Uint8Array(memory.buffer, op, 32).slice();
  } finally {
    exports.freeAll();
  }
}

/** 共享点 U（65 字节：04 || x || y）。 */
function computeU(
  d: Uint8Array,
  r: Uint8Array,
  rSelf: Uint8Array,
  peerPub: Uint8Array,
  peerR: Uint8Array,
): Uint8Array {
  const { exports, memory } = getModule();
  const dp = exports.alloc(32);
  const rp = exports.alloc(32);
  const rap = exports.alloc(64);
  const pp = exports.alloc(64);
  const rbp = exports.alloc(64);
  const up = exports.alloc(65);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(d, dp);
    mem.set(r, rp);
    mem.set(rSelf, rap);
    mem.set(peerPub, pp);
    mem.set(peerR, rbp);
    const rc = exports.kexComputeUOut(dp, rp, rap, pp, rbp, up);
    if (rc !== 1) throw new Error('sm2.kex: 共享点 U 为无穷远点');
    return new Uint8Array(memory.buffer, up, 65).slice();
  } finally {
    exports.freeAll();
  }
}

/** 确认值 S（32 字节）。 */
function computeConfirm(
  prefix: number,
  u: Uint8Array,
  za: Uint8Array,
  zb: Uint8Array,
  ra: Uint8Array,
  rb: Uint8Array,
): Uint8Array {
  const { exports, memory } = getModule();
  const up = exports.alloc(65);
  const zap = exports.alloc(32);
  const zbp = exports.alloc(32);
  const rap = exports.alloc(64);
  const rbp = exports.alloc(64);
  const op = exports.alloc(32);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(u, up);
    mem.set(za, zap);
    mem.set(zb, zbp);
    mem.set(ra, rap);
    mem.set(rb, rbp);
    exports.kexConfirmOut(prefix, up, zap, zbp, rap, rbp, op);
    return new Uint8Array(memory.buffer, op, 32).slice();
  } finally {
    exports.freeAll();
  }
}

/** 派生共享密钥：K = KDF(Ux || Uy || ZA || ZB, kLen)。 */
function deriveSharedKey(u: Uint8Array, za: Uint8Array, zb: Uint8Array, kLen: number): Uint8Array {
  const { exports, memory } = getModule();
  const zp = exports.alloc(128);
  const op = exports.alloc(kLen);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(u.subarray(1, 65), zp); // Ux || Uy
    mem.set(za, zp + 64);
    mem.set(zb, zp + 96);
    const rc = exports.kdfOut(zp, 128, op, kLen);
    if (rc !== 1) throw new Error('sm2.kex: KDF 输出全 0，请重试');
    return new Uint8Array(memory.buffer, op, kLen).slice();
  } finally {
    exports.freeAll();
  }
}

// ---------- 公共 API ----------

/** 阶段 1 消息：发起方临时公钥 RA。 */
export interface InitiatorMessage {
  /** 65 字节未压缩点 hex（04 || x || y）。 */
  ephemeralPub: string;
}

/** 阶段 2 消息：响应方临时公钥 RB + 确认值 S_B。 */
export interface ResponderMessage extends InitiatorMessage {
  /** 32 字节确认值 S_B 的 hex。 */
  confirm: string;
}

/** 阶段 3 消息：发起方确认值 S_A。 */
export interface InitiatorConfirm {
  /** 32 字节确认值 S_A 的 hex。 */
  confirm: string;
}

/** 密钥交换端点配置。 */
export interface KeyExchangeOptions {
  /** 本端用户标识。默认 `"1234567812345678"`（SM2 默认 ID）。 */
  idSelf?: string;
  /** 对端用户标识。默认 `"1234567812345678"`。 */
  idPeer?: string;
  /**
   * 测试注入：本端临时私钥（32 字节）。默认由宿主 CSPRNG 生成。
   * 仅用于确定性测试；生产环境请勿显式传入。
   */
  ephemeralPrivateKey?: string | Uint8Array;
}

/** 发起方端点。 */
export interface KeyExchangeInitiator {
  /** 阶段 1：生成本端临时公钥 RA。只能调用一次。 */
  initiate(): InitiatorMessage;
  /** 阶段 3：校验响应方 S_B，返回本端确认值 S_A。需先 `initiate()`。 */
  confirm(msg: ResponderMessage): InitiatorConfirm;
  /** 派生共享密钥（hex）。需先 `confirm()`；可选校验传入的 S_A。 */
  getSharedKey(msg?: InitiatorConfirm, kLen?: number): string;
}

/** 响应方端点。 */
export interface KeyExchangeResponder {
  /** 阶段 2：收到 RA，生成 RB 与确认值 S_B。只能调用一次。 */
  respond(msg: InitiatorMessage): ResponderMessage;
  /** 阶段 3：校验发起方 S_A 并派生共享密钥（hex）。需先 `respond()`。 */
  getSharedKey(msg: InitiatorConfirm, kLen?: number): string;
}

/**
 * 构造 SM2 密钥交换发起方（GM/T 0003.3-2014）。
 *
 * @param privA 本端私钥（32 字节 hex / Uint8Array）。
 * @param pubB 对端公钥（64 或 65 字节）。
 * @param options 标识与（测试用）临时私钥。
 */
export async function createExchangeInitiator(
  privA: string | Uint8Array,
  pubB: string | Uint8Array,
  options: KeyExchangeOptions = {},
): Promise<KeyExchangeInitiator> {
  await ensureSm2Loaded();
  const idA = options.idSelf ?? DEFAULT_ID;
  const idB = options.idPeer ?? DEFAULT_ID;
  const dA = prepPriv(privA, 'privA');
  const PB = prepPub(pubB, 'pubB');
  const PA = derivePublicKey(dA);
  const ZA = computeZ(PA, idA);
  const ZB = computeZ(PB, idB);

  let rA: Uint8Array | null = null;
  let RA: Uint8Array | null = null;
  let U: Uint8Array | null = null;
  let SA: Uint8Array | null = null;
  let confirmed = false;

  return {
    initiate(): InitiatorMessage {
      if (rA !== null) throw new Error('sm2.kex: initiate() 只能调用一次');
      rA = options.ephemeralPrivateKey
        ? prepPriv(options.ephemeralPrivateKey, 'rA')
        : scalarToBytes(randomScalarBelow(N));
      RA = derivePublicKey(rA);
      return { ephemeralPub: `04${bytesToHex(RA)}` };
    },

    confirm(msg: ResponderMessage): InitiatorConfirm {
      const selfR = rA;
      const selfRA = RA;
      if (selfR === null || selfRA === null) {
        throw new Error('sm2.kex: 需先调用 initiate()');
      }
      const RB = prepPub(msg.ephemeralPub, 'responder.ephemeralPub');
      const sB = hexToBytes(msg.confirm);
      if (sB.length !== 32) throw new RangeError('sm2.kex: 响应方 confirm 必须为 32 字节');

      const sharedU = computeU(dA, selfR, selfRA, PB, RB);
      const sA = computeConfirm(S_PREFIX_INITIATOR, sharedU, ZA, ZB, selfRA, RB);
      const sBExpected = computeConfirm(S_PREFIX_RESPONDER, sharedU, ZA, ZB, selfRA, RB);
      if (!constantTimeEqual(sB, sBExpected)) {
        throw new Error('sm2.kex: 响应方确认值 S_B 校验失败');
      }
      U = sharedU;
      SA = sA;
      confirmed = true;
      return { confirm: bytesToHex(sA) };
    },

    getSharedKey(msg?: InitiatorConfirm, kLen = 32): string {
      const sharedU = U;
      if (sharedU === null || !confirmed) throw new Error('sm2.kex: 需先完成 confirm()');
      validateKLen(kLen);
      if (msg !== undefined) {
        const provided = hexToBytes(msg.confirm);
        if (SA === null || !constantTimeEqual(provided, SA)) {
          throw new Error('sm2.kex: 发起方确认值 S_A 不一致');
        }
      }
      return bytesToHex(deriveSharedKey(sharedU, ZA, ZB, kLen));
    },
  };
}

/**
 * 构造 SM2 密钥交换响应方（GM/T 0003.3-2014）。
 *
 * @param privB 本端私钥（32 字节）。
 * @param pubA 对端（发起方）公钥（64 或 65 字节）。
 * @param options 标识与（测试用）临时私钥。
 */
export async function createExchangeResponder(
  privB: string | Uint8Array,
  pubA: string | Uint8Array,
  options: KeyExchangeOptions = {},
): Promise<KeyExchangeResponder> {
  await ensureSm2Loaded();
  const idA = options.idPeer ?? DEFAULT_ID; // 对端是发起方 A
  const idB = options.idSelf ?? DEFAULT_ID; // 本端是响应方 B
  const dB = prepPriv(privB, 'privB');
  const PA = prepPub(pubA, 'pubA');
  const PB = derivePublicKey(dB);
  const ZA = computeZ(PA, idA);
  const ZB = computeZ(PB, idB);

  let RA: Uint8Array | null = null;
  let RB: Uint8Array | null = null;
  let U: Uint8Array | null = null;

  return {
    respond(msg: InitiatorMessage): ResponderMessage {
      if (RB !== null) throw new Error('sm2.kex: respond() 只能调用一次');
      const incomingRA = prepPub(msg.ephemeralPub, 'initiator.ephemeralPub');
      const rB = options.ephemeralPrivateKey
        ? prepPriv(options.ephemeralPrivateKey, 'rB')
        : scalarToBytes(randomScalarBelow(N));
      const selfRB = derivePublicKey(rB);

      const sharedU = computeU(dB, rB, selfRB, PA, incomingRA);
      const sB = computeConfirm(S_PREFIX_RESPONDER, sharedU, ZA, ZB, incomingRA, selfRB);

      RA = incomingRA;
      RB = selfRB;
      U = sharedU;
      return { ephemeralPub: `04${bytesToHex(selfRB)}`, confirm: bytesToHex(sB) };
    },

    getSharedKey(msg: InitiatorConfirm, kLen = 32): string {
      const sharedU = U;
      const selfRA = RA;
      const selfRB = RB;
      if (sharedU === null || selfRA === null || selfRB === null) {
        throw new Error('sm2.kex: 需先调用 respond()');
      }
      validateKLen(kLen);
      const sA = hexToBytes(msg.confirm);
      if (sA.length !== 32) throw new RangeError('sm2.kex: 发起方 confirm 必须为 32 字节');
      const sAExpected = computeConfirm(S_PREFIX_INITIATOR, sharedU, ZA, ZB, selfRA, selfRB);
      if (!constantTimeEqual(sA, sAExpected)) {
        throw new Error('sm2.kex: 发起方确认值 S_A 校验失败');
      }
      return bytesToHex(deriveSharedKey(sharedU, ZA, ZB, kLen));
    },
  };
}

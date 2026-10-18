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
 *
 * SM2 key exchange protocol (GM/T 0003.3-2014 §6.4).
 *
 * Reference implementation: GmSSL `src/sm2_exch.c` (`sm2_key_exchange` /
 * `sm2_key_exchange_compute_confirm`). The protocol is a three-message flow:
 *
 * ```
 *   1. A → B : RA = rA·G                      (initiator's ephemeral public key)
 *   2. B → A : RB = rB·G, S_B                 (responder's ephemeral key + confirm value)
 *   3. A → B : S_A                            (initiator's confirm value)
 * ```
 *
 * Both sides compute the same shared point (A is the initiator, B the responder):
 * ```
 *   U = (x̄(RA)·rA + dA)·(PB + x̄(RB)·RB)
 *     = (x̄(RB)·rB + dB)·(PA + x̄(RA)·RA)
 * ```
 * Shared key: `K = KDF(Ux || Uy || ZA || ZB, kLen)`, where
 * `ZA = Z(IDA, PA)` and `ZB = Z(IDB, PB)`.
 *
 * Confirm values (`x̄(x) = 2^127 + (x mod 2^127)`):
 * ```
 *   h   = SM3(Ux || ZA || ZB || RA || RB)
 *   S_A = SM3(0x03 || Uy || h),  S_B = SM3(0x02 || Uy || h)
 * ```
 * The two formulas differ only in the prefix — `ZA/ZB/RA/RB` always follow the protocol
 * view with the initiator A first. This matches GmSSL: whichever side calls, ownership
 * of `Z`/`R` is never flipped (see the `is_initiator` branches at `sm2_exch.c:208-224`).
 *
 * This module does not import `./index` (to avoid a circular dependency) and warms
 * sm2.wasm itself.
 *
 * Spec/plan: plan Task 8; spec §6 API, §12.1 Q2 (the protocol flow is async).
 */

import { bytesToHex, hexToBytes } from '../runtime/convert.js';
import { loadWasm } from '../runtime/loadWasm.js';
import { randomScalarBelow } from '../runtime/random.js';
import { toPrivateKeyBytes as prepPriv, toPublicKeyBytes as prepPub } from './keyInput.js';

/**
 * SM2 子群阶 n，用于临时私钥采样范围。
 *
 * The SM2 subgroup order n, used as the range for sampling the ephemeral private key.
 */
const N = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');

/**
 * SM2 默认用户标识（GB/T 32918.2 / GM/T 0009）。
 *
 * The default SM2 user identity (GB/T 32918.2 / GM/T 0009).
 */
const DEFAULT_ID = '1234567812345678';

/**
 * 确认值前缀：发起方 S_A 用 0x03，响应方 S_B 用 0x02。
 *
 * Confirm-value prefixes: the initiator's S_A uses 0x03, the responder's S_B uses 0x02.
 */
const S_PREFIX_INITIATOR = 0x03;
const S_PREFIX_RESPONDER = 0x02;

/**
 * 密钥交换用到的 wasm 导出（sm2.wasm）。
 *
 * The wasm exports used by key exchange (sm2.wasm).
 */
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

/**
 * 预热后的 sm2 模块句柄：导出表 + 线性内存。
 *
 * Preloaded sm2 module handle: export table plus linear memory.
 */
interface KexModule {
  exports: KexExports;
  memory: WebAssembly.Memory;
}

/**
 * 取已预热的 sm2 模块句柄；未预热时抛错。
 *
 * Fetch the preloaded sm2 module handle; throws when nothing was preloaded.
 */
function getModule(): KexModule {
  const mod = (globalThis as { __sm2Wasm?: KexModule }).__sm2Wasm;
  if (!mod) throw new Error('sm2.kex: 未初始化，请先 `await ensureLoaded()`。');
  return mod;
}

/**
 * 预热 sm2 wasm（与 `./index` 的 `ensureLoaded` 等价；此处自足以避免循环依赖）。
 *
 * Warm up sm2 wasm (equivalent to `ensureLoaded` in `./index`; kept self-contained here
 * to avoid a circular dependency).
 */
async function ensureSm2Loaded(): Promise<void> {
  const mod = await loadWasm('sm2');
  (globalThis as { __sm2Wasm?: KexModule }).__sm2Wasm = {
    exports: mod.exports as unknown as KexExports,
    memory: mod.memory,
  };
}

// ---------- 输入归一化 ----------
// ---------- Input normalisation ----------

/**
 * 把 bigint 标量写成 32 字节大端数组（左侧补零）。
 *
 * Write a bigint scalar as a 32-byte big-endian array (zero-padded on the left).
 */
function scalarToBytes(k: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[31 - i] = Number((k >> BigInt(i * 8)) & 0xffn);
  return out;
}

/**
 * 常量时间字节比较（避免按内容提前返回而泄露确认值）。
 *
 * Constant-time byte comparison (never returns early on content, so no confirm value
 * leaks through timing).
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * 校验 kLen 为正整数。
 *
 * Validate that kLen is a positive integer.
 */
function validateKLen(kLen: number): void {
  if (!Number.isInteger(kLen) || kLen <= 0) {
    throw new RangeError('sm2.kex: kLen 必须为正整数');
  }
}

// ---------- wasm 原语封装 ----------
// ---------- Wrappers around wasm primitives ----------

/**
 * 从私钥派生公钥（64 字节 x || y）。
 *
 * Derive the public key from a private key (64 bytes, x || y).
 */
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

/**
 * Z = SM3(ENTLA || ID || a || b || Gx || Gy || Px || Py)（32 字节）。
 *
 * Z = SM3(ENTLA || ID || a || b || Gx || Gy || Px || Py), 32 bytes.
 */
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
    //
    // Take the view only after allocating, so memory growth cannot invalidate an old view.
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

/**
 * 共享点 U（65 字节：04 || x || y）。
 *
 * The shared point U (65 bytes: 04 || x || y).
 */
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

/**
 * 确认值 S（32 字节）。
 *
 * The confirm value S (32 bytes).
 */
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

/**
 * 派生共享密钥：K = KDF(Ux || Uy || ZA || ZB, kLen)。
 *
 * Derive the shared key: K = KDF(Ux || Uy || ZA || ZB, kLen).
 */
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
// ---------- Public API ----------

/**
 * 阶段 1 消息：发起方临时公钥 RA。
 *
 * Stage 1 message: the initiator's ephemeral public key RA.
 */
export interface InitiatorMessage {
  /**
   * 65 字节未压缩点 hex（04 || x || y）。
   *
   * Hex of the 65-byte uncompressed point (04 || x || y).
   */
  ephemeralPub: string;
}

/**
 * 阶段 2 消息：响应方临时公钥 RB + 确认值 S_B。
 *
 * Stage 2 message: the responder's ephemeral public key RB plus confirm value S_B.
 */
export interface ResponderMessage extends InitiatorMessage {
  /**
   * 32 字节确认值 S_B 的 hex。
   *
   * Hex of the 32-byte confirm value S_B.
   */
  confirm: string;
}

/**
 * 阶段 3 消息：发起方确认值 S_A。
 *
 * Stage 3 message: the initiator's confirm value S_A.
 */
export interface InitiatorConfirm {
  /**
   * 32 字节确认值 S_A 的 hex。
   *
   * Hex of the 32-byte confirm value S_A.
   */
  confirm: string;
}

/**
 * 密钥交换端点配置。
 *
 * Endpoint configuration for key exchange.
 */
export interface KeyExchangeOptions {
  /**
   * 本端用户标识。默认 `"1234567812345678"`（SM2 默认 ID）。
   *
   * The local user identity; defaults to `"1234567812345678"` (the SM2 default ID).
   */
  idSelf?: string;
  /**
   * 对端用户标识。默认 `"1234567812345678"`。
   *
   * The peer user identity; defaults to `"1234567812345678"`.
   */
  idPeer?: string;
  /**
   * 测试注入：本端临时私钥（32 字节）。默认由宿主 CSPRNG 生成。
   * 仅用于确定性测试；生产环境请勿显式传入。
   *
   * Test injection: the local ephemeral private key (32 bytes). Generated from the host
   * CSPRNG by default; meant only for deterministic tests and never to be passed
   * explicitly in production.
   */
  ephemeralPrivateKey?: string | Uint8Array;
}

/**
 * 发起方端点。
 *
 * The initiator endpoint.
 */
export interface KeyExchangeInitiator {
  /**
   * 阶段 1：生成本端临时公钥 RA。只能调用一次。
   *
   * Stage 1: generate the local ephemeral public key RA. May be called only once.
   */
  initiate(): InitiatorMessage;
  /**
   * 阶段 3：校验响应方 S_B，返回本端确认值 S_A。需先 `initiate()`。
   *
   * Stage 3: verify the responder's S_B and return the local confirm value S_A.
   * Requires `initiate()` first.
   */
  confirm(msg: ResponderMessage): InitiatorConfirm;
  /**
   * 派生共享密钥（hex）。需先 `confirm()`；可选校验传入的 S_A。
   *
   * Derive the shared key (hex). Requires `confirm()` first; the passed S_A is
   * optionally verified.
   */
  getSharedKey(msg?: InitiatorConfirm, kLen?: number): string;
}

/**
 * 响应方端点。
 *
 * The responder endpoint.
 */
export interface KeyExchangeResponder {
  /**
   * 阶段 2：收到 RA，生成 RB 与确认值 S_B。只能调用一次。
   *
   * Stage 2: on receiving RA, generate RB and confirm value S_B. May be called only once.
   */
  respond(msg: InitiatorMessage): ResponderMessage;
  /**
   * 阶段 3：校验发起方 S_A 并派生共享密钥（hex）。需先 `respond()`。
   *
   * Stage 3: verify the initiator's S_A and derive the shared key (hex). Requires
   * `respond()` first.
   */
  getSharedKey(msg: InitiatorConfirm, kLen?: number): string;
}

/**
 * 构造 SM2 密钥交换发起方（GM/T 0003.3-2014）。
 *
 * @param privA 本端私钥（32 字节 hex / Uint8Array）。
 * @param pubB 对端公钥（64 或 65 字节）。
 * @param options 标识与（测试用）临时私钥。
 *
 * Create an SM2 key-exchange initiator (GM/T 0003.3-2014).
 *
 * @param privA The local private key (32-byte hex / Uint8Array).
 * @param pubB The peer public key (64 or 65 bytes).
 * @param options Identities and (for tests) an ephemeral private key.
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
 *
 * Create an SM2 key-exchange responder (GM/T 0003.3-2014).
 *
 * @param privB The local private key (32 bytes).
 * @param pubA The peer (initiator) public key (64 or 65 bytes).
 * @param options Identities and (for tests) an ephemeral private key.
 */
export async function createExchangeResponder(
  privB: string | Uint8Array,
  pubA: string | Uint8Array,
  options: KeyExchangeOptions = {},
): Promise<KeyExchangeResponder> {
  await ensureSm2Loaded();
  const idA = options.idPeer ?? DEFAULT_ID; // 对端是发起方 A
  //
  // The peer is initiator A.
  const idB = options.idSelf ?? DEFAULT_ID; // 本端是响应方 B
  //
  // The local side is responder B.
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

// SM2 公钥密码运算（AssemblyScript）：签名/验签、加密/解密、密钥交换。
//
// 标准：GM/T 0003-2012（= GB/T 32918）
// - 签名/验签：GM/T 0003.2
// - 密钥交换：GM/T 0003.3
// - 加密/解密：GM/T 0003.4
// - 推荐曲线：GM/T 0003.5
//
// Z 值：Z = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
//   默认 IDA = "1234567812345678"（GMT 0009）。
//
// 本文件是**纯运算层**：输入输出均为线性内存指针，由 index.ts 的导出包装。
//
// SM2 public-key operations (AssemblyScript): sign/verify, encrypt/decrypt, key exchange.
//
// Standards: GM/T 0003-2012 (= GB/T 32918)
// - sign/verify: GM/T 0003.2
// - key exchange: GM/T 0003.3
// - encrypt/decrypt: GM/T 0003.4
// - recommended curve: GM/T 0003.5
//
// Z value: Z = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
//   default IDA = "1234567812345678" (GMT 0009).
//
// This file is a **pure computation layer**: inputs and outputs are linear-memory
// pointers, wrapped by the exports in index.ts.

import { sm3HashInto } from '../../sm3/assembly/sm3-core';
import {
  U256,
  u256cmp,
  u256fromMemBE,
  u256fromU32,
  u256isZero,
  u256toBytes,
  u256zero,
} from './field';
import { addModN, invModN, mulModN, nArr, subModN } from './modn';
import {
  addPoints,
  isInfinity,
  JPoint,
  lookupCombSlot,
  scalarMul,
  scalarMulG,
  scalarMulGAnd,
  scalarMulPrepared,
  toAffine,
} from './point';

// ---------- 工具 ----------
// ---------- Helpers ----------

/**
 * 从内存读 32 字节大端为 U256。
 *
 * Read 32 big-endian bytes from memory as a U256.
 */
function ld(ptr: usize): U256 {
  return u256fromMemBE(ptr);
}

/**
 * 写 U256 到内存（32 字节大端）。
 *
 * Write a U256 to memory (32 big-endian bytes).
 */
function st(x: U256, ptr: usize): void {
  u256toBytes(x, ptr);
}

/**
 * 拷贝 n 字节。
 *
 * Copy n bytes.
 */
function _memcpy(dst: usize, src: usize, n: usize): void {
  for (let i: usize = 0; i < n; i++) store<u8>(dst + i, load<u8>(src + i));
}

/**
 * 小端 limb 数组 → 32 字节大端。
 *
 * Little-endian limb array → 32 big-endian bytes.
 */
function limbsToBytes(x: U256, out: Uint8Array): void {
  u256toBytes(x, out.dataStart); // TypedArray 必须走 dataStart
  //
  // a TypedArray must go through dataStart
}

// ---------- Z 值 ----------
// ---------- Z value ----------

// 曲线参数（大端字节，用于 Z 计算）。
//
// Curve parameters as big-endian bytes, used for the Z computation.
function curveParamBytes(which: i32): Uint8Array {
  const out = new Uint8Array(32);
  let hex = '';
  if (which === 0)
    hex = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'; // a
  else if (which === 1)
    hex = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'; // b
  else if (which === 2)
    hex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'; // Gx
  else hex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'; // Gy
  for (let i = 0; i < 32; i++) {
    out[i] = <u8>((hexNib(hex.charCodeAt(i * 2)) << 4) | hexNib(hex.charCodeAt(i * 2 + 1)));
  }
  return out;
}

/**
 * 单个 hex 字符 → 4-bit 值（非 hex 字符返回 0）。
 *
 * One hex character → 4-bit value (non-hex characters yield 0).
 */
function hexNib(c: i32): i32 {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return 0;
}

// 默认用户标识 "1234567812345678"（16 字节）。
//
// The default user identity "1234567812345678" (16 bytes).
const DEFAULT_ID = '1234567812345678';

/**
 * 计算 Z 值（32 字节）。写入 outPtr。
 *
 * @param pubXPtr 公钥 x（32 字节大端）。
 * @param pubYPtr 公钥 y。
 * @param idPtr 用户标识字节。
 * @param idLen 用户标识长度。
 * @param outPtr 输出 32 字节。
 *
 * Compute the Z value (32 bytes) and write it to outPtr.
 *
 * @param pubXPtr Public key x (32 big-endian bytes).
 * @param pubYPtr Public key y.
 * @param idPtr User-identity bytes.
 * @param idLen User-identity length.
 * @param outPtr The 32-byte output.
 */
export function computeZ(
  pubXPtr: usize,
  pubYPtr: usize,
  idPtr: usize,
  idLen: usize,
  outPtr: usize,
): void {
  // Z 输入：ENTLA(2) || IDA(idLen) || a(32) || b(32) || Gx(32) || Gy(32) || Px(32) || Py(32)
  //
  // Z input: ENTLA(2) || IDA(idLen) || a(32) || b(32) || Gx(32) || Gy(32) || Px(32) || Py(32)
  const entla = idLen * 8;
  const total = 2 + <i32>idLen + 32 * 6;
  const buf = new StaticArray<u8>(total);
  buf[0] = <u8>((entla >> 8) & 0xff);
  buf[1] = <u8>(entla & 0xff);
  for (let i: usize = 0; i < idLen; i++) buf[2 + <i32>i] = load<u8>(idPtr + i);
  let off = 2 + <i32>idLen;
  for (let w = 0; w < 4; w++) {
    const cp = curveParamBytes(w);
    for (let i = 0; i < 32; i++) buf[off + i] = cp[i];
    off += 32;
  }
  for (let i = 0; i < 32; i++) buf[off + i] = load<u8>(pubXPtr + i);
  off += 32;
  for (let i = 0; i < 32; i++) buf[off + i] = load<u8>(pubYPtr + i);

  sm3HashInto(changetype<usize>(buf), total, outPtr);
}

/**
 * 便捷：用默认 ID 计算 Z。
 *
 * Convenience: compute Z with the default ID.
 */
export function computeZDefaultId(pubXPtr: usize, pubYPtr: usize, outPtr: usize): void {
  const id = new StaticArray<u8>(16);
  for (let i = 0; i < 16; i++) id[i] = <u8>DEFAULT_ID.charCodeAt(i);
  computeZ(pubXPtr, pubYPtr, changetype<usize>(id), 16, outPtr);
}

// ---------- 签名 / 验签 ----------
// ---------- Signature / verification ----------

/**
 * SM2 签名。
 *
 * `(x1, y1) = k·G` 由本函数现算。调用方若已预算好该点（见 `signWithPoint`），
 * 可省掉这次固定基点标量乘 —— 实测它占单次签名的 56%。
 *
 * @param privPtr 私钥 d（32 字节）。
 * @param zPtr Z 值（32 字节）。
 * @param msgPtr 消息。
 * @param msgLen 消息长度。
 * @param kPtr 随机数 k（32 字节，由 JS 侧提供 CSPRNG）。
 * @param rPtr 输出 r（32 字节）。
 * @param sPtr 输出 s（32 字节）。
 * @returns 0 成功；1 表示 k 不合法需要重试。
 *
 * SM2 signature.
 *
 * `(x1, y1) = k·G` is computed here. A caller that already precomputed that point (see
 * `signWithPoint`) can skip this fixed-base scalar multiplication — measured as 56% of
 * one signature.
 *
 * @param privPtr Private key d (32 bytes).
 * @param zPtr The Z value (32 bytes).
 * @param msgPtr The message.
 * @param msgLen Message length.
 * @param kPtr The random k (32 bytes, supplied by the JS-side CSPRNG).
 * @param rPtr Output r (32 bytes).
 * @param sPtr Output s (32 bytes).
 * @returns 0 on success; 1 when k is unusable and a retry is needed.
 */
export function sign(
  privPtr: usize,
  zPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  rPtr: usize,
  sPtr: usize,
): i32 {
  const k = ld(kPtr);
  return signCore(privPtr, zPtr, msgPtr, msgLen, k, toAffine(scalarMulG(k)).x, rPtr, sPtr);
}

/**
 * SM2 签名（`(x1, y1) = k·G` 由调用方预先算好，这里只取 x）。
 *
 * 用于"签名点池"：批量签名时把固定基点标量乘提前摊销，签名的关键路径只剩
 * `e = SM3(Z ‖ M)` 与两条模运算。
 *
 * @param kxPtr 预计算的 `k·G` 的 x 坐标（32 字节）。
 * @returns 0 成功；1 表示 k 不合法需要重试（调用方应换下一个点）。
 *
 * SM2 signature with `(x1, y1) = k·G` precomputed by the caller (only x is used here).
 *
 * Used by the "signature point pool": batch signing amortises the fixed-base scalar
 * multiplication up front, leaving only `e = SM3(Z ‖ M)` and two modular operations on
 * the critical path.
 *
 * @param kxPtr The x coordinate of the precomputed `k·G` (32 bytes).
 * @returns 0 on success; 1 when k is unusable and a retry is needed (the caller should
 *   take the next point).
 */
export function signWithPoint(
  privPtr: usize,
  zPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  kxPtr: usize,
  rPtr: usize,
  sPtr: usize,
): i32 {
  return signCore(privPtr, zPtr, msgPtr, msgLen, ld(kPtr), ld(kxPtr), rPtr, sPtr);
}

/**
 * `sign` / `signWithPoint` 的公共主体；`x1` 即 `(k·G).x`。
 *
 * The shared body of `sign` / `signWithPoint`; `x1` is `(k·G).x`.
 */
function signCore(
  privPtr: usize,
  zPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  k: U256,
  x1: U256,
  rPtr: usize,
  sPtr: usize,
): i32 {
  const d = ld(privPtr);
  const n = nArr();

  // r = (e + x1) mod n，其中 e = SM3(Z || M)
  //
  // r = (e + x1) mod n, where e = SM3(Z || M)
  const e = hashZMsg(zPtr, msgPtr, msgLen);
  const r = addModN(e, x1);
  if (u256isZero(r)) return 1;

  // 检查 r + k == n
  //
  // Check r + k == n
  const rk = addModN(r, k);
  if (u256cmp(rk, n) === 0) return 1;

  // s = ((1+d)^-1 * (k - r*d)) mod n
  //
  // s = ((1+d)^-1 * (k - r*d)) mod n
  const onePlD = addModN(u256fromU32(1), d);
  const inv = invModN(onePlD);
  const rd = mulModN(r, d);
  const kSubRd = subModN(k, rd);
  const s = mulModN(inv, kSubRd);
  if (u256isZero(s)) return 1;

  st(r, rPtr);
  st(s, sPtr);
  return 0;
}

/**
 * SM2 验签。
 *
 * @param pubXPtr 公钥 x。
 * @param pubYPtr 公钥 y。
 * @param zPtr Z 值。
 * @param msgPtr 消息。
 * @param msgLen 长度。
 * @param rPtr r（32 字节）。
 * @param sPtr s（32 字节）。
 * @returns 1 有效，0 无效。
 *
 * SM2 verification.
 *
 * @param pubXPtr Public key x.
 * @param pubYPtr Public key y.
 * @param zPtr The Z value.
 * @param msgPtr The message.
 * @param msgLen Length.
 * @param rPtr r (32 bytes).
 * @param sPtr s (32 bytes).
 * @returns 1 when valid, 0 otherwise.
 */
export function verify(
  pubXPtr: usize,
  pubYPtr: usize,
  zPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  rPtr: usize,
  sPtr: usize,
): i32 {
  const r = ld(rPtr);
  const s = ld(sPtr);
  const n = nArr();
  // r, s ∈ [1, n-1]
  //
  // r, s ∈ [1, n-1]
  if (u256isZero(r) || u256cmp(r, n) >= 0) return 0;
  if (u256isZero(s) || u256cmp(s, n) >= 0) return 0;

  const e = hashZMsg(zPtr, msgPtr, msgLen);
  const t = addModN(r, s);
  if (u256isZero(t)) return 0;

  // (x1, y1) = s·G + t·P（联合 wNAF：两条标量乘共享同一条倍点链）
  //
  // (x1, y1) = s·G + t·P (interleaved wNAF: both scalar multiplications share one
  // doubling chain)
  const pub = new JPoint();
  pub.x = ld(pubXPtr);
  pub.y = ld(pubYPtr);
  pub.z = u256fromU32(1);
  const sum = toAffine(scalarMulGAnd(s, t, pub));
  const R = addModN(e, sum.x);

  return u256cmp(R, r) === 0 ? 1 : 0;
}

/**
 * 内部：SM3(Z || M)。
 *
 * Internal: SM3(Z || M).
 */
function hashZMsg(zPtr: usize, msgPtr: usize, msgLen: usize): U256 {
  const total = 32 + <i32>msgLen;
  const buf = new StaticArray<u8>(total);
  for (let i = 0; i < 32; i++) buf[i] = load<u8>(zPtr + i);
  for (let i: usize = 0; i < msgLen; i++) buf[32 + <i32>i] = load<u8>(msgPtr + i);
  const out = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(buf), total, changetype<usize>(out));
  return u256fromMemBE(changetype<usize>(out));
}

// ---------- KDF（GM/T 0003.4 §5.4.3） ----------
// ---------- KDF, encryption and decryption (GM/T 0003.4 §5.4.3) ----------

/**
 * SM2 加密（GM/T 0003.4）。
 *
 * 输出布局：C1(65: 04||x||y) || C3(32) || C2(klen)  （C1C3C2，默认）
 *
 * @param pubXPtr 公钥 x。
 * @param pubYPtr 公钥 y。
 * @param msgPtr 明文。
 * @param msgLen 明文长度。
 * @param kPtr 随机 k。
 * @param outPtr 输出。
 * @returns 1 成功，0 表示 KDF 全 0 需重试。
 *
 * SM2 encryption (GM/T 0003.4).
 *
 * Output layout: C1(65: 04||x||y) || C3(32) || C2(klen)  (C1C3C2, the default)
 *
 * @param pubXPtr Public key x.
 * @param pubYPtr Public key y.
 * @param msgPtr The plaintext.
 * @param msgLen Plaintext length.
 * @param kPtr The random k.
 * @param outPtr The output.
 * @returns 1 on success, 0 when the KDF output is all zero and a retry is needed.
 */
export function encrypt(
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  outPtr: usize,
): i32 {
  const pub = new JPoint();
  pub.x = ld(pubXPtr);
  pub.y = ld(pubYPtr);
  pub.z = u256fromU32(1);

  const k = ld(kPtr);
  // C1 = k·G（未压缩点）。
  //
  // C1 = k·G (an uncompressed point).
  const c1 = toAffine(scalarMulG(k));
  store<u8>(outPtr, 0x04);
  st(c1.x, outPtr + 1);
  st(c1.y, outPtr + 33);

  // (x2, y2) = k·P。
  //
  // (x2, y2) = k·P.
  const slot = lookupCombSlot(pubXPtr, pubYPtr);
  const kp = toAffine(slot >= 0 ? scalarMulPrepared(k, slot) : scalarMul(k, pub));

  // t = KDF(x2 || y2, msgLen)
  const kdfIn = new StaticArray<u8>(64);
  bytesInto(c1Buffer(kp.x), 0, kdfIn, 0, 32);
  bytesInto(c1Buffer(kp.y), 0, kdfIn, 32, 32);
  const t = new StaticArray<u8>(<i32>msgLen);
  const rc = kdf(changetype<usize>(kdfIn), 64, changetype<usize>(t), msgLen);
  if (rc === 0 && msgLen > 0) return 0;

  // C2 = M xor t
  const c2Off = outPtr + 65 + 32;
  for (let i: usize = 0; i < msgLen; i++) {
    store<u8>(c2Off + i, <u8>(load<u8>(msgPtr + i) ^ t[<i32>i]));
  }

  // C3 = SM3(x2 || M || y2)
  const c3In = new StaticArray<u8>(32 + <i32>msgLen + 32);
  bytesInto(c1Buffer(kp.x), 0, c3In, 0, 32);
  for (let i: usize = 0; i < msgLen; i++) c3In[32 + <i32>i] = load<u8>(msgPtr + i);
  bytesInto(c1Buffer(kp.y), 0, c3In, 32 + <i32>msgLen, 32);
  sm3HashInto(changetype<usize>(c3In), 32 + msgLen + 32, outPtr + 65);
  return 1;
}

/**
 * 把 U256 写到 Uint8Array。
 *
 * Write a U256 into a Uint8Array.
 */
function c1Buffer(x: U256): Uint8Array {
  const b = new Uint8Array(32);
  limbsToBytes(x, b);
  return b;
}

/**
 * 把 src 的 n 字节复制到 StaticArray dst（显式偏移，不走 TS 切片）。
 *
 * Copy n bytes of src into the StaticArray dst (explicit offsets, no TS slicing).
 */
function bytesInto(
  src: Uint8Array,
  srcOff: usize,
  dst: StaticArray<u8>,
  dstOff: i32,
  n: i32,
): void {
  for (let i: usize = 0; i < <usize>n; i++) dst[dstOff + <i32>i] = src[<i32>srcOff + <i32>i];
}

/**
 * SM2 解密。输入 C1(65)||C3(32)||C2，输出明文。
 *
 * @returns 1 成功，0 C3 校验失败。
 *
 * SM2 decryption. Input C1(65)||C3(32)||C2, output the plaintext.
 *
 * @returns 1 on success, 0 when the C3 check fails.
 */
export function decrypt(privPtr: usize, ctPtr: usize, ctLen: usize, outPtr: usize): i32 {
  const d = ld(privPtr);
  // C1 = 04 || x || y
  const c1 = new JPoint();
  c1.x = ld(ctPtr + 1);
  c1.y = ld(ctPtr + 33);
  c1.z = u256fromU32(1);

  const msgLen: usize = ctLen - 97;
  // (x2,y2) = d·C1
  const dp = toAffine(scalarMul(d, c1));

  const kdfIn = new StaticArray<u8>(64);
  bytesInto(c1Buffer(dp.x), 0, kdfIn, 0, 32);
  bytesInto(c1Buffer(dp.y), 0, kdfIn, 32, 32);
  const t = new StaticArray<u8>(<i32>msgLen);
  const rc = kdf(changetype<usize>(kdfIn), 64, changetype<usize>(t), msgLen);
  if (rc === 0 && msgLen > 0) return 0;

  // C2 在偏移 65+32，明文 = C2 xor t
  //
  // C2 sits at offset 65+32; plaintext = C2 xor t
  const c2Off = ctPtr + 97;
  for (let i: usize = 0; i < msgLen; i++) {
    store<u8>(outPtr + i, <u8>(load<u8>(c2Off + i) ^ t[<i32>i]));
  }

  // 校验 C3 = SM3(x2 || M || y2)
  //
  // Verify C3 = SM3(x2 || M || y2)
  const c3In = new StaticArray<u8>(32 + <i32>msgLen + 32);
  bytesInto(c1Buffer(dp.x), 0, c3In, 0, 32);
  for (let i: usize = 0; i < msgLen; i++) c3In[32 + <i32>i] = load<u8>(outPtr + i);
  bytesInto(c1Buffer(dp.y), 0, c3In, 32 + <i32>msgLen, 32);
  const expect = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(c3In), 32 + msgLen + 32, changetype<usize>(expect));
  for (let i = 0; i < 32; i++) {
    if (expect[i] !== load<u8>(ctPtr + 65 + i)) return 0;
  }
  return 1;
}

/**
 * 密钥派生函数 KDF(Z, klen)。
 *
 * @param zPtr 输入字节。
 * @param zLen 长度。
 * @param outPtr 输出 klen 字节。
 * @param klen 输出长度。
 * @returns 1 成功；0 表示输出全 0（调用方需重试）。
 *
 * Key derivation function KDF(Z, klen).
 *
 * @param zPtr Input bytes.
 * @param zLen Input length.
 * @param outPtr The klen-byte output.
 * @param klen Output length.
 * @returns 1 on success; 0 when the output is all zeros (the caller must retry).
 */
export function kdf(zPtr: usize, zLen: usize, outPtr: usize, klen: usize): i32 {
  let ct = 1;
  let written = 0;
  let allZero = true;
  const hashIn = new StaticArray<u8>(<i32>(zLen + 4));
  for (let i: usize = 0; i < zLen; i++) hashIn[<i32>i] = load<u8>(zPtr + i);
  const h = new StaticArray<u8>(32);
  while (<usize>written < klen) {
    hashIn[<i32>zLen] = <u8>((ct >> 24) & 0xff);
    hashIn[<i32>(zLen + 1)] = <u8>((ct >> 16) & 0xff);
    hashIn[<i32>(zLen + 2)] = <u8>((ct >> 8) & 0xff);
    hashIn[<i32>(zLen + 3)] = <u8>(ct & 0xff);
    sm3HashInto(changetype<usize>(hashIn), zLen + 4, changetype<usize>(h));
    const take = min(32, <i32>(klen - <usize>written));
    for (let i = 0; i < take; i++) {
      const v = h[i];
      if (v !== 0) allZero = false;
      store<u8>(outPtr + <usize>written + <usize>i, v);
    }
    written += take;
    ct++;
  }
  return allZero ? 0 : 1;
}

// ---------- 密钥交换（GM/T 0003.3-2014 §6.4，对齐 GmSSL src/sm2_exch.c） ----------
//
// U = t · (P_peer + x̄(R_peer)·R_peer)，其中 t = (x̄(R_self)·r_self + d) mod n。
// x̄(x) = 2^127 + (x mod 2^127)：x 的低 128 位置其最高位为 1，高 128 位清零。
//
// 说明：确认值与共享密钥的协议视角映射（ZA/ZB/RA/RB 恒按「发起方 A 在前」排列，
// S_A/S_B 仅前缀不同）由 TS 门面层负责，本层只做纯运算，与 GmSSL 的
// sm2_key_exchange / sm2_key_exchange_compute_confirm 语义一一对应。
//
// Key exchange (GM/T 0003.3-2014 §6.4, aligned with GmSSL src/sm2_exch.c)
//
// U = t · (P_peer + x̄(R_peer)·R_peer), where t = (x̄(R_self)·r_self + d) mod n.
// x̄(x) = 2^127 + (x mod 2^127): bit 127 of the low 128 bits is set to 1 and the high
// 128 bits are cleared.
//
// Note: the protocol-view mapping of confirm values and shared keys (ZA/ZB/RA/RB always
// ordered with initiator A first; S_A/S_B differ only in the prefix) belongs to the
// TypeScript facade; this layer does pure arithmetic that maps one-to-one onto GmSSL's
// sm2_key_exchange / sm2_key_exchange_compute_confirm.

/**
 * x̄ = 2^127 + (x mod 2^127)。
 *
 * x̄ = 2^127 + (x mod 2^127).
 */
function xHat(x: U256): U256 {
  const r = u256zero();
  store<u32>(r, load<u32>(x));
  store<u32>(r + 4, load<u32>(x + 4));
  store<u32>(r + 8, load<u32>(x + 8));
  store<u32>(r + 12, (load<u32>(x + 12) & 0x7fffffff) | <u32>0x80000000); // bit127 置 1
  //
  // set bit 127
  // r[4..7] 已由 u256zero 清零
  //
  // r[4..7] were already zeroed by u256zero
  return r;
}

/**
 * 从内存读仿射点（x || y，各 32 字节大端）为 Jacobian 点（Z = 1）。
 *
 * Read an affine point from memory (x || y, 32 big-endian bytes each) as a Jacobian
 * point with Z = 1.
 */
function affinePoint(xyPtr: usize): JPoint {
  const p = new JPoint();
  p.x = ld(xyPtr);
  p.y = ld(xyPtr + 32);
  p.z = u256fromU32(1);
  return p;
}

/**
 * 密钥交换共享点 U = t·(P_peer + x̄(R_peer)·R_peer)。
 *
 * @param privPtr 本端静态私钥 d（32 字节）。
 * @param rSelfPtr 本端临时私钥 r（32 字节）。
 * @param rSelfXYPtr 本端临时公钥 R_self（x || y，64 字节）。
 * @param peerPubXYPtr 对端静态公钥 P_peer（x || y，64 字节）。
 * @param peerRXYPtr 对端临时公钥 R_peer（x || y，64 字节）。
 * @param outPtr 输出 U（65 字节：04 || x || y）。
 * @returns 1 成功；0 出现无穷远点（调用方需重试）。
 *
 * Key-exchange shared point U = t·(P_peer + x̄(R_peer)·R_peer).
 *
 * @param privPtr The local static private key d (32 bytes).
 * @param rSelfPtr The local ephemeral private key r (32 bytes).
 * @param rSelfXYPtr The local ephemeral public key R_self (x || y, 64 bytes).
 * @param peerPubXYPtr The peer's static public key P_peer (x || y, 64 bytes).
 * @param peerRXYPtr The peer's ephemeral public key R_peer (x || y, 64 bytes).
 * @param outPtr Output U (65 bytes: 04 || x || y).
 * @returns 1 on success; 0 when the point at infinity appears (the caller must retry).
 */
export function kexComputeU(
  privPtr: usize,
  rSelfPtr: usize,
  rSelfXYPtr: usize,
  peerPubXYPtr: usize,
  peerRXYPtr: usize,
  outPtr: usize,
): i32 {
  const d = ld(privPtr);
  const r = ld(rSelfPtr);
  const xSelf = xHat(ld(rSelfXYPtr));
  const xPeer = xHat(ld(peerRXYPtr));

  // t = (x̄(R_self)·r + d) mod n
  const t = addModN(mulModN(xSelf, r), d);

  // point = P_peer + x̄(R_peer)·R_peer
  const peerPub = affinePoint(peerPubXYPtr);
  const peerR = affinePoint(peerRXYPtr);
  const sum = addPoints(peerPub, scalarMul(xPeer, peerR));
  if (isInfinity(sum)) return 0;

  // U = t · point
  const u = scalarMul(t, sum);
  if (isInfinity(u)) return 0;

  const aff = toAffine(u);
  store<u8>(outPtr, 0x04);
  st(aff.x, outPtr + 1);
  st(aff.y, outPtr + 33);
  return 1;
}

/**
 * 密钥交换确认值 S = SM3(prefix || Uy || SM3(Ux || ZA || ZB || RA || RB))。
 *
 * ZA/ZB/RA/RB 恒按「发起方 A 在前」的协议视角传入；S_A 用 prefix = 0x03、
 * S_B 用 prefix = 0x02（与 GmSSL sm2_key_exchange_compute_confirm 一致）。
 *
 * @param prefix 0x03（发起方）或 0x02（响应方）。
 * @param uPtr U（65 字节：04 || x || y）。
 * @param zaPtr ZA（32 字节）。
 * @param zbPtr ZB（32 字节）。
 * @param raXYPtr RA（x || y，64 字节）。
 * @param rbXYPtr RB（x || y，64 字节）。
 * @param outPtr 输出 S（32 字节）。
 *
 * Key-exchange confirm value S = SM3(prefix || Uy || SM3(Ux || ZA || ZB || RA || RB)).
 *
 * ZA/ZB/RA/RB are always passed in the protocol view with initiator A first; S_A uses
 * prefix = 0x03 and S_B uses prefix = 0x02 (matching GmSSL
 * sm2_key_exchange_compute_confirm).
 *
 * @param prefix 0x03 (initiator) or 0x02 (responder).
 * @param uPtr U (65 bytes: 04 || x || y).
 * @param zaPtr ZA (32 bytes).
 * @param zbPtr ZB (32 bytes).
 * @param raXYPtr RA (x || y, 64 bytes).
 * @param rbXYPtr RB (x || y, 64 bytes).
 * @param outPtr Output S (32 bytes).
 */
export function kexConfirm(
  prefix: i32,
  uPtr: usize,
  zaPtr: usize,
  zbPtr: usize,
  raXYPtr: usize,
  rbXYPtr: usize,
  outPtr: usize,
): void {
  // inner = SM3(Ux || ZA || ZB || RA(64) || RB(64))
  const inner = new StaticArray<u8>(32);
  const innerLen = 32 + 32 + 32 + 64 + 64;
  const buf = new StaticArray<u8>(innerLen);
  let off = 0;
  for (let i = 0; i < 32; i++) buf[off + i] = load<u8>(uPtr + 1 + i); // Ux（跳过 04 前缀）
  //
  // Ux (skipping the 04 prefix)
  off = 32;
  for (let i = 0; i < 32; i++) buf[off + i] = load<u8>(zaPtr + i);
  off = 64;
  for (let i = 0; i < 32; i++) buf[off + i] = load<u8>(zbPtr + i);
  off = 96;
  for (let i = 0; i < 64; i++) buf[off + i] = load<u8>(raXYPtr + i);
  off = 160;
  for (let i = 0; i < 64; i++) buf[off + i] = load<u8>(rbXYPtr + i);
  sm3HashInto(changetype<usize>(buf), innerLen, changetype<usize>(inner));

  // out = SM3(prefix || Uy || inner)
  const out2 = new StaticArray<u8>(1 + 32 + 32);
  out2[0] = <u8>prefix;
  for (let i = 0; i < 32; i++) out2[1 + i] = load<u8>(uPtr + 33 + i); // Uy
  for (let i = 0; i < 32; i++) out2[33 + i] = inner[i];
  sm3HashInto(changetype<usize>(out2), 1 + 32 + 32, outPtr);
}

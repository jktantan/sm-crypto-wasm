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

import {
  U256, u256fromBytes, u256toBytes, u256cmp, u256isZero, u256zero,
  fpAdd, fpSub, fpMul,
  pArr,
} from './field';
import { JPoint, basePoint, scalarMul, scalarMulG, toAffine, infinity, addPoints } from './point';
import { addModN, subModN, mulModN, invModN, nArr } from './modn';
import { sm3HashInto } from './sm3core';

// ---------- 工具 ----------

/** 从内存读 32 字节大端为 U256。 */
function ld(ptr: usize): U256 {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = load<u8>(ptr + i);
  return u256fromBytes(b, 0);
}

/** 写 U256 到内存（32 字节大端）。 */
function st(x: U256, ptr: usize): void {
  u256toBytes(x, ptr);
}

/** 拷贝 k 字节。 */
function memcpy(dst: usize, src: usize, n: usize): void {
  for (let i: usize = 0; i < n; i++) store<u8>(dst + i, load<u8>(src + i));
}

/** 小端 limb 数组 → 32 字节大端。 */
function limbsToBytes(x: U256, out: Uint8Array): void {
  for (let i = 0; i < 8; i++) {
    const v = x[7 - i];
    out[i * 4] = <u8>(v >>> 24);
    out[i * 4 + 1] = <u8>(v >>> 16);
    out[i * 4 + 2] = <u8>(v >>> 8);
    out[i * 4 + 3] = <u8>v;
  }
}

/** 32 字节大端 → U256。 */
function bytesToU256(b: Uint8Array, off: usize): U256 {
  return u256fromBytes(b, off);
}

// ---------- Z 值 ----------

// 曲线参数（大端字节，用于 Z 计算）。
function curveParamBytes(which: i32): Uint8Array {
  const out = new Uint8Array(32);
  let hex = '';
  if (which === 0) hex = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'; // a
  else if (which === 1) hex = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'; // b
  else if (which === 2) hex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'; // Gx
  else hex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'; // Gy
  for (let i = 0; i < 32; i++) {
    out[i] = <u8>((hexNib(hex.charCodeAt(i * 2)) << 4) | hexNib(hex.charCodeAt(i * 2 + 1)));
  }
  return out;
}

function hexNib(c: i32): i32 {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return 0;
}

// 默认用户标识 "1234567812345678"（16 字节）。
const DEFAULT_ID = '1234567812345678';

/**
 * 计算 Z 值（32 字节）。写入 outPtr。
 *
 * @param pubXPtr 公钥 x（32 字节大端）。
 * @param pubYPtr 公钥 y。
 * @param idPtr 用户标识字节。
 * @param idLen 用户标识长度。
 * @param outPtr 输出 32 字节。
 */
export function computeZ(pubXPtr: usize, pubYPtr: usize, idPtr: usize, idLen: usize, outPtr: usize): void {
  // Z 输入：ENTLA(2) || IDA(idLen) || a(32) || b(32) || Gx(32) || Gy(32) || Px(32) || Py(32)
  const entla = idLen * 8;
  const total = 2 + idLen + 32 * 6;
  const buf = new StaticArray<u8>(total);
  buf[0] = <u8>((entla >> 8) & 0xff);
  buf[1] = <u8>(entla & 0xff);
  for (let i: usize = 0; i < idLen; i++) buf[2 + i] = load<u8>(idPtr + i);
  let off = 2 + idLen;
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

/** 便捷：用默认 ID 计算 Z。 */
export function computeZDefaultId(pubXPtr: usize, pubYPtr: usize, outPtr: usize): void {
  const id = new StaticArray<u8>(16);
  for (let i = 0; i < 16; i++) id[i] = <u8>DEFAULT_ID.charCodeAt(i);
  computeZ(pubXPtr, pubYPtr, changetype<usize>(id), 16, outPtr);
}

// ---------- 签名 / 验签 ----------

/**
 * SM2 签名。
 *
 * @param privPtr 私钥 d（32 字节）。
 * @param zPtr Z 值（32 字节）。
 * @param msgPtr 消息。
 * @param msgLen 消息长度。
 * @param kPtr 随机数 k（32 字节，由 JS 侧提供 CSPRNG）。
 * @param rPtr 输出 r（32 字节）。
 * @param sPtr 输出 s（32 字节）。
 * @returns 0 成功；1 表示 k 不合法需要重试。
 */
export function sign(
  privPtr: usize, zPtr: usize, msgPtr: usize, msgLen: usize,
  kPtr: usize, rPtr: usize, sPtr: usize,
): i32 {
  const d = ld(privPtr);
  const k = ld(kPtr);
  const n = nArr();

  // r = (e + x1) mod n，其中 e = SM3(Z || M)，(x1,y1) = k·G
  const e = hashZMsg(zPtr, msgPtr, msgLen);
  const kg = toAffine(scalarMulG(k));
  const x1 = kg.x;
  let r = addModN(e, x1);
  if (u256isZero(r)) return 1;

  // 检查 r + k == n
  const rk = addModN(r, k);
  if (u256cmp(rk, n) === 0) return 1;

  // s = ((1+d)^-1 * (k - r*d)) mod n
  const one = u256zero();
  one[0] = 1;
  const onePlD = addModN(one, d);
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
 */
export function verify(
  pubXPtr: usize, pubYPtr: usize, zPtr: usize, msgPtr: usize, msgLen: usize,
  rPtr: usize, sPtr: usize,
): i32 {
  const r = ld(rPtr);
  const s = ld(sPtr);
  const n = nArr();
  // r, s ∈ [1, n-1]
  if (u256isZero(r) || u256cmp(r, n) >= 0) return 0;
  if (u256isZero(s) || u256cmp(s, n) >= 0) return 0;

  const e = hashZMsg(zPtr, msgPtr, msgLen);
  const t = addModN(r, s);
  if (u256isZero(t)) return 0;

  // (x1, y1) = s·G + t·P
  const pub = new JPoint();
  pub.x = ld(pubXPtr);
  pub.y = ld(pubYPtr);
  const one = u256zero();
  one[0] = 1;
  pub.z = one;

  const sg = scalarMulG(s);
  const tp = scalarMul(t, pub);
  const sum = toAffine(addPointRaw(sg, tp));
  const R = addModN(e, sum.x);

  return u256cmp(R, r) === 0 ? 1 : 0;
}

/** 内部：SM3(Z || M)。 */
function hashZMsg(zPtr: usize, msgPtr: usize, msgLen: usize): U256 {
  const total = 32 + msgLen;
  const buf = new StaticArray<u8>(<i32>total);
  for (let i = 0; i < 32; i++) buf[i] = load<u8>(zPtr + i);
  for (let i: usize = 0; i < msgLen; i++) buf[<i32>(32 + i)] = load<u8>(msgPtr + i);
  const out = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(buf), total, changetype<usize>(out));
  const tmp = new Uint8Array(32);
  for (let i = 0; i < 32; i++) tmp[i] = out[i];
  return bytesToU256(tmp, 0);
}

// point.ts 的 addPoints 已在顶部 import。
function addPointRaw(a: JPoint, b: JPoint): JPoint {
  return addPoints(a, b);
}

// ---------- KDF（GM/T 0003.4 §5.4.3） ----------

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
 */
export function encrypt(
  pubXPtr: usize, pubYPtr: usize, msgPtr: usize, msgLen: usize,
  kPtr: usize, outPtr: usize,
): i32 {
  const pub = new JPoint();
  pub.x = ld(pubXPtr);
  pub.y = ld(pubYPtr);
  const one = u256zero();
  one[0] = 1;
  pub.z = one;

  const k = ld(kPtr);
  // C1 = k·G（未压缩点）。
  const c1 = toAffine(scalarMulG(k));
  store<u8>(outPtr, 0x04);
  st(c1.x, outPtr + 1);
  st(c1.y, outPtr + 33);

  // (x2, y2) = k·P。
  const kp = toAffine(scalarMul(k, pub));

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
  const c3In = new StaticArray<u8>(<i32>(32 + msgLen + 32));
  bytesInto(c1Buffer(kp.x), 0, c3In, 0, 32);
  for (let i: usize = 0; i < msgLen; i++) c3In[<i32>(32 + i)] = load<u8>(msgPtr + i);
  bytesInto(c1Buffer(kp.y), 0, c3In, <i32>(32 + msgLen), 32);
  sm3HashInto(changetype<usize>(c3In), 32 + msgLen + 32, outPtr + 65);
  return 1;
}

/** 把 U256 写到 Uint8Array。 */
function c1Buffer(x: U256): Uint8Array {
  const b = new Uint8Array(32);
  limbsToBytes(x, b);
  return b;
}

function bytesInto(src: Uint8Array, srcOff: usize, dst: StaticArray<u8>, dstOff: i32, n: i32): void {
  for (let i: usize = 0; i < <usize>n; i++) dst[dstOff + <i32>i] = src[srcOff + i];
}

/**
 * SM2 解密。输入 C1(65)||C3(32)||C2，输出明文。
 *
 * @returns 1 成功，0 C3 校验失败。
 */
export function decrypt(
  privPtr: usize, ctPtr: usize, ctLen: usize, outPtr: usize,
): i32 {
  const d = ld(privPtr);
  // C1 = 04 || x || y
  const c1 = new JPoint();
  c1.x = ld(ctPtr + 1);
  c1.y = ld(ctPtr + 33);
  const one = u256zero();
  one[0] = 1;
  c1.z = one;

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
  const c2Off = ctPtr + 97;
  for (let i: usize = 0; i < msgLen; i++) {
    store<u8>(outPtr + i, <u8>(load<u8>(c2Off + i) ^ t[<i32>i]));
  }

  // 校验 C3 = SM3(x2 || M || y2)
  const c3In = new StaticArray<u8>(<i32>(32 + msgLen + 32));
  bytesInto(c1Buffer(dp.x), 0, c3In, 0, 32);
  for (let i: usize = 0; i < msgLen; i++) c3In[<i32>(32 + i)] = load<u8>(outPtr + i);
  bytesInto(c1Buffer(dp.y), 0, c3In, <i32>(32 + msgLen), 32);
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
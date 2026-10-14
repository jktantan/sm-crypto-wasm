// SM9 高层密码运算（AssemblyScript）：密钥派生、签名/验签、加密/解密。
//
// 权威基准：GmSSL C 实现（src/sm9_key.c / sm9_sign.c / sm9_enc.c，GM/T 0044-2016）。
//   H1 = modn_from_hash( SM3(0x01||ID||hid||1) || SM3(0x01||ID||hid||2) )
//   H2 = modn_from_hash( SM3(0x02||Z||1) || SM3(0x02||Z||2) )
//   KDF = SM3(0x02||Z||ct)，ct 从 1 起
//   Fp2→bytes: a1||a0；Fp4: a1||a0；Fp12: a2||a1||a0
//   C1 = 0x04||x||y（65B）；KDF 输入用 C1 的 x||y（64B）
//   C3 = HMAC-SM3(K2, C2)

import { U256, nArr, addModN, mulModN, invModN } from './fp';
import { G1, g1Generator, g1Mul, g1ToAffine, g1Add } from './point';
import { G2, g2Generator, g2Mul, g2ToAffine, g2Add } from './point';
import { Fp2 } from './fp2';
import { Fp4 } from './fp4';
import { Fp12, fp12one, fp12Pow, fp12Mul } from './fp12';
import { sm9Pairing } from './pairing';
import { sm3HashInto } from '../../sm3/assembly/sm3-core';
import {
  u256clone, u256fromU32, u256subRaw, u256addRaw, u256toBytes, u256eq, modSub, bytesMod,
} from '../../common/assembly/field256';

/** 签名私钥派生用的 hid。 */
export const HID_SIGN: u8 = 0x01;
/** 加密私钥派生用的 hid。 */
export const HID_ENC: u8 = 0x03;
/** 密钥交换私钥派生用的 hid（GM/T 0044.3）。 */
export const HID_EXCH: u8 = 0x02;

const HASH1_PREFIX: u8 = 0x01;
const HASH2_PREFIX: u8 = 0x02;

// ---------- H1 / H2 / KDF ----------

/** SM3(prefix || z || ct)，ct 为 4 字节大端；返回 32 字节。 */
function hashPrefixCt(prefix: u8, z: StaticArray<u8>, ct: u32): StaticArray<u8> {
  const n = z.length;
  const buf = new StaticArray<u8>(1 + n + 4);
  buf[0] = prefix;
  for (let i = 0; i < n; i++) buf[1 + i] = z[i];
  const o = 1 + n;
  buf[o] = <u8>(ct >>> 24);
  buf[o + 1] = <u8>(ct >>> 16);
  buf[o + 2] = <u8>(ct >>> 8);
  buf[o + 3] = <u8>ct;
  const out = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(buf), buf.length, changetype<usize>(out));
  return out;
}

/** 40 字节哈希（ha||hb 取前 40 字节）mod (n-1)，再 +1，∈[1,n-1]。 */
function hash40Modn(ha: StaticArray<u8>, hb: StaticArray<u8>): U256 {
  const h = new StaticArray<u8>(40);
  for (let i = 0; i < 32; i++) h[i] = ha[i];
  for (let i = 0; i < 8; i++) h[32 + i] = hb[i];
  const nm1 = u256clone(nArr());
  u256subRaw(nm1, u256fromU32(1));
  const r = bytesMod(h, nm1);
  u256addRaw(r, u256fromU32(1));
  return r;
}

/** H1(id||hid, n)，对齐 GmSSL sm9_z256_hash1。 */
export function hash1(id: StaticArray<u8>, idLen: i32, hid: u8): U256 {
  const z = new StaticArray<u8>(idLen + 1);
  for (let i = 0; i < idLen; i++) z[i] = id[i];
  z[idLen] = hid;
  return hash40Modn(hashPrefixCt(HASH1_PREFIX, z, 1), hashPrefixCt(HASH1_PREFIX, z, 2));
}

/** H2(Z, n)，Z 为任意字节串。 */
export function hash2(z: StaticArray<u8>): U256 {
  return hash40Modn(hashPrefixCt(HASH2_PREFIX, z, 1), hashPrefixCt(HASH2_PREFIX, z, 2));
}

/** SM9 KDF（GM/T 0044 5.4.3），对齐 GmSSL sm3_kdf（无前缀）。 */
export function kdf(z: StaticArray<u8>, klen: i32): StaticArray<u8> {
  const out = new StaticArray<u8>(klen);
  let off = 0;
  let ct: u32 = 1;
  while (off < klen) {
    const buf = new StaticArray<u8>(z.length + 4);
    for (let i = 0; i < z.length; i++) buf[i] = z[i];
    const o = z.length;
    buf[o] = <u8>(ct >>> 24);
    buf[o + 1] = <u8>(ct >>> 16);
    buf[o + 2] = <u8>(ct >>> 8);
    buf[o + 3] = <u8>ct;
    const h = new StaticArray<u8>(32);
    sm3HashInto(changetype<usize>(buf), buf.length, changetype<usize>(h));
    for (let i = 0; i < 32 && off < klen; i++, off++) out[off] = h[i];
    ct++;
  }
  return out;
}

// ---------- 密钥派生 ----------

/** ds = [ks·(H1+ks)^{-1}]P1（G1）。 */
export function signExtractKeyDs(ks: U256, id: StaticArray<u8>, idLen: i32): G1 {
  const h1 = hash1(id, idLen, HID_SIGN);
  const t1 = addModN(h1, ks);
  const t2 = mulModN(ks, invModN(t1));
  return g1Mul(t2, g1Generator());
}

/** t2 = ks·(H1+ks)^{-1} mod n（签名私钥标量）。 */
export function signT2(ks: U256, id: StaticArray<u8>, idLen: i32): U256 {
  const h1 = hash1(id, idLen, HID_SIGN);
  const t1 = addModN(h1, ks);
  return mulModN(ks, invModN(t1));
}

/** de = [ke·(H1(ID||hid)+ke)^{-1}]P2（G2），hid 指定用途。 */
function extractKeyDe(ke: U256, id: StaticArray<u8>, idLen: i32, hid: u8): G2 {
  const h1 = hash1(id, idLen, hid);
  const t1 = addModN(h1, ke);
  const t2 = mulModN(ke, invModN(t1));
  return g2Mul(t2, g2Generator());
}

/** 加密私钥 de = [ke·(H1+ke)^{-1}]P2（hid=0x03）。 */
export function encExtractKeyDe(ke: U256, id: StaticArray<u8>, idLen: i32): G2 {
  return extractKeyDe(ke, id, idLen, HID_ENC);
}

/** 密钥交换私钥 de = [ke·(H1+ke)^{-1}]P2（hid=0x02）。 */
export function exchExtractKeyDe(ke: U256, id: StaticArray<u8>, idLen: i32): G2 {
  return extractKeyDe(ke, id, idLen, HID_EXCH);
}

/** Ppubs = [ks]P2。 */
export function signMasterPublic(ks: U256): G2 {
  return g2Mul(ks, g2Generator());
}

/** Ppube = [ke]P1。 */
export function encMasterPublic(ke: U256): G1 {
  return g1Mul(ke, g1Generator());
}

// ---------- 字节辅助 ----------

function cat2(a: StaticArray<u8>, b: StaticArray<u8>): StaticArray<u8> {
  const r = new StaticArray<u8>(a.length + b.length);
  for (let i = 0; i < a.length; i++) r[i] = a[i];
  for (let i = 0; i < b.length; i++) r[a.length + i] = b[i];
  return r;
}

function cat3(a: StaticArray<u8>, b: StaticArray<u8>, c: StaticArray<u8>): StaticArray<u8> {
  return cat2(cat2(a, b), c);
}

/** 从 32 字节大端（起点 off）读 U256。 */
function u256FromBytesBE(b: StaticArray<u8>, off: i32): U256 {
  const x = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) {
    const o = off + i * 4;
    x[7 - i] = (((<u32>b[o]) << 24) | ((<u32>b[o + 1]) << 16) | ((<u32>b[o + 2]) << 8) | (<u32>b[o + 3])) & 0xffffffff;
  }
  return x;
}

/** Fp2 → 线性内存：a1||a0。 */
function fp2ToBytes(a: Fp2, ptr: usize): void {
  u256toBytes(a[1], ptr);
  u256toBytes(a[0], ptr + 32);
}

/** Fp4 → 线性内存：a1||a0。 */
function fp4ToBytes(a: Fp4, ptr: usize): void {
  fp2ToBytes(a[1], ptr);
  fp2ToBytes(a[0], ptr + 64);
}

/** Fp12 → 384 字节：a2||a1||a0（GmSSL 约定）。 */
function fp12ToBytes(w: Fp12): StaticArray<u8> {
  const r = new StaticArray<u8>(384);
  const p = changetype<usize>(r);
  fp4ToBytes(w[2], p);
  fp4ToBytes(w[1], p + 128);
  fp4ToBytes(w[0], p + 256);
  return r;
}

/** G1 仿射 → 65 字节 0x04||x||y。 */
function g1Compressed(P: G1): StaticArray<u8> {
  const A = g1ToAffine(P);
  const r = new StaticArray<u8>(65);
  r[0] = 0x04;
  u256toBytes(A.X, changetype<usize>(r) + 1);
  u256toBytes(A.Y, changetype<usize>(r) + 33);
  return r;
}

/** G1 仿射 → 64 字节 x||y（KDF 输入用）。 */
function g1xy(P: G1): StaticArray<u8> {
  const A = g1ToAffine(P);
  const r = new StaticArray<u8>(64);
  u256toBytes(A.X, changetype<usize>(r));
  u256toBytes(A.Y, changetype<usize>(r) + 32);
  return r;
}

/** HMAC-SM3（RFC 2104，块 64 字节）。 */
function hmacSm3(key: StaticArray<u8>, msg: StaticArray<u8>): StaticArray<u8> {
  const blockSize = 64;
  const k0 = new StaticArray<u8>(blockSize);
  if (key.length <= blockSize) {
    for (let i = 0; i < key.length; i++) k0[i] = key[i];
  } else {
    const kh = new StaticArray<u8>(32);
    sm3HashInto(changetype<usize>(key), key.length, changetype<usize>(kh));
    for (let i = 0; i < 32; i++) k0[i] = kh[i];
  }
  const ipad = new StaticArray<u8>(blockSize + msg.length);
  for (let i = 0; i < blockSize; i++) ipad[i] = k0[i] ^ 0x36;
  for (let i = 0; i < msg.length; i++) ipad[blockSize + i] = msg[i];
  const inner = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(ipad), ipad.length, changetype<usize>(inner));

  const opad = new StaticArray<u8>(blockSize + 32);
  for (let i = 0; i < blockSize; i++) opad[i] = k0[i] ^ 0x5c;
  for (let i = 0; i < 32; i++) opad[blockSize + i] = inner[i];
  const out = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(opad), opad.length, changetype<usize>(out));
  return out;
}

// ---------- 签名 / 验签（GM/T 0044 第 5 章） ----------

/** g = e(Ppubs, P1)（所有用户共享，可预计算）。 */
export function signG(ppubs: G2): Fp12 {
  return sm9Pairing(g2ToAffine(ppubs), g1Generator());
}

/** SM9 签名。输出 h(32)||Sx(32)||Sy(32)，共 96 字节。 */
export function sm9Sign(ds: G1, ppubs: G2, msgPtr: usize, msgLen: i32, r: U256, outPtr: usize): void {
  const g = signG(ppubs);
  const w = fp12Pow(g, r);
  const m = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) m[i] = load<u8>(msgPtr + i);
  const h = hash2(cat2(m, fp12ToBytes(w)));
  // l = (r - h) mod n
  const l = modSub(r, h, nArr());
  const S = g1ToAffine(g1Mul(l, ds));
  u256toBytes(h, outPtr);
  u256toBytes(S.X, outPtr + 32);
  u256toBytes(S.Y, outPtr + 64);
}

/** SM9 验签。签名 = h(32)||Sx(32)||Sy(32)。通过返回 1。 */
export function sm9Verify(ppubs: G2, idPtr: usize, idLen: i32, msgPtr: usize, msgLen: i32, sigPtr: usize): i32 {
  const h = readU256(sigPtr);
  const S = new G1();
  S.X = readU256(sigPtr + 32);
  S.Y = readU256(sigPtr + 64);
  S.Z = u256fromU32(1);

  const g = signG(ppubs);
  const t = fp12Pow(g, h);

  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);
  const h1 = hash1(id, idLen, HID_SIGN);
  const P2 = g2Add(g2Mul(h1, g2Generator()), ppubs);

  const u = sm9Pairing(g2ToAffine(P2), S);
  const w = fp12Mul(u, t);

  const m = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) m[i] = load<u8>(msgPtr + i);
  const h2 = hash2(cat2(m, fp12ToBytes(w)));
  return u256eq(h2, h) ? 1 : 0;
}

// ---------- 加密 / 解密（GM/T 0044 第 6 章） ----------

/** SM9 加密。输出 C1(65)||C3(32)||C2(msgLen)，返回总长度。 */
export function sm9Encrypt(ppube: G1, idPtr: usize, idLen: i32, msgPtr: usize, msgLen: i32, r: U256, outPtr: usize): i32 {
  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);

  const h1 = hash1(id, idLen, HID_ENC);
  const Q = g1Add(g1Mul(h1, g1Generator()), ppube);
  const g = sm9Pairing(g2Generator(), g1ToAffine(ppube));
  const w = fp12Pow(g, r);

  const C1 = g1Compressed(g1Mul(r, Q));
  const C1xy = g1xy(g1Mul(r, Q));
  const K = kdf(cat3(C1xy, fp12ToBytes(w), id), msgLen + 32);

  const C2 = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) C2[i] = load<u8>(msgPtr + i) ^ K[i];

  const K2 = new StaticArray<u8>(32);
  for (let i = 0; i < 32; i++) K2[i] = K[msgLen + i];
  const C3 = hmacSm3(K2, C2);

  const total = 65 + 32 + msgLen;
  for (let i = 0; i < 65; i++) store<u8>(outPtr + i, C1[i]);
  for (let i = 0; i < 32; i++) store<u8>(outPtr + 65 + i, C3[i]);
  for (let i = 0; i < msgLen; i++) store<u8>(outPtr + 97 + i, C2[i]);
  return total;
}

/** SM9 解密。输入 C1(65)||C3(32)||C2，返回明文长度；校验失败返回 -1。 */
export function sm9Decrypt(de: G2, idPtr: usize, idLen: i32, ctPtr: usize, ctLen: i32, outPtr: usize): i32 {
  if (ctLen < 97) return -1;
  const msgLen = ctLen - 97;

  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);

  const C1 = new StaticArray<u8>(65);
  for (let i = 0; i < 65; i++) C1[i] = load<u8>(ctPtr + i);
  const C3 = new StaticArray<u8>(32);
  for (let i = 0; i < 32; i++) C3[i] = load<u8>(ctPtr + 65 + i);
  const C2 = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) C2[i] = load<u8>(ctPtr + 97 + i);

  if (C1[0] !== 0x04) return -1;

  const P = new G1();
  P.X = u256FromBytesBE(C1, 1);
  P.Y = u256FromBytesBE(C1, 33);
  P.Z = u256fromU32(1);

  const w = sm9Pairing(g2ToAffine(de), P);
  const C1xy = new StaticArray<u8>(64);
  for (let i = 0; i < 64; i++) C1xy[i] = C1[1 + i];
  const K = kdf(cat3(C1xy, fp12ToBytes(w), id), msgLen + 32);

  // GmSSL: C3 = HMAC-SM3(K2, C2)，即对密文算 HMAC（不是对明文）。
  const K2 = new StaticArray<u8>(32);
  for (let i = 0; i < 32; i++) K2[i] = K[msgLen + i];
  const C3p = hmacSm3(K2, C2);

  const C2p = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) C2p[i] = C2[i] ^ K[i];

  for (let i = 0; i < 32; i++) if (C3p[i] !== C3[i]) return -1;

  for (let i = 0; i < msgLen; i++) store<u8>(outPtr + i, C2p[i]);
  return msgLen;
}

/** 从线性内存读 U256（大端 32 字节）。 */
function readU256(ptr: usize): U256 {
  const b = new StaticArray<u8>(32);
  for (let i = 0; i < 32; i++) b[i] = load<u8>(ptr + i);
  return u256FromBytesBE(b, 0);
}

/** 诊断：直接调 sm9 的 kdf（输入为线性内存）。 */
export function kdfOut(zPtr: usize, zLen: i32, kPtr: usize, kLen: i32): void {
  const z = new StaticArray<u8>(zLen);
  for (let i = 0; i < zLen; i++) z[i] = load<u8>(zPtr + i);
  const K = kdf(z, kLen);
  for (let i = 0; i < kLen; i++) store<u8>(kPtr + i, K[i]);
}

// ---------- 密钥封装 KEM（GM/T 0044.4，对齐 GmSSL sm9_enc.c） ----------

function isAllZero(b: StaticArray<u8>, n: i32): bool {
  for (let i = 0; i < n; i++) if (b[i] !== 0) return false;
  return true;
}

/**
 * SM9 KEM 封装：Q = [H1(ID||hid,N)]P1 + Ppube；C1 = [r]Q；
 * w = e(Ppube, P2)^r；K = KDF(C1.x||C1.y || w || ID, klen)。
 *
 * @param ppube 加密主公钥 [ke]P1（G1）。
 * @param r     临时随机数（32 字节）。
 * @returns 1 成功；0 表示 K 全 0（调用方需换 r 重试）。
 */
export function sm9KemEncrypt(
  ppube: G1, idPtr: usize, idLen: i32, r: U256, klen: i32, c1Ptr: usize, kPtr: usize,
): i32 {
  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);

  const h1 = hash1(id, idLen, HID_ENC);
  const Q = g1Add(g1Mul(h1, g1Generator()), ppube);
  const C = g1Mul(r, Q);

  const g = sm9Pairing(g2Generator(), g1ToAffine(ppube));
  const w = fp12Pow(g, r);

  const C1 = g1Compressed(C);
  const C1xy = g1xy(C);
  const K = kdf(cat3(C1xy, fp12ToBytes(w), id), klen);
  if (isAllZero(K, klen)) return 0;

  for (let i = 0; i < 65; i++) store<u8>(c1Ptr + i, C1[i]);
  for (let i = 0; i < klen; i++) store<u8>(kPtr + i, K[i]);
  return 1;
}

/**
 * SM9 KEM 解封装：w = e(de, C1)；K = KDF(C1.x||C1.y || w || ID, klen)。
 *
 * @param de 用户加密私钥 [ke/(H1+ke)]P2（G2）。
 * @returns 1 成功；0 表示 C1 格式错或 K 全 0。
 */
export function sm9KemDecrypt(
  de: G2, idPtr: usize, idLen: i32, c1Ptr: usize, klen: i32, kPtr: usize,
): i32 {
  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);

  const C1 = new StaticArray<u8>(65);
  for (let i = 0; i < 65; i++) C1[i] = load<u8>(c1Ptr + i);
  if (C1[0] !== 0x04) return 0;

  const P = new G1();
  P.X = u256FromBytesBE(C1, 1);
  P.Y = u256FromBytesBE(C1, 33);
  P.Z = u256fromU32(1);

  const w = sm9Pairing(g2ToAffine(de), P);
  const C1xy = new StaticArray<u8>(64);
  for (let i = 0; i < 64; i++) C1xy[i] = C1[1 + i];
  const K = kdf(cat3(C1xy, fp12ToBytes(w), id), klen);
  if (isAllZero(K, klen)) return 0;

  for (let i = 0; i < klen; i++) store<u8>(kPtr + i, K[i]);
  return 1;
}

void fp12one; void g1Add; void g2Add;

// ---------- 密钥交换（GM/T 0044.3，对齐 GmSSL sm9_exch.c） ----------
//
// 双方用各自加密私钥 de（= enc key，见 sm9.h: #define SM9_EXCH_KEY SM9_ENC_KEY）
// 与主公钥 Ppube=[ke]P1：
//   E1 = e(P2, Ppube)^r ；E2 = e(de, peerR) ；G3 = E2^r
//   发起方：G1 = E1, G2 = E2 ；响应方：G1 = E2, G2 = E1
//   K = KDF(IDA||IDB||RA||RB||G1||G2||G3, klen)         （RA/RB 恒按 A 在前）
//   S = SM3(prefix || G1 || SM3(G2 || G3 || IDA || IDB || RA || RB))
//     prefix = 0x83（发起方）/ 0x82（响应方）

/** 从线性内存读 len 字节。 */
function ldBytes(ptr: usize, len: i32): StaticArray<u8> {
  const b = new StaticArray<u8>(len);
  for (let i = 0; i < len; i++) b[i] = load<u8>(ptr + i);
  return b;
}

/** 从 65 字节未压缩点取 64 字节 x||y。 */
function xy64(p65: StaticArray<u8>): StaticArray<u8> {
  const r = new StaticArray<u8>(64);
  for (let i = 0; i < 64; i++) r[i] = p65[1 + i];
  return r;
}

/** 从线性内存读 65 字节未压缩 G1 点（04||x||y）为 G1（Z=1）。 */
function readG1Bytes(ptr: usize): G1 {
  const P = new G1();
  P.X = readU256(ptr + 1);
  P.Y = readU256(ptr + 33);
  P.Z = u256fromU32(1);
  return P;
}

/** 计算 G1/G2/G3 的字节（各 384B），对齐 GmSSL compute_g。 */
function exchComputeG(
  de: G2, ppube: G1, isInitiator: bool, r: U256, peerR: G1,
  g1b: StaticArray<u8>, g2b: StaticArray<u8>, g3b: StaticArray<u8>,
): void {
  const E1 = fp12Pow(sm9Pairing(g2Generator(), g1ToAffine(ppube)), r);
  const E2 = sm9Pairing(g2ToAffine(de), g1ToAffine(peerR));
  const G3v = fp12Pow(E2, r);
  const G1v = isInitiator ? E1 : E2;
  const G2v = isInitiator ? E2 : E1;
  const b1 = fp12ToBytes(G1v);
  const b2 = fp12ToBytes(G2v);
  const b3 = fp12ToBytes(G3v);
  for (let i = 0; i < 384; i++) {
    g1b[i] = b1[i];
    g2b[i] = b2[i];
    g3b[i] = b3[i];
  }
}

/** 生成本端临时点 R = [r](H1(ID_peer||hid,N)·P1 + Ppube)，输出 65B。 */
export function sm9ExchEphemeral(ppube: G1, peerIdPtr: usize, peerIdLen: i32, r: U256, outPtr: usize): void {
  const peerId = ldBytes(peerIdPtr, peerIdLen);
  const h1 = hash1(peerId, peerIdLen, HID_EXCH);
  const Q = g1Add(g1Mul(h1, g1Generator()), ppube);
  const R = g1Compressed(g1Mul(r, Q));
  for (let i = 0; i < 65; i++) store<u8>(outPtr + i, R[i]);
}

/** 密钥交换共享密钥 K = KDF(...)。@returns 1 成功；0 K 全 0。 */
export function sm9ExchKey(
  de: G2, ppube: G1, isInitiator: i32,
  selfIdPtr: usize, selfIdLen: i32, peerIdPtr: usize, peerIdLen: i32,
  r: U256, selfRPtr: usize, peerRPtr: usize, klen: i32, outPtr: usize,
): i32 {
  const selfId = ldBytes(selfIdPtr, selfIdLen);
  const peerId = ldBytes(peerIdPtr, peerIdLen);
  const selfR65 = ldBytes(selfRPtr, 65);
  const peerR65 = ldBytes(peerRPtr, 65);

  const g1b = new StaticArray<u8>(384);
  const g2b = new StaticArray<u8>(384);
  const g3b = new StaticArray<u8>(384);
  const initiator = isInitiator !== 0;
  exchComputeG(de, ppube, initiator, r, readG1Bytes(peerRPtr), g1b, g2b, g3b);

  const idA = initiator ? selfId : peerId;
  const idB = initiator ? peerId : selfId;
  const ra = initiator ? selfR65 : peerR65;
  const rb = initiator ? peerR65 : selfR65;

  const z = cat2(cat2(cat2(cat2(cat2(cat2(idA, idB), xy64(ra)), xy64(rb)), g1b), g2b), g3b);
  const K = kdf(z, klen);
  if (isAllZero(K, klen)) return 0;
  for (let i = 0; i < klen; i++) store<u8>(outPtr + i, K[i]);
  return 1;
}

/** 密钥交换确认值 S = SM3(prefix || G1 || SM3(G2||G3||IDA||IDB||RA||RB))。prefix: 0x83 发起方 / 0x82 响应方。 */
export function sm9ExchConfirm(
  de: G2, ppube: G1, isInitiator: i32,
  selfIdPtr: usize, selfIdLen: i32, peerIdPtr: usize, peerIdLen: i32,
  r: U256, selfRPtr: usize, peerRPtr: usize, prefix: i32, outPtr: usize,
): void {
  const selfId = ldBytes(selfIdPtr, selfIdLen);
  const peerId = ldBytes(peerIdPtr, peerIdLen);
  const selfR65 = ldBytes(selfRPtr, 65);
  const peerR65 = ldBytes(peerRPtr, 65);

  const g1b = new StaticArray<u8>(384);
  const g2b = new StaticArray<u8>(384);
  const g3b = new StaticArray<u8>(384);
  const initiator = isInitiator !== 0;
  exchComputeG(de, ppube, initiator, r, readG1Bytes(peerRPtr), g1b, g2b, g3b);

  const idA = initiator ? selfId : peerId;
  const idB = initiator ? peerId : selfId;
  const ra = initiator ? selfR65 : peerR65;
  const rb = initiator ? peerR65 : selfR65;

  const hashIn = cat2(cat2(cat2(cat2(cat2(g2b, g3b), idA), idB), xy64(ra)), xy64(rb));
  const hash = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(hashIn), hashIn.length, changetype<usize>(hash));

  const pfx = new StaticArray<u8>(1);
  pfx[0] = <u8>prefix;
  const outIn = cat3(pfx, g1b, hash);
  sm3HashInto(changetype<usize>(outIn), outIn.length, outPtr);
}

/**
 * 一次算出 SA(0x83)、SB(0x82) 与共享密钥 K（避免重复 pairing）。
 * @returns 1 成功；0 K 全 0。
 */
export function sm9ExchAll(
  de: G2, ppube: G1, isInitiator: i32,
  selfIdPtr: usize, selfIdLen: i32, peerIdPtr: usize, peerIdLen: i32,
  r: U256, selfRPtr: usize, peerRPtr: usize, klen: i32,
  saPtr: usize, sbPtr: usize, kPtr: usize,
): i32 {
  const selfId = ldBytes(selfIdPtr, selfIdLen);
  const peerId = ldBytes(peerIdPtr, peerIdLen);
  const selfR65 = ldBytes(selfRPtr, 65);
  const peerR65 = ldBytes(peerRPtr, 65);

  const g1b = new StaticArray<u8>(384);
  const g2b = new StaticArray<u8>(384);
  const g3b = new StaticArray<u8>(384);
  const initiator = isInitiator !== 0;
  exchComputeG(de, ppube, initiator, r, readG1Bytes(peerRPtr), g1b, g2b, g3b);

  const idA = initiator ? selfId : peerId;
  const idB = initiator ? peerId : selfId;
  const ra = initiator ? selfR65 : peerR65;
  const rb = initiator ? peerR65 : selfR65;

  const hashIn = cat2(cat2(cat2(cat2(cat2(g2b, g3b), idA), idB), xy64(ra)), xy64(rb));
  const hash = new StaticArray<u8>(32);
  sm3HashInto(changetype<usize>(hashIn), hashIn.length, changetype<usize>(hash));

  const pA = new StaticArray<u8>(1);
  pA[0] = 0x83;
  const pB = new StaticArray<u8>(1);
  pB[0] = 0x82;
  const saIn = cat3(pA, g1b, hash);
  sm3HashInto(changetype<usize>(saIn), saIn.length, saPtr);
  const sbIn = cat3(pB, g1b, hash);
  sm3HashInto(changetype<usize>(sbIn), sbIn.length, sbPtr);

  const z = cat2(cat2(cat2(cat2(cat2(cat2(idA, idB), xy64(ra)), xy64(rb)), g1b), g2b), g3b);
  const K = kdf(z, klen);
  if (isAllZero(K, klen)) return 0;
  for (let i = 0; i < klen; i++) store<u8>(kPtr + i, K[i]);
  return 1;
}
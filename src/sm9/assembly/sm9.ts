// SM9 高层密码运算（AssemblyScript）：密钥派生、签名/验签、加密/解密。
//
// 权威基准：GmSSL C 实现（src/sm9_key.c / sm9_sign.c / sm9_enc.c，GM/T 0044-2016）。
//   H1 = modn_from_hash( SM3(0x01||ID||hid||1) || SM3(0x01||ID||hid||2) )
//   H2 = modn_from_hash( SM3(0x02||Z||1) || SM3(0x02||Z||2) )
//   KDF = SM3(0x02||Z||ct)，ct 从 1 起
//   Fp2→bytes: a1||a0；Fp4: a1||a0；Fp12: a2||a1||a0
//   C1 = 0x04||x||y（65B）；KDF 输入用 C1 的 x||y（64B）
//   C3 = HMAC-SM3(K2, C2)

import {
  bytesMod,
  modSub,
  permAlloc,
  permU256,
  u256addRaw,
  u256clone,
  u256eq,
  u256fromU32,
  u256subRaw,
  u256toBytes,
  u256zero,
} from '../../common/assembly/field256';
import { sm3HashInto } from '../../sm3/assembly/sm3-core';
import { addModN, fpFromMontTo, fpMontOne, fpToMont, invModN, mulModN, nArr, U256 } from './fp';
import { Fp2 } from './fp2';
import { Fp4 } from './fp4';
import { Fp12, fp12Mul, fp12one, fp12Pow } from './fp12';
import { sm9Pairing } from './pairing';
import {
  G1,
  G2,
  g1Add,
  g1Generator,
  g1Mul,
  g1MulG,
  g1ToAffine,
  g2Add,
  g2Generator,
  g2MulG,
  g2ToAffine,
} from './point';

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
  return g1MulG(t2);
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
  return g2MulG(t2);
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
  return g2MulG(ks);
}

/** Ppube = [ke]P1。 */
export function encMasterPublic(ke: U256): G1 {
  return g1MulG(ke);
}

// ---------- 公开配对值缓存 ----------
//
// e(Ppubs, P1) 与 e(P2, Ppube) 只取决于主公钥（公开点），与消息 / 用户无关，
// 但各占一整次 pairing（百毫秒级）。verify / encrypt / KEM 对同一主公钥反复调用时
// 每次都重算。这里按主公钥仿射坐标做 4 槽直接映射缓存——缓存的值是公开点的
// 配对结果，不含任何秘密，缓存只省时间不改变任何安全边界。
// 4 槽：绝大多数应用（1 个 KGC + 少数根密钥）远用不满；满了覆盖最旧槽。

/** signG 缓存槽：key 为 Ppubs 仿射（128 字节），value 为 e(Ppubs, P1)。 */
class SignGCacheSlot {
  keyX1: U256 = 0;
  keyX0: U256 = 0;
  keyY1: U256 = 0;
  keyY0: U256 = 0;
  /** 0 表示空槽（Fp12 现在是指针类型，不能用 null）；非 0 时指向永久区的值。 */
  value: Fp12 = 0;
}

const SIGN_G_CACHE = new StaticArray<SignGCacheSlot>(4);
for (let i = 0; i < 4; i++) SIGN_G_CACHE[i] = new SignGCacheSlot();

function g2FingerprintU(P: G2): u32 {
  let h: u32 = 0x9e3779b9;
  h = (h ^ load<u32>(P.X)) * <u32>0x01000193;
  h = (h ^ load<u32>(P.X + 60)) * <u32>0x01000193;
  h = (h ^ load<u32>(P.Y + 12)) * <u32>0x01000193;
  h = (h ^ load<u32>(P.Y + 32)) * <u32>0x01000193;
  return h;
}

/** 把一个 Fp12（384 字节）深拷贝到永久区（缓存必须跨导出调用存活）。 */
function permFp12(src: Fp12): Fp12 {
  const p = permAlloc(384);
  memory.copy(p, src, 384);
  return p;
}

/** g = e(Ppubs, P1)（带 4 槽缓存；Ppubs 需为仿射）。 */
export function signG(ppubs: G2): Fp12 {
  const a = g2ToAffine(ppubs);
  const slotIdx = g2FingerprintU(a) & 3;
  const slot = SIGN_G_CACHE[slotIdx];
  if (
    slot.value !== 0 &&
    u256eq(slot.keyX1, a.X + 32) &&
    u256eq(slot.keyX0, a.X) &&
    u256eq(slot.keyY1, a.Y + 32) &&
    u256eq(slot.keyY0, a.Y)
  ) {
    return slot.value;
  }
  const g = sm9Pairing(a, g1Generator());
  slot.keyX1 = permU256(a.X + 32);
  slot.keyX0 = permU256(a.X);
  slot.keyY1 = permU256(a.Y + 32);
  slot.keyY0 = permU256(a.Y);
  slot.value = permFp12(g);
  return g;
}

/** encG 缓存槽：key 为 Ppube 仿射（64 字节）。 */
class EncGCacheSlot {
  keyX: U256 = 0;
  keyY: U256 = 0;
  /** 0 表示空槽。 */
  value: Fp12 = 0;
}

const ENC_G_CACHE = new StaticArray<EncGCacheSlot>(4);
for (let i = 0; i < 4; i++) ENC_G_CACHE[i] = new EncGCacheSlot();

function g1FingerprintU(P: G1): u32 {
  let h: u32 = 0x9e3779b9;
  h = (h ^ load<u32>(P.X)) * <u32>0x01000193;
  h = (h ^ load<u32>(P.X + 28)) * <u32>0x01000193;
  h = (h ^ load<u32>(P.Y + 12)) * <u32>0x01000193;
  h = (h ^ load<u32>(P.Y)) * <u32>0x01000193;
  return h;
}

/** g = e(P2, Ppube)（带 4 槽缓存；对应加密 / KEM 里的 e(Ppube, P2) 同一值）。 */
export function encG(ppube: G1): Fp12 {
  const a = g1ToAffine(ppube);
  const slotIdx = g1FingerprintU(a) & 3;
  const slot = ENC_G_CACHE[slotIdx];
  if (slot.value !== 0 && u256eq(slot.keyX, a.X) && u256eq(slot.keyY, a.Y)) {
    return slot.value;
  }
  const g = sm9Pairing(g2Generator(), a);
  slot.keyX = permU256(a.X);
  slot.keyY = permU256(a.Y);
  slot.value = permFp12(g);
  return g;
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
  const x = u256zero();
  const base = changetype<usize>(b) + <usize>off;
  for (let i = 0; i < 8; i++) {
    const o = base + i * 4;
    const v =
      ((<u32>load<u8>(o)) << 24) |
      ((<u32>load<u8>(o + 1)) << 16) |
      ((<u32>load<u8>(o + 2)) << 8) |
      <u32>load<u8>(o + 3);
    store<u32>(x + ((<usize>(7 - i)) << 2), v & 0xffffffff);
  }
  return x;
}

// 转回标准域的字节输出暂存（u256toBytes 只读，顺序调用安全；非重入：这些是叶子）。
const FP_TMP: U256 = u256zero();

/** Fp2 → 线性内存：a1||a0（转回标准域）。 */
function fp2ToBytes(a: Fp2, ptr: usize): void {
  fpFromMontTo(FP_TMP, a + 32);
  u256toBytes(FP_TMP, ptr);
  fpFromMontTo(FP_TMP, a);
  u256toBytes(FP_TMP, ptr + 32);
}

/** Fp4 → 线性内存：a1||a0。 */
function fp4ToBytes(a: Fp4, ptr: usize): void {
  fp2ToBytes(a + 64, ptr);
  fp2ToBytes(a, ptr + 64);
}

/** Fp12 → 384 字节：a2||a1||a0（GmSSL 约定）。 */
function fp12ToBytes(w: Fp12): StaticArray<u8> {
  const r = new StaticArray<u8>(384);
  const p = changetype<usize>(r);
  fp4ToBytes(w + 256, p);
  fp4ToBytes(w + 128, p + 128);
  fp4ToBytes(w, p + 256);
  return r;
}

/** G1 仿射 → 65 字节 0x04||x||y（转回标准域）。 */
function g1Compressed(P: G1): StaticArray<u8> {
  const A = g1ToAffine(P);
  const r = new StaticArray<u8>(65);
  r[0] = 0x04;
  fpFromMontTo(FP_TMP, A.X);
  u256toBytes(FP_TMP, changetype<usize>(r) + 1);
  fpFromMontTo(FP_TMP, A.Y);
  u256toBytes(FP_TMP, changetype<usize>(r) + 33);
  return r;
}

/** G1 仿射 → 64 字节 x||y（KDF 输入用，转回标准域）。 */
function g1xy(P: G1): StaticArray<u8> {
  const A = g1ToAffine(P);
  const r = new StaticArray<u8>(64);
  fpFromMontTo(FP_TMP, A.X);
  u256toBytes(FP_TMP, changetype<usize>(r));
  fpFromMontTo(FP_TMP, A.Y);
  u256toBytes(FP_TMP, changetype<usize>(r) + 32);
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
// signG（带缓存）已上移到「公开配对值缓存」一节。

/** SM9 签名。输出 h(32)||Sx(32)||Sy(32)，共 96 字节。 */
export function sm9Sign(
  ds: G1,
  ppubs: G2,
  msgPtr: usize,
  msgLen: i32,
  r: U256,
  outPtr: usize,
): void {
  const g = signG(ppubs);
  const w = fp12Pow(g, r);
  const m = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) m[i] = load<u8>(msgPtr + i);
  const h = hash2(cat2(m, fp12ToBytes(w)));
  // l = (r - h) mod n
  const l = modSub(r, h, nArr());
  const S = g1ToAffine(g1Mul(l, ds));
  u256toBytes(h, outPtr);
  fpFromMontTo(FP_TMP, S.X);
  u256toBytes(FP_TMP, outPtr + 32);
  fpFromMontTo(FP_TMP, S.Y);
  u256toBytes(FP_TMP, outPtr + 64);
}

/** SM9 验签。签名 = h(32)||Sx(32)||Sy(32)。通过返回 1。 */
export function sm9Verify(
  ppubs: G2,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  sigPtr: usize,
): i32 {
  const h = readU256(sigPtr);
  const S = new G1();
  S.X = fpToMont(readU256(sigPtr + 32));
  S.Y = fpToMont(readU256(sigPtr + 64));
  S.Z = fpMontOne();

  const g = signG(ppubs);
  const t = fp12Pow(g, h);

  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);
  const h1 = hash1(id, idLen, HID_SIGN);
  const P2 = g2Add(g2MulG(h1), ppubs);

  const u = sm9Pairing(g2ToAffine(P2), S);
  const w = fp12Mul(u, t);

  const m = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) m[i] = load<u8>(msgPtr + i);
  const h2 = hash2(cat2(m, fp12ToBytes(w)));
  return u256eq(h2, h) ? 1 : 0;
}

// ---------- 加密 / 解密（GM/T 0044 第 6 章） ----------

/** SM9 加密。输出 C1(65)||C3(32)||C2(msgLen)，返回总长度。 */
export function sm9Encrypt(
  ppube: G1,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  r: U256,
  outPtr: usize,
  outCap: i32,
): i32 {
  // 输出缓冲容量校验：密文 = C1(65) || C3(32) || C2(msgLen)，绝不越界写。
  const total = 65 + 32 + msgLen;
  if (total > outCap) return -1;

  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);

  const h1 = hash1(id, idLen, HID_ENC);
  const Q = g1Add(g1MulG(h1), ppube);
  const g = encG(ppube);
  const w = fp12Pow(g, r);

  const C1 = g1Compressed(g1Mul(r, Q));
  const C1xy = g1xy(g1Mul(r, Q));
  const K = kdf(cat3(C1xy, fp12ToBytes(w), id), msgLen + 32);

  const C2 = new StaticArray<u8>(msgLen);
  for (let i = 0; i < msgLen; i++) C2[i] = load<u8>(msgPtr + i) ^ K[i];

  const K2 = new StaticArray<u8>(32);
  for (let i = 0; i < 32; i++) K2[i] = K[msgLen + i];
  const C3 = hmacSm3(K2, C2);

  for (let i = 0; i < 65; i++) store<u8>(outPtr + i, C1[i]);
  for (let i = 0; i < 32; i++) store<u8>(outPtr + 65 + i, C3[i]);
  for (let i = 0; i < msgLen; i++) store<u8>(outPtr + 97 + i, C2[i]);
  return total;
}

/** SM9 解密。输入 C1(65)||C3(32)||C2，返回明文长度；校验失败返回 -1。 */
export function sm9Decrypt(
  de: G2,
  idPtr: usize,
  idLen: i32,
  ctPtr: usize,
  ctLen: i32,
  outPtr: usize,
): i32 {
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
  P.X = fpToMont(u256FromBytesBE(C1, 1));
  P.Y = fpToMont(u256FromBytesBE(C1, 33));
  P.Z = fpMontOne();

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
  ppube: G1,
  idPtr: usize,
  idLen: i32,
  r: U256,
  klen: i32,
  c1Ptr: usize,
  kPtr: usize,
): i32 {
  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);

  const h1 = hash1(id, idLen, HID_ENC);
  const Q = g1Add(g1MulG(h1), ppube);
  const C = g1Mul(r, Q);

  const g = encG(ppube);
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
  de: G2,
  idPtr: usize,
  idLen: i32,
  c1Ptr: usize,
  klen: i32,
  kPtr: usize,
): i32 {
  const id = new StaticArray<u8>(idLen);
  for (let i = 0; i < idLen; i++) id[i] = load<u8>(idPtr + i);

  const C1 = new StaticArray<u8>(65);
  for (let i = 0; i < 65; i++) C1[i] = load<u8>(c1Ptr + i);
  if (C1[0] !== 0x04) return 0;

  const P = new G1();
  P.X = fpToMont(u256FromBytesBE(C1, 1));
  P.Y = fpToMont(u256FromBytesBE(C1, 33));
  P.Z = fpMontOne();

  const w = sm9Pairing(g2ToAffine(de), P);
  const C1xy = new StaticArray<u8>(64);
  for (let i = 0; i < 64; i++) C1xy[i] = C1[1 + i];
  const K = kdf(cat3(C1xy, fp12ToBytes(w), id), klen);
  if (isAllZero(K, klen)) return 0;

  for (let i = 0; i < klen; i++) store<u8>(kPtr + i, K[i]);
  return 1;
}

void fp12one;
void g1Add;
void g2Add;

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

/** 从线性内存读 65 字节未压缩 G1 点（04||x||y）为 G1（Z=1，坐标转 Montgomery）。 */
function readG1Bytes(ptr: usize): G1 {
  const P = new G1();
  P.X = fpToMont(readU256(ptr + 1));
  P.Y = fpToMont(readU256(ptr + 33));
  P.Z = fpMontOne();
  return P;
}

/** 计算 G1/G2/G3 的字节（各 384B），对齐 GmSSL compute_g。 */
function exchComputeG(
  de: G2,
  ppube: G1,
  isInitiator: bool,
  r: U256,
  peerR: G1,
  g1b: StaticArray<u8>,
  g2b: StaticArray<u8>,
  g3b: StaticArray<u8>,
): void {
  const E1 = fp12Pow(encG(ppube), r);
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
export function sm9ExchEphemeral(
  ppube: G1,
  peerIdPtr: usize,
  peerIdLen: i32,
  r: U256,
  outPtr: usize,
): void {
  const peerId = ldBytes(peerIdPtr, peerIdLen);
  const h1 = hash1(peerId, peerIdLen, HID_EXCH);
  const Q = g1Add(g1MulG(h1), ppube);
  const R = g1Compressed(g1Mul(r, Q));
  for (let i = 0; i < 65; i++) store<u8>(outPtr + i, R[i]);
}

/** 密钥交换共享密钥 K = KDF(...)。@returns 1 成功；0 K 全 0。 */
export function sm9ExchKey(
  de: G2,
  ppube: G1,
  isInitiator: i32,
  selfIdPtr: usize,
  selfIdLen: i32,
  peerIdPtr: usize,
  peerIdLen: i32,
  r: U256,
  selfRPtr: usize,
  peerRPtr: usize,
  klen: i32,
  outPtr: usize,
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
  de: G2,
  ppube: G1,
  isInitiator: i32,
  selfIdPtr: usize,
  selfIdLen: i32,
  peerIdPtr: usize,
  peerIdLen: i32,
  r: U256,
  selfRPtr: usize,
  peerRPtr: usize,
  prefix: i32,
  outPtr: usize,
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
  de: G2,
  ppube: G1,
  isInitiator: i32,
  selfIdPtr: usize,
  selfIdLen: i32,
  peerIdPtr: usize,
  peerIdLen: i32,
  r: U256,
  selfRPtr: usize,
  peerRPtr: usize,
  klen: i32,
  saPtr: usize,
  sbPtr: usize,
  kPtr: usize,
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

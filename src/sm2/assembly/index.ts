// SM2 AssemblyScript 入口。
//
// 当前阶段：仅暴露素数域 Fp 基础运算，用于逐层验证（oracle = Node BigInt）。
// 后续叠加：曲线点运算、标量乘、签名/验签、加密/解密。
//
// 导出：
//   alloc(n) / freeAll()
//   fpAddOut(aPtr, bPtr, outPtr)
//   fpSubOut(aPtr, bPtr, outPtr)
//   fpMulOut(aPtr, bPtr, outPtr)
//   fpInvOut(aPtr, outPtr)
//
// 所有 256-bit 操作数按 32 字节大端读写。

import {
  computeZ,
  computeZDefaultId,
  decrypt,
  encrypt,
  kdf,
  kexComputeU,
  kexConfirm,
  sign,
  verify,
} from './crypto';
import {
  fpAdd,
  fpInv,
  fpMul,
  fpSub,
  mul512Debug,
  reduce512Debug,
  U256,
  u256fromBytes,
  u256toBytes,
} from './field';
import { JPoint, scalarMul, scalarMulG, toAffine } from './point';

const pinned: Array<StaticArray<u8>> = [];

export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

export function freeAll(): void {
  pinned.length = 0;
}

function read(ptr: usize): U256 {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = load<u8>(ptr + i);
  return u256fromBytes(b, 0);
}

export function fpAddOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = fpAdd(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

export function fpSubOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = fpSub(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

export function fpMulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = fpMul(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

export function fpInvOut(aPtr: usize, outPtr: usize): void {
  const r = fpInv(read(aPtr));
  u256toBytes(r, outPtr);
}

/** 调试用：暴露 mul512 的低 512 位（16 limb → 64 字节大端）。 */
export function mul512Out(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = mul512Debug(read(aPtr), read(bPtr));
  for (let i = 0; i < 16; i++) {
    const v = r[15 - i];
    store<u8>(outPtr + i * 4, <u8>(v >>> 24));
    store<u8>(outPtr + i * 4 + 1, <u8>(v >>> 16));
    store<u8>(outPtr + i * 4 + 2, <u8>(v >>> 8));
    store<u8>(outPtr + i * 4 + 3, <u8>v);
  }
}

/** 调试用：仅 reduce512 的包装。 */
export function reduce512Out(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const prod = mul512Debug(read(aPtr), read(bPtr));
  const r = reduce512Debug(prod);
  u256toBytes(r, outPtr);
}

// ---------- 点运算（供 oracle 验证） ----------

/** 标量乘 G，输出仿射坐标 X || Y（64 字节）。 */
export function scalarMulGOut(kPtr: usize, outPtr: usize): void {
  const k = read(kPtr);
  const r = toAffine(scalarMulG(k));
  u256toBytes(r.x, outPtr);
  u256toBytes(r.y, outPtr + 32);
}

/** 标量乘任意点，输出仿射坐标 X || Y（64 字节）。 */
export function scalarMulOut(kPtr: usize, pxPtr: usize, pyPtr: usize, outPtr: usize): void {
  const k = read(kPtr);
  const p = new JPoint();
  p.x = read(pxPtr);
  p.y = read(pyPtr);
  const z = new StaticArray<u32>(8);
  z[0] = 1;
  p.z = z;
  const r = toAffine(scalarMul(k, p));
  u256toBytes(r.x, outPtr);
  u256toBytes(r.y, outPtr + 32);
}

// ---------- 签名 / 验签 / KDF ----------

/** 计算 Z 值（默认 ID）。 */
export function computeZOut(pubXPtr: usize, pubYPtr: usize, outPtr: usize): void {
  computeZDefaultId(pubXPtr, pubYPtr, outPtr);
}

/** SM2 签名：out = r(32) || s(32)。返回 0 成功，1 需重试。 */
export function signOut(
  privPtr: usize,
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  outPtr: usize,
): i32 {
  const z = new StaticArray<u8>(32);
  computeZDefaultId(pubXPtr, pubYPtr, changetype<usize>(z));
  return sign(privPtr, changetype<usize>(z), msgPtr, msgLen, kPtr, outPtr, outPtr + 32);
}

/** SM2 验签。sigPtr = r || s。返回 1 有效，0 无效。 */
export function verifyOut(
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  sigPtr: usize,
): i32 {
  const z = new StaticArray<u8>(32);
  computeZDefaultId(pubXPtr, pubYPtr, changetype<usize>(z));
  return verify(pubXPtr, pubYPtr, changetype<usize>(z), msgPtr, msgLen, sigPtr, sigPtr + 32);
}

/** KDF。返回 1 成功，0 表示输出全 0。 */
export function kdfOut(zPtr: usize, zLen: usize, outPtr: usize, klen: usize): i32 {
  return kdf(zPtr, zLen, outPtr, klen);
}

/** 从私钥 d 计算公钥 (x, y)。 */
export function publicKeyOut(dPtr: usize, outPtr: usize): void {
  const d = read(dPtr);
  const p = toAffine(scalarMulG(d));
  u256toBytes(p.x, outPtr);
  u256toBytes(p.y, outPtr + 32);
}

/** SM2 加密：out = C1(65)||C3(32)||C2。返回 1 成功。 */
export function encryptOut(
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  outPtr: usize,
): i32 {
  return encrypt(pubXPtr, pubYPtr, msgPtr, msgLen, kPtr, outPtr);
}

/** SM2 解密：ctLen = 97 + ml。返回 1 成功（C3 校验过）。 */
export function decryptOut(privPtr: usize, ctPtr: usize, ctLen: usize, outPtr: usize): i32 {
  return decrypt(privPtr, ctPtr, ctLen, outPtr);
}

// ---------- 密钥交换（供 TS 门面调用） ----------

/** 计算 Z 值（自定义 ID）：out = Z(IDA ‖ P)。 */
export function computeZIdOut(
  pubXPtr: usize,
  pubYPtr: usize,
  idPtr: usize,
  idLen: usize,
  outPtr: usize,
): void {
  computeZ(pubXPtr, pubYPtr, idPtr, idLen, outPtr);
}

/**
 * 密钥交换共享点 U（65 字节：04 || x || y）。
 *
 * @param rSelfXYPtr 本端临时公钥 R_self（x || y，64 字节）。
 * @param peerPubXYPtr 对端静态公钥 P_peer（x || y，64 字节）。
 * @param peerRXYPtr 对端临时公钥 R_peer（x || y，64 字节）。
 * @returns 1 成功；0 无穷远点。
 */
export function kexComputeUOut(
  privPtr: usize,
  rSelfPtr: usize,
  rSelfXYPtr: usize,
  peerPubXYPtr: usize,
  peerRXYPtr: usize,
  outPtr: usize,
): i32 {
  return kexComputeU(privPtr, rSelfPtr, rSelfXYPtr, peerPubXYPtr, peerRXYPtr, outPtr);
}

/** 密钥交换确认值 S（32 字节）。prefix：0x03 发起方 / 0x02 响应方。 */
export function kexConfirmOut(
  prefix: i32,
  uPtr: usize,
  zaPtr: usize,
  zbPtr: usize,
  raXYPtr: usize,
  rbXYPtr: usize,
  outPtr: usize,
): void {
  kexConfirm(prefix, uPtr, zaPtr, zbPtr, raXYPtr, rbXYPtr, outPtr);
}

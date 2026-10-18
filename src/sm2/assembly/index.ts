// SM2 AssemblyScript 入口。
//
// 导出以下类别：
// - 内存管理：alloc, freeAll
// - 域与曲线诊断：fpAddOut, fpSubOut, fpMulOut, fpSqrOut, fpInvOut,
//   mul512Out, reduce512Out, scalarMulGOut, scalarMulOut
// - SM2 业务：publicKeyOut, computeZOut, computeZIdOut, signOut,
//   signWithIDOut, signWithPointOut, verifyOut, verifyWithZOut, kdfOut,
//   encryptOut, decryptOut
// - 密钥交换：kexComputeUOut, kexConfirmOut
// - 固定公钥 comb 缓存：prepareCombOut, setCombCapacityOut, clearComb,
//   combSlotKeyOut
//
// 所有 256-bit 操作数按 32 字节大端读写；wasm 内部 limb 使用小端。
//
// SM2 AssemblyScript entry point.
//
// Exports:
// - Memory management: alloc, freeAll
// - Field and curve diagnostics: fpAddOut, fpSubOut, fpMulOut, fpSqrOut,
//   fpInvOut, mul512Out, reduce512Out, scalarMulGOut, scalarMulOut
// - SM2 operations: publicKeyOut, computeZOut, computeZIdOut, signOut,
//   signWithIDOut, signWithPointOut, verifyOut, verifyWithZOut, kdfOut,
//   encryptOut, decryptOut
// - Key exchange: kexComputeUOut, kexConfirmOut
// - Prepared-key comb cache: prepareCombOut, setCombCapacityOut, clearComb,
//   combSlotKeyOut
//
// All 256-bit operands are read/written as 32-byte big-endian; limbs are
// little-endian internally.

import {
  computeZ,
  computeZDefaultId,
  decrypt,
  encrypt,
  kdf,
  kexComputeU,
  kexConfirm,
  sign,
  signWithPoint,
  verify,
} from './crypto';
import {
  fpAdd,
  fpInv,
  fpMul,
  fpSqr,
  fpSub,
  mul512Debug,
  reduce512Debug,
  U256,
  u256fromMemBE,
  u256fromU32,
  u256toBytes,
  arenaRewind,
} from './field';
import {
  JPoint,
  clearPreparedComb,
  combSlotKeyOut as combSlotKey,
  prepareCombFor,
  scalarMul,
  scalarMulG,
  setCombCapacity,
  toAffine,
} from './point';

/**
 * 持住已分配缓冲，防止被 AS GC 回收。
 *
 * Holds every allocated buffer so the AS GC cannot reclaim it.
 */
const pinned: Array<StaticArray<u8>> = [];

/**
 * 从 AS 堆分配 n 字节；重置 arena 并持住缓冲。
 *
 * Allocates n bytes from the AS heap, rewinds the arena, and pins the buffer.
 */
export function alloc(n: i32): usize {
  arenaRewind();
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

/**
 * 释放全部 pinned 缓冲并回退 arena。
 *
 * Releases all pinned buffers and rewinds the arena.
 */
export function freeAll(): void {
  arenaRewind();
  pinned.length = 0;
}

/**
 * 读一个 32 字节大端操作数为 U256（左值）；调用方传入的指针始终指向大端字节。
 *
 * 本文件所有 256-bit 入参 / 出参都是 32 字节大端，因此读写统一走这两个辅助函数。
 *
 * Read one 32-byte big-endian operand as a U256 (rvalue); every pointer handed in by a
 * caller points at big-endian bytes.
 *
 * All 256-bit inputs / outputs in this file are 32-byte big-endian, so reads and writes
 * go through this helper and `u256toBytes`.
 */
function read(ptr: usize): U256 {
  return u256fromMemBE(ptr);
}

/**
 * out = (a + b) mod p（32 字节大端 Fp 元素）。
 *
 * out = (a + b) mod p (32-byte big-endian Fp elements).
 */
export function fpAddOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = fpAdd(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

/**
 * out = (a - b) mod p（32 字节大端 Fp 元素）。
 *
 * out = (a - b) mod p (32-byte big-endian Fp elements).
 */
export function fpSubOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = fpSub(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

/**
 * out = (a * b) mod p（32 字节大端 Fp 元素）。
 *
 * out = (a * b) mod p (32-byte big-endian Fp elements).
 */
export function fpMulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = fpMul(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

/**
 * 诊断：素域平方（走 modSqr 的平方专用路径，与 fpMulOut 的归约一致）。
 *
 * Diagnostic: field squaring (uses modSqr's dedicated squaring path, with the same
 * reduction as fpMulOut).
 */
export function fpSqrOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = fpSqr(read(aPtr));
  u256toBytes(r, outPtr);
}

/**
 * out = a^-1 mod p（32 字节大端 Fp 元素）。
 *
 * out = a^-1 mod p (32-byte big-endian Fp element).
 */
export function fpInvOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = fpInv(read(aPtr));
  u256toBytes(r, outPtr);
}

/**
 * 调试用：暴露 mul512 的低 512 位（16 limb → 64 字节大端）。
 *
 * Debug only: expose the low 512 bits of mul512 (16 limbs → 64 big-endian bytes).
 */
export function mul512Out(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = mul512Debug(read(aPtr), read(bPtr));
  for (let i = 0; i < 16; i++) {
    const v = load<u32>(r + ((<usize>(15 - i)) << 2));
    store<u8>(outPtr + i * 4, <u8>(v >>> 24));
    store<u8>(outPtr + i * 4 + 1, <u8>(v >>> 16));
    store<u8>(outPtr + i * 4 + 2, <u8>(v >>> 8));
    store<u8>(outPtr + i * 4 + 3, <u8>v);
  }
}

/**
 * 调试用：仅 reduce512 的包装。
 *
 * Debug only: a thin wrapper around reduce512.
 */
export function reduce512Out(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  const prod = mul512Debug(read(aPtr), read(bPtr));
  const r = reduce512Debug(prod);
  u256toBytes(r, outPtr);
}

// ---------- 点运算（供 oracle 验证） ----------
// ---------- Point arithmetic (for oracle checks) ----------

/**
 * 标量乘 G，输出仿射坐标 X || Y（64 字节）。
 *
 * Multiply the base point G by a scalar and output the affine coordinates X || Y
 * (64 bytes).
 */
export function scalarMulGOut(kPtr: usize, outPtr: usize): void {
  arenaRewind();
  const k = read(kPtr);
  const r = toAffine(scalarMulG(k));
  u256toBytes(r.x, outPtr);
  u256toBytes(r.y, outPtr + 32);
}

/**
 * 标量乘任意点，输出仿射坐标 X || Y（64 字节）。
 *
 * Multiply an arbitrary point by a scalar and output the affine coordinates X || Y
 * (64 bytes).
 */
export function scalarMulOut(kPtr: usize, pxPtr: usize, pyPtr: usize, outPtr: usize): void {
  arenaRewind();
  const k = read(kPtr);
  const p = new JPoint();
  p.x = read(pxPtr);
  p.y = read(pyPtr);
  p.z = u256fromU32(1);
  const r = toAffine(scalarMul(k, p));
  u256toBytes(r.x, outPtr);
  u256toBytes(r.y, outPtr + 32);
}

// ---------- 签名 / 验签 / KDF ----------
// ---------- Signature / verification / KDF ----------

/**
 * 计算 Z 值（默认 ID）。
 *
 * Compute the Z value with the default ID.
 */
export function computeZOut(pubXPtr: usize, pubYPtr: usize, outPtr: usize): void {
  arenaRewind();
  computeZDefaultId(pubXPtr, pubYPtr, outPtr);
}

/**
 * SM2 签名：out = r(32) || s(32)。返回 0 成功，1 需重试。
 *
 * SM2 signature: out = r(32) || s(32). Returns 0 on success, 1 when a retry is needed.
 */
export function signOut(
  privPtr: usize,
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  outPtr: usize,
): i32 {
  arenaRewind();
  const z = new StaticArray<u8>(32);
  computeZDefaultId(pubXPtr, pubYPtr, changetype<usize>(z));
  return sign(privPtr, changetype<usize>(z), msgPtr, msgLen, kPtr, outPtr, outPtr + 32);
}

/**
 * SM2 签名（自定义用户标识）：out = r(32) || s(32)。返回 0 成功，1 需重试。
 *
 * 供 X.509 签发使用：OpenSSL 的 X.509 路径默认使用空标识，GM/T 证书使用
 * `1234567812345678`，因此需要把用户标识作为显式参数。
 *
 * SM2 signature with a custom user identity: out = r(32) || s(32). Returns 0 on success,
 * 1 when a retry is needed.
 *
 * Needed by X.509 issuance: OpenSSL's X.509 path uses an empty identity by default while
 * GM/T certificates use `1234567812345678`, so the user identity must be an explicit
 * parameter.
 */
export function signWithIDOut(
  privPtr: usize,
  pubXPtr: usize,
  pubYPtr: usize,
  idPtr: usize,
  idLen: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  outPtr: usize,
): i32 {
  arenaRewind();
  const z = new StaticArray<u8>(32);
  computeZ(pubXPtr, pubYPtr, idPtr, idLen, changetype<usize>(z));
  return sign(privPtr, changetype<usize>(z), msgPtr, msgLen, kPtr, outPtr, outPtr + 32);
}

/**
 * SM2 签名（使用调用方预先算好的 `k·G`）：out = r(32) || s(32)。
 *
 * 与 `signOut` 的唯一区别：不再自己做固定基点标量乘（实测占单次签名的 56%），
 * 改由调用方通过 `scalarMulGOut` 预算 —— 这是"签名点池"的底座。
 *
 * @param kxPtr 预计算的 `k·G` 的 x 坐标（32 字节）。
 * @returns 0 成功，1 需重试（调用方应换下一个点）。
 *
 * SM2 signature using a `k·G` precomputed by the caller: out = r(32) || s(32).
 *
 * The only difference from `signOut` is that it does not perform the fixed-base scalar
 * multiplication itself (measured as 56% of one signature); the caller precomputes it
 * through `scalarMulGOut` — this is the foundation of the "signature point pool".
 *
 * @param kxPtr The x coordinate of the precomputed `k·G` (32 bytes).
 * @returns 0 on success, 1 when a retry is needed (the caller should take the next point).
 */
export function signWithPointOut(
  privPtr: usize,
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  kxPtr: usize,
  outPtr: usize,
): i32 {
  arenaRewind();
  const z = new StaticArray<u8>(32);
  computeZDefaultId(pubXPtr, pubYPtr, changetype<usize>(z));
  return signWithPoint(
    privPtr,
    changetype<usize>(z),
    msgPtr,
    msgLen,
    kPtr,
    kxPtr,
    outPtr,
    outPtr + 32,
  );
}

/**
 * SM2 验签。sigPtr = r || s。返回 1 有效，0 无效。
 *
 * SM2 verification. sigPtr = r || s. Returns 1 when valid, 0 otherwise.
 */
export function verifyOut(
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  sigPtr: usize,
): i32 {
  arenaRewind();
  const z = new StaticArray<u8>(32);
  computeZDefaultId(pubXPtr, pubYPtr, changetype<usize>(z));
  return verify(pubXPtr, pubYPtr, changetype<usize>(z), msgPtr, msgLen, sigPtr, sigPtr + 32);
}

/**
 * SM2 验签（调用方提供预计算的 Z 值）。sigPtr = r || s。返回 1 有效，0 无效。
 *
 * 供 X.509 验证使用：证书签名的用户标识可能是 GM/T 默认值，也可能是
 * OpenSSL X.509 路径使用的空标识，调用方用 `computeZIdOut` 算好 Z 再调用本函数。
 *
 * SM2 verification with a caller-supplied Z value. sigPtr = r || s. Returns 1 when valid,
 * 0 otherwise.
 *
 * Needed by X.509 verification: the user identity behind a certificate signature may be
 * the GM/T default or the empty identity used by OpenSSL's X.509 path; the caller
 * computes Z with `computeZIdOut` and then calls this function.
 */
export function verifyWithZOut(
  pubXPtr: usize,
  pubYPtr: usize,
  zPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  sigPtr: usize,
): i32 {
  arenaRewind();
  return verify(pubXPtr, pubYPtr, zPtr, msgPtr, msgLen, sigPtr, sigPtr + 32);
}

/**
 * KDF。返回 1 成功，0 表示输出全 0。
 *
 * The KDF. Returns 1 on success, 0 when the output is all zeros.
 */
export function kdfOut(zPtr: usize, zLen: usize, outPtr: usize, klen: usize): i32 {
  arenaRewind();
  return kdf(zPtr, zLen, outPtr, klen);
}

/**
 * 从私钥 d 计算公钥 (x, y)。
 *
 * Compute the public key (x, y) from the private key d.
 */
export function publicKeyOut(dPtr: usize, outPtr: usize): void {
  arenaRewind();
  const d = read(dPtr);
  const p = toAffine(scalarMulG(d));
  u256toBytes(p.x, outPtr);
  u256toBytes(p.y, outPtr + 32);
}

/**
 * SM2 加密：out = C1(65)||C3(32)||C2。返回 1 成功。
 *
 * SM2 encryption: out = C1(65)||C3(32)||C2. Returns 1 on success.
 */
export function encryptOut(
  pubXPtr: usize,
  pubYPtr: usize,
  msgPtr: usize,
  msgLen: usize,
  kPtr: usize,
  outPtr: usize,
): i32 {
  arenaRewind();
  return encrypt(pubXPtr, pubYPtr, msgPtr, msgLen, kPtr, outPtr);
}

/**
 * SM2 解密：ctLen = 97 + ml。返回 1 成功（C3 校验过）。
 *
 * SM2 decryption: ctLen = 97 + ml. Returns 1 on success (the C3 check passed).
 */
export function decryptOut(privPtr: usize, ctPtr: usize, ctLen: usize, outPtr: usize): i32 {
  arenaRewind();
  return decrypt(privPtr, ctPtr, ctLen, outPtr);
}

// ---------- 密钥交换（供 TS 门面调用） ----------
// ---------- Key exchange (called by the TypeScript facade) ----------

/**
 * 计算 Z 值（自定义 ID）：out = Z(IDA ‖ P)。
 *
 * Compute the Z value with a custom ID: out = Z(IDA ‖ P).
 */
export function computeZIdOut(
  pubXPtr: usize,
  pubYPtr: usize,
  idPtr: usize,
  idLen: usize,
  outPtr: usize,
): void {
  arenaRewind();
  computeZ(pubXPtr, pubYPtr, idPtr, idLen, outPtr);
}

/**
 * 密钥交换共享点 U（65 字节：04 || x || y）。
 *
 * @param rSelfXYPtr 本端临时公钥 R_self（x || y，64 字节）。
 * @param peerPubXYPtr 对端静态公钥 P_peer（x || y，64 字节）。
 * @param peerRXYPtr 对端临时公钥 R_peer（x || y，64 字节）。
 * @returns 1 成功；0 无穷远点。
 *
 * Key-exchange shared point U (65 bytes: 04 || x || y).
 *
 * @param rSelfXYPtr The local ephemeral public key R_self (x || y, 64 bytes).
 * @param peerPubXYPtr The peer's static public key P_peer (x || y, 64 bytes).
 * @param peerRXYPtr The peer's ephemeral public key R_peer (x || y, 64 bytes).
 * @returns 1 on success; 0 when the result is the point at infinity.
 */
export function kexComputeUOut(
  privPtr: usize,
  rSelfPtr: usize,
  rSelfXYPtr: usize,
  peerPubXYPtr: usize,
  peerRXYPtr: usize,
  outPtr: usize,
): i32 {
  arenaRewind();
  return kexComputeU(privPtr, rSelfPtr, rSelfXYPtr, peerPubXYPtr, peerRXYPtr, outPtr);
}

/**
 * 密钥交换确认值 S（32 字节）。prefix：0x03 发起方 / 0x02 响应方。
 *
 * Key-exchange confirm value S (32 bytes). prefix: 0x03 initiator / 0x02 responder.
 */
export function kexConfirmOut(
  prefix: i32,
  uPtr: usize,
  zaPtr: usize,
  zbPtr: usize,
  raXYPtr: usize,
  rbXYPtr: usize,
  outPtr: usize,
): void {
  arenaRewind();
  kexConfirm(prefix, uPtr, zaPtr, zbPtr, raXYPtr, rbXYPtr, outPtr);
}

/**
 * 为固定公钥构建 comb 表（多槽 LRU）。返回槽索引。
 *
 * Build a comb table for a fixed public key (multi-slot LRU). Returns the slot index.
 */
export function prepareCombOut(pubXPtr: usize, pubYPtr: usize, capacity: i32): i32 {
  arenaRewind();
  setCombCapacity(capacity);
  return prepareCombFor(pubXPtr, pubYPtr);
}

/**
 * 设置可用槽数（1..8）。
 *
 * Set the number of usable slots (1..8).
 */
export function setCombCapacityOut(capacity: i32): void {
  setCombCapacity(capacity);
}

/**
 * 清空所有槽（encrypt 回退到 wNAF）。
 *
 * Clear every slot (encrypt then falls back to wNAF).
 */
export function clearComb(): void {
  clearPreparedComb();
}

/**
 * 读某槽的公钥指纹（64 字节 x||y）；槽无效返回 0。
 *
 * Read a slot's public-key fingerprint (64 bytes x||y); returns 0 for an invalid slot.
 */
export function combSlotKeyOut(slot: i32, outPtr: usize): i32 {
  arenaRewind();
  return combSlotKey(slot, outPtr);
}

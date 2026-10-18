// SM9 AssemblyScript 入口。
//
// 分层实现（对齐 GmSSL 官方 view/SM9.js）：
//   Fp → Fp2 → Fp4 → Fp12 → G1/G2 → pairing → final exponent
//   → sign / encrypt / KEM / key exchange.
//
// 导出：
// - 内存管理：alloc, freeAll
// - 域与曲线诊断：fp2*, fp4*, fp12*, g1*, g2*, pairingOut, tangentOut,
//   lineOut, twistAutoOut, finalExpOut, millerOut, pairingTraceOut,
//   g2OpsOut, lineJacOut
// - 业务：signDsOut, encDeOut, sm9SignOut, sm9VerifyOut, sm9EncryptOut,
//   sm9DecryptOut, sm9KemEncryptOut, sm9KemEncryptPubOut, sm9KemDecryptOut,
//   sm9ExchEphemeralOut, sm9ExchKeyOut, sm9ExchConfirmOut, sm9ExchAllOut,
//   hash1Out, signT2Out
//
// Fp2 / Fp4 / Fp12 的输入输出为各分量 32 字节大端拼接。
//
// SM9 AssemblyScript entry point.
//
// Layered implementation, aligned with GmSSL's view/SM9.js:
//   Fp → Fp2 → Fp4 → Fp12 → G1/G2 → pairing → final exponent
//   → sign / encrypt / KEM / key exchange.
//
// Exports:
// - Memory management: alloc, freeAll
// - Field and curve diagnostics: fp2*, fp4*, fp12*, g1*, g2*, pairingOut,
//   tangentOut, lineOut, twistAutoOut, finalExpOut, millerOut,
//   pairingTraceOut, g2OpsOut, lineJacOut
// - Operations: signDsOut, encDeOut, sm9SignOut, sm9VerifyOut, sm9EncryptOut,
//   sm9DecryptOut, sm9KemEncryptOut, sm9KemEncryptPubOut, sm9KemDecryptOut,
//   sm9ExchEphemeralOut, sm9ExchKeyOut, sm9ExchConfirmOut, sm9ExchAllOut,
//   hash1Out, signT2Out
//
// Fp2 / Fp4 / Fp12 inputs and outputs are concatenated 32-byte big-endian components.

import {
  arenaAlloc,
  arenaRewind,
  u256fromMemBE,
  u256fromU32,
  u256toBytes,
  u256zero,
} from '../../common/assembly/field256';
import { fpFromMontTo, fpMontOne, fpToMont, fpToMontTo, U256 } from './fp';
import { Fp2, fp2Inv, fp2Mul, fp2one, fp2Sqr, fp2set, fp2zero } from './fp2';
import { Fp4, fp4Inv, fp4Mul, fp4Sqr, fp4zero } from './fp4';
import { Fp12, fp12Inv, fp12Mul, fp12Pow, fp12Sqr, fp12zero } from './fp12';
import {
  evalGLine,
  evalGTangent,
  finalExponent,
  millerLoop,
  millerStepF,
  millerStepT,
  sm9Pairing,
  sqrCycSelfTest,
  twistNegPi2,
  twistPi1,
  twistPi2,
} from './pairing';
import {
  G1,
  G2,
  g1Add,
  g1Generator,
  g1MulG,
  g1ToAffine,
  g2Add,
  g2AddFull,
  g2Double,
  g2Generator,
  g2MulG,
  g2ToAffine,
} from './point';
import {
  encExtractKeyDe,
  encMasterPublic,
  exchExtractKeyDe,
  hash1,
  signExtractKeyDs,
  signMasterPublic,
  signT2,
  sm9Decrypt,
  sm9Encrypt,
  sm9ExchAll,
  sm9ExchConfirm,
  sm9ExchEphemeral,
  sm9ExchKey,
  sm9KemDecrypt,
  sm9KemEncrypt,
  sm9Sign,
  sm9Verify,
} from './sm9';

// 导出缓冲区列表（保证 alloc 出来的 StaticArray 不被 GC 回收）。
//
// List of exported buffers (keeps the StaticArrays handed out by alloc alive).
const pinned: Array<StaticArray<u8>> = [];

/**
 * 从 AS 堆分配 n 字节并重置 arena。
 *
 * Allocates n bytes from the AS heap and rewinds the arena.
 */
export function alloc(n: i32): usize {
  arenaRewind();
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

/**
 * 释放全部缓冲并回退 arena。
 *
 * Releases all buffers and rewinds the arena.
 */
export function freeAll(): void {
  arenaRewind();
  pinned.length = 0;
}

// 转回标准域的字节输出暂存（u256toBytes 只读，顺序调用安全；非重入：这些是叶子）。
//
// Scratch for byte output after converting back to the standard domain
// (u256toBytes only reads it, so sequential calls are safe; not re-entrant:
// these are leaves).
const W_FP: U256 = u256zero();

/**
 * 读 Fp2（字节是标准域，读入即转 Montgomery）。GmSSL 约定：a1||a0。
 *
 * Reads an Fp2 (the bytes are in the standard domain and are converted to
 * Montgomery form on read). GmSSL convention: a1||a0.
 */
function readFp2(ptr: usize): Fp2 {
  const r = arenaAlloc(64);
  fpToMontTo(r, u256fromMemBE(ptr + 32)); // a0
  fpToMontTo(r + 32, u256fromMemBE(ptr)); // a1
  return r;
}

/**
 * 写 Fp2（转回标准域）。
 *
 * Writes an Fp2 (converted back to the standard domain).
 */
function writeFp2(a: Fp2, ptr: usize): void {
  fpFromMontTo(W_FP, a + 32);
  u256toBytes(W_FP, ptr);
  fpFromMontTo(W_FP, a);
  u256toBytes(W_FP, ptr + 32);
}

/**
 * 读 Fp4（GmSSL 约定：a1||a0）。
 *
 * Reads an Fp4 (GmSSL convention: a1||a0).
 */
function readFp4(ptr: usize): Fp4 {
  const r = arenaAlloc(128);
  memory.copy(r, readFp2(ptr + 64), 64); // a0
  memory.copy(r + 64, readFp2(ptr), 64); // a1
  return r;
}

/**
 * 写 Fp4（a1||a0）。
 *
 * Writes an Fp4 (a1||a0).
 */
function writeFp4(a: Fp4, ptr: usize): void {
  writeFp2(a + 64, ptr);
  writeFp2(a, ptr + 64);
}

/**
 * 读 Fp12（GmSSL 约定：a2||a1||a0）。
 *
 * Reads an Fp12 (GmSSL convention: a2||a1||a0).
 */
function readFp12(ptr: usize): Fp12 {
  const r = arenaAlloc(384);
  memory.copy(r, readFp4(ptr + 256), 128); // a0
  memory.copy(r + 128, readFp4(ptr + 128), 128); // a1
  memory.copy(r + 256, readFp4(ptr), 128); // a2
  return r;
}

/**
 * 写 Fp12（a2||a1||a0）。
 *
 * Writes an Fp12 (a2||a1||a0).
 */
function writeFp12(a: Fp12, ptr: usize): void {
  writeFp4(a + 256, ptr);
  writeFp4(a + 128, ptr + 128);
  writeFp4(a, ptr + 256);
}

/**
 * 诊断：Fp2 乘。
 *
 * Diagnostic: Fp2 multiplication.
 */
export function fp2MulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp2(fp2Mul(readFp2(aPtr), readFp2(bPtr)), outPtr);
}

/**
 * 诊断：Fp2 平方。
 *
 * Diagnostic: Fp2 squaring.
 */
export function fp2SqrOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp2(fp2Sqr(readFp2(aPtr)), outPtr);
}

/**
 * 诊断：Fp2 逆。
 *
 * Diagnostic: Fp2 inverse.
 */
export function fp2InvOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp2(fp2Inv(readFp2(aPtr)), outPtr);
}

/**
 * 诊断：Fp4 乘。
 *
 * Diagnostic: Fp4 multiplication.
 */
export function fp4MulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp4(fp4Mul(readFp4(aPtr), readFp4(bPtr)), outPtr);
}

/**
 * 诊断：Fp4 平方。
 *
 * Diagnostic: Fp4 squaring.
 */
export function fp4SqrOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp4(fp4Sqr(readFp4(aPtr)), outPtr);
}

/**
 * 诊断：Fp4 逆。
 *
 * Diagnostic: Fp4 inverse.
 */
export function fp4InvOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp4(fp4Inv(readFp4(aPtr)), outPtr);
}

/**
 * 诊断：Fp12 乘。
 *
 * Diagnostic: Fp12 multiplication.
 */
export function fp12MulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp12(fp12Mul(readFp12(aPtr), readFp12(bPtr)), outPtr);
}

/**
 * 诊断：Fp12 平方。
 *
 * Diagnostic: Fp12 squaring.
 */
export function fp12SqrOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp12(fp12Sqr(readFp12(aPtr)), outPtr);
}

/**
 * 诊断：Fp12 逆。
 *
 * Diagnostic: Fp12 inverse.
 */
export function fp12InvOut(aPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp12(fp12Inv(readFp12(aPtr)), outPtr);
}

/**
 * 诊断：G1 标量乘基点 P1，输出仿射 x||y（64 字节）。
 *
 * Diagnostic: G1 scalar multiply of the base point P1; outputs affine x||y
 * (64 bytes).
 */
export function g1MulGOut(kPtr: usize, outPtr: usize): void {
  arenaRewind();
  const k = readU256(kPtr);
  const r = g1ToAffine(g1MulG(k));
  writeG1Affine(r, outPtr);
}

// 临时标量入口：G1/G2 用固定小标量测试（避免 readU256 字节序问题）。
//
// Temporary scalar entry points: G1/G2 tested with small fixed scalars (to side
// step readU256 byte-order issues).
/**
 * 诊断：G1 小标量乘基点 P1（u32 标量），输出仿射 x||y。
 *
 * Diagnostic: G1 scalar multiply of the base point P1 by a small (u32) scalar;
 * outputs affine x||y.
 */
export function g1MulSmall(k: u32, outPtr: usize): void {
  arenaRewind();
  const r = g1ToAffine(g1MulG(u256fromU32(k)));
  writeG1Affine(r, outPtr);
}
/**
 * 诊断：G2 小标量乘基点 P2（u32 标量），输出仿射 X||Y。
 *
 * Diagnostic: G2 scalar multiply of the base point P2 by a small (u32) scalar;
 * outputs affine X||Y.
 */
export function g2MulSmall(k: u32, outPtr: usize): void {
  arenaRewind();
  const r = g2ToAffine(g2MulG(u256fromU32(k)));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}
// 输出原始 Jacobian (X||Y||Z) 用于对拍。
//
// Outputs the raw Jacobian (X||Y||Z) for cross-checking.
/**
 * 诊断：G2 小标量乘基点 P2，输出原始 Jacobian X||Y||Z（各 64 字节）。
 *
 * Diagnostic: G2 scalar multiply of the base point P2 by a small scalar;
 * outputs the raw Jacobian X||Y||Z (64 bytes each).
 */
export function g2MulSmallRaw(k: u32, outPtr: usize): void {
  arenaRewind();
  const r = g2MulG(u256fromU32(k));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
  writeFp2(r.Z, outPtr + 128);
}

/**
 * 诊断：G2 标量乘基点 P2，输出仿射 X||Y（各 Fp2 = 64 字节，共 128 字节）。
 *
 * Diagnostic: G2 scalar multiply of the base point P2; outputs affine X||Y
 * (64 bytes per Fp2, 128 bytes in total).
 */
export function g2MulGOut(kPtr: usize, outPtr: usize): void {
  arenaRewind();
  const k = readU256(kPtr);
  const r = g2ToAffine(g2MulG(k));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

/**
 * 诊断：SM9 pairing e(Q, P)。Q 为 twist 点（Z=1，X||Y 各 64 字节），P 为 base 点（x||y 各 32 字节）。输出 Fp12 = 12×32 字节。
 *
 * Diagnostic: the SM9 pairing e(Q, P). Q is a twist point (Z=1, X||Y 64 bytes
 * each), P is a base point (x||y 32 bytes each). Outputs an Fp12 = 12×32
 * bytes.
 */
export function pairingOut(qPtr: usize, pPtr: usize, outPtr: usize): void {
  arenaRewind();
  const Q = new G2();
  Q.X = readFp2(qPtr);
  Q.Y = readFp2(qPtr + 64);
  Q.Z = fp2one();
  const P = new G1();
  P.X = fpToMont(readU256(pPtr));
  P.Y = fpToMont(readU256(pPtr + 32));
  P.Z = fpMontOne();
  writeFp12(sm9Pairing(Q, P), outPtr);
}

/**
 * 读 G2 仿射（X||Y 各 64 字节），Z 置为 1。
 *
 * Reads an affine G2 point (X||Y, 64 bytes each) and sets Z to 1.
 */
function readG2Affine(ptr: usize): G2 {
  const Q = new G2();
  Q.X = readFp2(ptr);
  Q.Y = readFp2(ptr + 64);
  Q.Z = fp2one();
  return Q;
}

/**
 * 读 G1 仿射（x||y 各 32 字节，标准域 → Montgomery）。
 *
 * Reads an affine G1 point (x||y, 32 bytes each, standard domain → Montgomery).
 */
function readG1Affine(ptr: usize): G1 {
  const P = new G1();
  P.X = fpToMont(readU256(ptr));
  P.Y = fpToMont(readU256(ptr + 32));
  P.Z = fpMontOne();
  return P;
}

/**
 * 写 G1 仿射（x||y 各 32 字节，Montgomery → 标准域）。
 *
 * Writes an affine G1 point (x||y, 32 bytes each, Montgomery → standard
 * domain).
 */
function writeG1Affine(P: G1, ptr: usize): void {
  fpFromMontTo(W_FP, P.X);
  u256toBytes(W_FP, ptr);
  fpFromMontTo(W_FP, P.Y);
  u256toBytes(W_FP, ptr + 32);
}

/**
 * 诊断：切线 line function。输入 T（G2 仿射 128B）、Q（G1 64B），输出 num/den 各 384B。
 *
 * Diagnostic: tangent line function. Inputs T (affine G2, 128B) and Q (G1, 64B);
 * outputs num/den, 384B each.
 */
export function tangentOut(tPtr: usize, pPtr: usize, numPtr: usize, denPtr: usize): void {
  arenaRewind();
  const g = evalGTangent(readG2Affine(tPtr), readG1Affine(pPtr));
  writeFp12(g[0], numPtr);
  writeFp12(g[1], denPtr);
}

/**
 * 诊断：割线 line function。输入 T、P（均 G2 仿射 128B）、Q（G1 64B），输出 num/den 各 384B。
 *
 * Diagnostic: secant line function. Inputs T and P (tPtr / pp2Ptr, both affine
 * G2, 128B) and Q (G1, 64B); outputs num/den, 384B each.
 */
export function lineOut(
  tPtr: usize,
  pp2Ptr: usize,
  pPtr: usize,
  numPtr: usize,
  denPtr: usize,
): void {
  arenaRewind();
  const g = evalGLine(readG2Affine(tPtr), readG2Affine(pp2Ptr), readG1Affine(pPtr));
  writeFp12(g[0], numPtr);
  writeFp12(g[1], denPtr);
}

/**
 * 诊断：twist 点自同构。kind: 0=π1, 1=π2, 2=-π2。输入 Q 仿射 128B，输出 Jacobian X||Y||Z（192B）。
 *
 * Diagnostic: twist point automorphism. kind: 0=π1, 1=π2, 2=-π2. Input Q is
 * affine (128B); the output is Jacobian X||Y||Z (192B).
 */
export function twistAutoOut(kind: u32, qPtr: usize, outPtr: usize): void {
  arenaRewind();
  const Q = readG2Affine(qPtr);
  const R = kind === 0 ? twistPi1(Q) : kind === 1 ? twistPi2(Q) : twistNegPi2(Q);
  writeFp2(R.X, outPtr);
  writeFp2(R.Y, outPtr + 64);
  writeFp2(R.Z, outPtr + 128);
}

/**
 * 诊断：最终幂。输入 f（Fp12 384B），输出 384B。
 *
 * Diagnostic: final exponentiation. Input f (Fp12, 384B), output 384B.
 */
export function finalExpOut(fPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp12(finalExponent(readFp12(fPtr)), outPtr);
}

/**
 * 诊断：Miller loop（final exponent 之前）。输入 Q 仿射 128B、P 64B，输出结果 384B。
 *
 * Diagnostic: Miller loop (before the final exponentiation). Inputs Q affine
 * (128B) and P (64B); the result is 384B.
 */
export function millerOut(qPtr: usize, pPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp12(millerLoop(readG2Affine(qPtr), readG1Affine(pPtr)), outPtr);
}

/**
 * 诊断：跑到第 step 步时的 T（Jacobian 192B）与 fNum/fDen（各 384B）。
 *
 * Diagnostic: T (Jacobian, 192B) and fNum/fDen (384B each) after step
 * iterations.
 */
export function pairingTraceOut(
  step: u32,
  qPtr: usize,
  pPtr: usize,
  tPtr: usize,
  numPtr: usize,
  denPtr: usize,
): void {
  arenaRewind();
  const Q = readG2Affine(qPtr);
  const P = readG1Affine(pPtr);
  const T = millerStepT(<i32>step, Q, P);
  writeFp2(T.X, tPtr);
  writeFp2(T.Y, tPtr + 64);
  writeFp2(T.Z, tPtr + 128);
  const f = millerStepF(<i32>step, Q, P);
  writeFp12(f[0], numPtr);
  writeFp12(f[1], denPtr);
}

/**
 * 诊断：twist 点运算。op: 0=double, 1=add, 2=addFull。输入 a、b 为 Jacobian（192B），输出 Jacobian 192B。
 *
 * Diagnostic: twist point arithmetic. op: 0=double, 1=add, 2=addFull. Inputs a
 * and b are Jacobian (192B); the output is Jacobian 192B.
 */
export function g2OpsOut(op: u32, aPtr: usize, bPtr: usize, outPtr: usize): void {
  arenaRewind();
  const A = readG2Jac(aPtr);
  const B = readG2Jac(bPtr);
  const R = op === 0 ? g2Double(A) : op === 1 ? g2Add(A, B) : g2AddFull(A, B);
  writeFp2(R.X, outPtr);
  writeFp2(R.Y, outPtr + 64);
  writeFp2(R.Z, outPtr + 128);
}

/**
 * 诊断：割线 line function（Jacobian 输入）。T、P2 为 Jacobian 192B，Q 为 G1 64B。
 *
 * Diagnostic: secant line function (Jacobian inputs). T and P2 are Jacobian
 * (192B) and Q is G1 (64B).
 */
export function lineJacOut(
  tPtr: usize,
  p2Ptr: usize,
  qPtr: usize,
  numPtr: usize,
  denPtr: usize,
): void {
  arenaRewind();
  const g = evalGLine(readG2Jac(tPtr), readG2Jac(p2Ptr), readG1Affine(qPtr));
  writeFp12(g[0], numPtr);
  writeFp12(g[1], denPtr);
}

/**
 * 读 G2 Jacobian（X||Y||Z 各 64 字节）。
 *
 * Reads a Jacobian G2 point (X||Y||Z, 64 bytes each).
 */
function readG2Jac(ptr: usize): G2 {
  const Q = new G2();
  Q.X = readFp2(ptr);
  Q.Y = readFp2(ptr + 64);
  Q.Z = readFp2(ptr + 128);
  return Q;
}

/**
 * 诊断：签名私钥 ds = [ks/(H1+ks)]P1。输入 ks 32B、id idLen 字节，输出仿射 x||y 64B。
 *
 * Diagnostic: signing private key ds = [ks/(H1+ks)]P1. Inputs ks (32B) and id
 * (idLen bytes); outputs affine x||y, 64B.
 */
export function signDsOut(ksPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  arenaRewind();
  const r = g1ToAffine(signExtractKeyDs(readU256(ksPtr), readBytes(idPtr, idLen), idLen));
  writeG1Affine(r, outPtr);
}

/**
 * 诊断：加密私钥 de = [ke/(H1+ke)]P2。输入 ke 32B、id，输出仿射 X||Y 128B。
 *
 * Diagnostic: encryption private key de = [ke/(H1+ke)]P2. Inputs ke (32B) and
 * id; outputs affine X||Y, 128B.
 */
export function encDeOut(kePtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  arenaRewind();
  const r = g2ToAffine(encExtractKeyDe(readU256(kePtr), readBytes(idPtr, idLen), idLen));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

/**
 * 诊断：SM9 签名。输出 h||Sx||Sy 共 96B。
 *
 * Diagnostic: SM9 signing. Outputs h||Sx||Sy, 96B in total.
 */
export function sm9SignOut(
  ksPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  rPtr: usize,
  outPtr: usize,
): void {
  arenaRewind();
  const ks = readU256(ksPtr);
  const ds = signExtractKeyDs(ks, readBytes(idPtr, idLen), idLen);
  const ppubs = signMasterPublic(ks);
  sm9Sign(ds, ppubs, msgPtr, msgLen, readU256(rPtr), outPtr);
}

/**
 * 诊断：SM9 验签（sig 96B）。通过返回 1。
 *
 * Diagnostic: SM9 verification (sig is 96B). Returns 1 on success.
 */
export function sm9VerifyOut(
  ksPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  sigPtr: usize,
): i32 {
  arenaRewind();
  const ppubs = signMasterPublic(readU256(ksPtr));
  return sm9Verify(ppubs, idPtr, idLen, msgPtr, msgLen, sigPtr);
}

/**
 * 诊断：SM9 加密。输出 C1||C3||C2，返回总长度。
 *
 * Diagnostic: SM9 encryption. Outputs C1||C3||C2 and returns the total length.
 */
export function sm9EncryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  rPtr: usize,
  outPtr: usize,
  outCap: i32,
): i32 {
  arenaRewind();
  const ppube = encMasterPublic(readU256(kePtr));
  return sm9Encrypt(ppube, idPtr, idLen, msgPtr, msgLen, readU256(rPtr), outPtr, outCap);
}

/**
 * 诊断：SM9 解密。输出明文，返回长度；校验失败返回 -1。
 *
 * Diagnostic: SM9 decryption. Writes the plaintext and returns its length, or
 * -1 when verification fails.
 */
export function sm9DecryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  ctPtr: usize,
  ctLen: i32,
  outPtr: usize,
): i32 {
  arenaRewind();
  const de = encExtractKeyDe(readU256(kePtr), readBytes(idPtr, idLen), idLen);
  return sm9Decrypt(de, idPtr, idLen, ctPtr, ctLen, outPtr);
}

/**
 * SM9 KEM 封装：输出 C1(65B) 与 K(klen)。返回 1 成功；0 需换 r 重试。
 *
 * SM9 KEM encapsulation: outputs C1 (65B) and K (klen). Returns 1 on success;
 * 0 means the caller must retry with another r.
 */
export function sm9KemEncryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  rPtr: usize,
  klen: i32,
  c1Ptr: usize,
  kPtr: usize,
): i32 {
  arenaRewind();
  const ppube = encMasterPublic(readU256(kePtr));
  return sm9KemEncrypt(ppube, idPtr, idLen, readU256(rPtr), klen, c1Ptr, kPtr);
}

/**
 * 用加密主公钥（G1 仿射 64B）做 KEM 封装。
 *
 * 发送方通常只有主公钥，不应持有 KGC 的加密主私钥；此入口与
 * `sm9EncryptPubOut` 对齐。返回 1 成功；0 需换 r 重试。
 *
 * KEM encapsulation using the encryption master public key (affine G1, 64B).
 *
 * The sender usually only holds the master public key and must not hold the
 * KGC's encryption master private key; this entry point mirrors
 * `sm9EncryptPubOut`. Returns 1 on success; 0 means the caller must retry with
 * another r.
 */
export function sm9KemEncryptPubOut(
  pubPtr: usize,
  idPtr: usize,
  idLen: i32,
  rPtr: usize,
  klen: i32,
  c1Ptr: usize,
  kPtr: usize,
): i32 {
  arenaRewind();
  return sm9KemEncrypt(readG1Affine(pubPtr), idPtr, idLen, readU256(rPtr), klen, c1Ptr, kPtr);
}

/**
 * SM9 KEM 解封装：输入 C1(65B)，输出 K(klen)。返回 1 成功。
 *
 * SM9 KEM decapsulation: input C1 (65B), output K (klen). Returns 1 on
 * success.
 */
export function sm9KemDecryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  c1Ptr: usize,
  klen: i32,
  kPtr: usize,
): i32 {
  arenaRewind();
  const de = encExtractKeyDe(readU256(kePtr), readBytes(idPtr, idLen), idLen);
  return sm9KemDecrypt(de, idPtr, idLen, c1Ptr, klen, kPtr);
}

// ---------- 密钥交换（GM/T 0044.3） ----------
// ---------- Key exchange (GM/T 0044.3) ----------

/**
 * SM9 密钥交换：生成本端临时点 R（65B）。
 *
 * SM9 key exchange: generate this side's ephemeral point R (65B).
 */
export function sm9ExchEphemeralOut(
  kePtr: usize,
  peerIdPtr: usize,
  peerIdLen: i32,
  rPtr: usize,
  outPtr: usize,
): void {
  arenaRewind();
  const ppube = encMasterPublic(readU256(kePtr));
  sm9ExchEphemeral(ppube, peerIdPtr, peerIdLen, readU256(rPtr), outPtr);
}

/**
 * SM9 密钥交换：共享密钥 K（klen）。返回 1 成功；0 K 全 0。
 *
 * SM9 key exchange: the shared secret K (klen). Returns 1 on success; 0 when K
 * is all zero.
 */
export function sm9ExchKeyOut(
  kePtr: usize,
  isInitiator: i32,
  selfIdPtr: usize,
  selfIdLen: i32,
  peerIdPtr: usize,
  peerIdLen: i32,
  rPtr: usize,
  selfRPtr: usize,
  peerRPtr: usize,
  klen: i32,
  outPtr: usize,
): i32 {
  arenaRewind();
  const de = exchExtractKeyDe(readU256(kePtr), readBytes(selfIdPtr, selfIdLen), selfIdLen);
  const ppube = encMasterPublic(readU256(kePtr));
  return sm9ExchKey(
    de,
    ppube,
    isInitiator,
    selfIdPtr,
    selfIdLen,
    peerIdPtr,
    peerIdLen,
    readU256(rPtr),
    selfRPtr,
    peerRPtr,
    klen,
    outPtr,
  );
}

/**
 * SM9 密钥交换：确认值 S（32B）。prefix: 0x83 发起方 / 0x82 响应方。
 *
 * SM9 key exchange: confirmation value S (32B). prefix: 0x83 initiator /
 * 0x82 responder.
 */
export function sm9ExchConfirmOut(
  kePtr: usize,
  isInitiator: i32,
  selfIdPtr: usize,
  selfIdLen: i32,
  peerIdPtr: usize,
  peerIdLen: i32,
  rPtr: usize,
  selfRPtr: usize,
  peerRPtr: usize,
  prefix: i32,
  outPtr: usize,
): void {
  arenaRewind();
  const de = exchExtractKeyDe(readU256(kePtr), readBytes(selfIdPtr, selfIdLen), selfIdLen);
  const ppube = encMasterPublic(readU256(kePtr));
  sm9ExchConfirm(
    de,
    ppube,
    isInitiator,
    selfIdPtr,
    selfIdLen,
    peerIdPtr,
    peerIdLen,
    readU256(rPtr),
    selfRPtr,
    peerRPtr,
    prefix,
    outPtr,
  );
}

/**
 * SM9 密钥交换：一次算出 SA(0x83)、SB(0x82) 与 K(klen)。返回 1 成功。
 *
 * SM9 key exchange: compute SA(0x83), SB(0x82) and K(klen) in one pass. Returns
 * 1 on success.
 */
export function sm9ExchAllOut(
  kePtr: usize,
  isInitiator: i32,
  selfIdPtr: usize,
  selfIdLen: i32,
  peerIdPtr: usize,
  peerIdLen: i32,
  rPtr: usize,
  selfRPtr: usize,
  peerRPtr: usize,
  klen: i32,
  saPtr: usize,
  sbPtr: usize,
  kPtr: usize,
): i32 {
  arenaRewind();
  const de = exchExtractKeyDe(readU256(kePtr), readBytes(selfIdPtr, selfIdLen), selfIdLen);
  const ppube = encMasterPublic(readU256(kePtr));
  return sm9ExchAll(
    de,
    ppube,
    isInitiator,
    selfIdPtr,
    selfIdLen,
    peerIdPtr,
    peerIdLen,
    readU256(rPtr),
    selfRPtr,
    peerRPtr,
    klen,
    saPtr,
    sbPtr,
    kPtr,
  );
}

/**
 * 诊断：H1 值。hid 为 1（签名）或 3（加密）。输出 32B。
 *
 * Diagnostic: the H1 value. hid is 1 (signing) or 3 (encryption). Outputs 32B.
 */
export function hash1Out(idPtr: usize, idLen: i32, hid: u32, outPtr: usize): void {
  arenaRewind();
  u256toBytes(hash1(readBytes(idPtr, idLen), idLen, <u8>hid), outPtr);
}

/**
 * 诊断：t2 = ks·(H1+ks)^{-1} mod n（签名）。输出 32B。
 *
 * Diagnostic: t2 = ks·(H1+ks)^{-1} mod n (signing). Outputs 32B.
 */
export function signT2Out(ksPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  arenaRewind();
  u256toBytes(signT2(readU256(ksPtr), readBytes(idPtr, idLen), idLen), outPtr);
}

/**
 * 诊断：签名主公钥 [ks]P2，输出仿射 128B。
 *
 * Diagnostic: signing master public key [ks]P2, output as 128 affine bytes.
 */
export function signPubOut(ksPtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = g2ToAffine(signMasterPublic(readU256(ksPtr)));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

/**
 * 诊断：加密主公钥 [ke]P1，输出仿射 64B。
 *
 * Diagnostic: encryption master public key [ke]P1, output as 64 affine bytes.
 */
export function encPubOut(kePtr: usize, outPtr: usize): void {
  arenaRewind();
  const r = g1ToAffine(encMasterPublic(readU256(kePtr)));
  writeG1Affine(r, outPtr);
}

// ---------- 主公钥形态入口（spec §6：verify / encrypt 直接吃主公钥） ----------
// ---------- Master-public-key entry points (spec §6: verify / encrypt take the public key directly) ----------

/**
 * 用签名主公钥（G2 仿射 128B）验签。通过返回 1。
 *
 * Verify with the signing master public key (affine G2, 128B). Returns 1 on
 * success.
 */
export function sm9VerifyPubOut(
  pubPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  sigPtr: usize,
): i32 {
  arenaRewind();
  return sm9Verify(readG2Affine(pubPtr), idPtr, idLen, msgPtr, msgLen, sigPtr);
}

/**
 * 用加密主公钥（G1 仿射 64B）加密。返回密文总长度。
 *
 * Encrypt with the encryption master public key (affine G1, 64B). Returns the
 * total ciphertext length.
 */
export function sm9EncryptPubOut(
  pubPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  rPtr: usize,
  outPtr: usize,
  outCap: i32,
): i32 {
  arenaRewind();
  return sm9Encrypt(
    readG1Affine(pubPtr),
    idPtr,
    idLen,
    msgPtr,
    msgLen,
    readU256(rPtr),
    outPtr,
    outCap,
  );
}

/**
 * 用户加密公钥 Q = [H1(id, hid=3)]P1 + Ppub-e（G1 仿射 64B）。输入加密主公钥 64B。
 *
 * User encryption public key Q = [H1(id, hid=3)]P1 + Ppub-e (affine G1, 64B).
 * Input is the encryption master public key (64B).
 */
export function sm9UserEncPubOut(pubPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  arenaRewind();
  const ppube = readG1Affine(pubPtr);
  const t = hash1(readBytes(idPtr, idLen), idLen, 3);
  const r = g1ToAffine(g1Add(g1MulG(t), ppube));
  writeG1Affine(r, outPtr);
}

/**
 * 用户签名公钥 Q = [H1(id, hid=1)]P2 + Ppub-s（G2 仿射 128B）。输入签名主公钥 128B。
 *
 * User signing public key Q = [H1(id, hid=1)]P2 + Ppub-s (affine G2, 128B).
 * Input is the signing master public key (128B).
 */
export function sm9UserSignPubOut(pubPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  arenaRewind();
  const ppubs = readG2Affine(pubPtr);
  const t = hash1(readBytes(idPtr, idLen), idLen, 1);
  const r = g2ToAffine(g2Add(g2MulG(t), ppubs));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

/**
 * 从线性内存读 len 字节（拷贝到新 StaticArray）。
 *
 * Reads len bytes from linear memory (copied into a fresh StaticArray).
 */
function readBytes(ptr: usize, len: i32): StaticArray<u8> {
  const b = new StaticArray<u8>(len);
  for (let i = 0; i < len; i++) b[i] = load<u8>(ptr + i);
  return b;
}

/**
 * 诊断：Fp12 幂。输入 f 384B、k 32B，输出 384B。
 *
 * Diagnostic: Fp12 exponentiation. Inputs f (384B) and k (32B); output 384B.
 */
export function fp12PowOut(fPtr: usize, kPtr: usize, outPtr: usize): void {
  arenaRewind();
  writeFp12(fp12Pow(readFp12(fPtr), readU256(kPtr)), outPtr);
}

/**
 * 从线性内存读 U256（32 字节大端）。
 *
 * Reads a U256 from linear memory (32 big-endian bytes).
 */
function readU256(ptr: usize): U256 {
  return u256fromMemBE(ptr);
}

void fp2zero;
void fp4zero;
void fp12zero;
void fp2set;
void g2Generator;
void g1Generator;

// kdfOut：从 sm9.kdf 实现（避免 AS export 冲突）
//
// kdfOut: implemented from sm9.kdf here (to avoid an AS export name clash).
import { sm3HashInto } from '../../sm3/assembly/sm3-core';

/**
 * SM9 KDF（GM/T 0044 5.4.3）：逐块 SM3(z||ct)，ct 从 1 起，4 字节大端。
 *
 * The SM9 KDF (GM/T 0044 5.4.3): SM3(z||ct) block by block, ct starting at 1
 * as 4 big-endian bytes.
 */
function kdfImpl(z: StaticArray<u8>, klen: i32): StaticArray<u8> {
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
/**
 * 诊断：cyclotomic 平方自测（见 pairing.ts 的 sqrCycSelfTest）。返回 1=一致。
 *
 * Diagnostic: cyclotomic squaring self-test (see sqrCycSelfTest in pairing.ts).
 * Returns 1 when they agree.
 */
export function sqrCycSelfTestOut(seed: i32): i32 {
  arenaRewind();
  return sqrCycSelfTest(<u32>seed);
}

/**
 * 诊断：直接调 KDF（输入为线性内存），输出 kLen 字节。
 *
 * Diagnostic: calls the KDF directly (input taken from linear memory) and
 * writes kLen bytes.
 */
export function kdfOut(zPtr: usize, zLen: i32, kPtr: usize, kLen: i32): void {
  arenaRewind();
  const z = new StaticArray<u8>(zLen);
  for (let i = 0; i < zLen; i++) z[i] = load<u8>(zPtr + i);
  const K = kdfImpl(z, kLen);
  for (let i = 0; i < kLen; i++) store<u8>(kPtr + i, K[i]);
}

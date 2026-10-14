// SM9 AssemblyScript 入口。
//
// 分阶段实现（对齐 GmSSL 官方 view/SM9.js）：
//   Fp（fp.ts）→ Fp2（fp2.ts）→ Fp4（fp4.ts）→ Fp12（fp12.ts）
//   → G1/G2 点 → pairing → final exponent → sign/encrypt
//
// 当前阶段：暴露 Fp2 的加/乘/平方/逆诊断入口，用 GmSSL oracle 逐层对拍。
//
// 导出（诊断阶段）：
//   alloc(n) / freeAll()
//   fp2MulOut(aPtr, bPtr, outPtr)   —— 输入/输出为 a0||a1 各 32 字节大端
//   fp2SqrOut(aPtr, outPtr)
//   fp2InvOut(aPtr, outPtr)

import {
  u256fromBytes as u256fromBytesShared,
  u256fromHex,
  u256toBytes,
} from '../../common/assembly/field256';
import { U256 } from './fp';
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

const pinned: Array<StaticArray<u8>> = [];

export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

export function freeAll(): void {
  pinned.length = 0;
}

// GmSSL 约定：Fp2 序列化为 a1||a0（a1 在前）。
function readFp2(ptr: usize): Fp2 {
  const b = new Uint8Array(64);
  for (let i = 0; i < 64; i++) b[i] = load<u8>(ptr + i);
  const r = new StaticArray<U256>(2);
  r[0] = u256fromBytesShared(b, 32);
  r[1] = u256fromBytesShared(b, 0);
  return r;
}

function writeFp2(a: Fp2, ptr: usize): void {
  u256toBytes(a[1], ptr);
  u256toBytes(a[0], ptr + 32);
}

function readFp4(ptr: usize): Fp4 {
  return fp4set_(readFp2(ptr + 64), readFp2(ptr));
}

function fp4set_(a0: Fp2, a1: Fp2): Fp4 {
  const r = new StaticArray<Fp2>(2);
  r[0] = a0;
  r[1] = a1;
  return r;
}

function writeFp4(a: Fp4, ptr: usize): void {
  writeFp2(a[1], ptr);
  writeFp2(a[0], ptr + 64);
}

function readFp12(ptr: usize): Fp12 {
  const r = new StaticArray<Fp4>(3);
  r[0] = readFp4(ptr + 256);
  r[1] = readFp4(ptr + 128);
  r[2] = readFp4(ptr);
  return r;
}

function writeFp12(a: Fp12, ptr: usize): void {
  writeFp4(a[2], ptr);
  writeFp4(a[1], ptr + 128);
  writeFp4(a[0], ptr + 256);
}

/** 诊断：Fp2 乘。 */
export function fp2MulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  writeFp2(fp2Mul(readFp2(aPtr), readFp2(bPtr)), outPtr);
}

/** 诊断：Fp2 平方。 */
export function fp2SqrOut(aPtr: usize, outPtr: usize): void {
  writeFp2(fp2Sqr(readFp2(aPtr)), outPtr);
}

/** 诊断：Fp2 逆。 */
export function fp2InvOut(aPtr: usize, outPtr: usize): void {
  writeFp2(fp2Inv(readFp2(aPtr)), outPtr);
}

/** 诊断：Fp4 乘。 */
export function fp4MulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  writeFp4(fp4Mul(readFp4(aPtr), readFp4(bPtr)), outPtr);
}

/** 诊断：Fp4 平方。 */
export function fp4SqrOut(aPtr: usize, outPtr: usize): void {
  writeFp4(fp4Sqr(readFp4(aPtr)), outPtr);
}

/** 诊断：Fp4 逆。 */
export function fp4InvOut(aPtr: usize, outPtr: usize): void {
  writeFp4(fp4Inv(readFp4(aPtr)), outPtr);
}

/** 诊断：Fp12 乘。 */
export function fp12MulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  writeFp12(fp12Mul(readFp12(aPtr), readFp12(bPtr)), outPtr);
}

/** 诊断：Fp12 平方。 */
export function fp12SqrOut(aPtr: usize, outPtr: usize): void {
  writeFp12(fp12Sqr(readFp12(aPtr)), outPtr);
}

/** 诊断：Fp12 逆。 */
export function fp12InvOut(aPtr: usize, outPtr: usize): void {
  writeFp12(fp12Inv(readFp12(aPtr)), outPtr);
}

/** 诊断：G1 标量乘基点 P1，输出仿射 x||y（64 字节）。 */
export function g1MulGOut(kPtr: usize, outPtr: usize): void {
  const k = readU256(kPtr);
  const r = g1ToAffine(g1MulG(k));
  // 注意：不能对裸数字字面量调用 u256toBytes 之外的东西；outPtr 需为实际内存地址。
  u256toBytes(r.X, outPtr);
  u256toBytes(r.Y, outPtr + 32);
}

// 临时标量入口：G1/G2 用固定小标量测试（避免 readU256 字节序问题）。
export function g1MulSmall(k: u32, outPtr: usize): void {
  const kk = new StaticArray<u32>(8);
  kk[0] = k;
  const r = g1ToAffine(g1MulG(kk));
  u256toBytes(r.X, outPtr);
  u256toBytes(r.Y, outPtr + 32);
}
export function g2MulSmall(k: u32, outPtr: usize): void {
  const kk = new StaticArray<u32>(8);
  kk[0] = k;
  const r = g2ToAffine(g2MulG(kk));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}
// 输出原始 Jacobian (X||Y||Z) 用于对拍。
export function g2MulSmallRaw(k: u32, outPtr: usize): void {
  const kk = new StaticArray<u32>(8);
  kk[0] = k;
  const r = g2MulG(kk);
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
  writeFp2(r.Z, outPtr + 128);
}

/** 诊断：G2 标量乘基点 P2，输出仿射 X||Y（各 Fp2 = 64 字节，共 128 字节）。 */
export function g2MulGOut(kPtr: usize, outPtr: usize): void {
  const k = readU256(kPtr);
  const r = g2ToAffine(g2MulG(k));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

/** 诊断：SM9 pairing e(Q, P)。Q 为 twist 点（Z=1，X||Y 各 64 字节），P 为 base 点（x||y 各 32 字节）。输出 Fp12 = 12×32 字节。 */
export function pairingOut(qPtr: usize, pPtr: usize, outPtr: usize): void {
  const Q = new G2();
  Q.X = readFp2(qPtr);
  Q.Y = readFp2(qPtr + 64);
  Q.Z = fp2one();
  const P = new G1();
  P.X = readU256(pPtr);
  P.Y = readU256(pPtr + 32);
  P.Z = u256fromHex('0000000000000000000000000000000000000000000000000000000000000001');
  writeFp12(sm9Pairing(Q, P), outPtr);
}

function readG2Affine(ptr: usize): G2 {
  const Q = new G2();
  Q.X = readFp2(ptr);
  Q.Y = readFp2(ptr + 64);
  Q.Z = fp2one();
  return Q;
}

function readG1Affine(ptr: usize): G1 {
  const P = new G1();
  P.X = readU256(ptr);
  P.Y = readU256(ptr + 32);
  P.Z = u256fromHex('0000000000000000000000000000000000000000000000000000000000000001');
  return P;
}

/** 诊断：切线 line function。输入 T（G2 仿射 128B）、Q（G1 64B），输出 num/den 各 384B。 */
export function tangentOut(tPtr: usize, pPtr: usize, numPtr: usize, denPtr: usize): void {
  const g = evalGTangent(readG2Affine(tPtr), readG1Affine(pPtr));
  writeFp12(g[0], numPtr);
  writeFp12(g[1], denPtr);
}

/** 诊断：割线 line function。输入 T、P（均 G2 仿射 128B）、Q（G1 64B），输出 num/den 各 384B。 */
export function lineOut(
  tPtr: usize,
  pp2Ptr: usize,
  pPtr: usize,
  numPtr: usize,
  denPtr: usize,
): void {
  const g = evalGLine(readG2Affine(tPtr), readG2Affine(pp2Ptr), readG1Affine(pPtr));
  writeFp12(g[0], numPtr);
  writeFp12(g[1], denPtr);
}

/** 诊断：twist 点自同构。kind: 0=π1, 1=π2, 2=-π2。输入 Q 仿射 128B，输出 Jacobian X||Y||Z（196B）。 */
export function twistAutoOut(kind: u32, qPtr: usize, outPtr: usize): void {
  const Q = readG2Affine(qPtr);
  const R = kind === 0 ? twistPi1(Q) : kind === 1 ? twistPi2(Q) : twistNegPi2(Q);
  writeFp2(R.X, outPtr);
  writeFp2(R.Y, outPtr + 64);
  writeFp2(R.Z, outPtr + 128);
}

/** 诊断：最终幂。输入 f（Fp12 384B），输出 384B。 */
export function finalExpOut(fPtr: usize, outPtr: usize): void {
  writeFp12(finalExponent(readFp12(fPtr)), outPtr);
}

/** 诊断：Miller loop（final exponent 之前）。输入 Q 仿射 128B、P 64B，输出结果 384B。 */
export function millerOut(qPtr: usize, pPtr: usize, outPtr: usize): void {
  writeFp12(millerLoop(readG2Affine(qPtr), readG1Affine(pPtr)), outPtr);
}

/** 诊断：跑到第 step 步时的 T（Jacobian 192B）与 fNum/fDen（各 384B）。 */
export function pairingTraceOut(
  step: u32,
  qPtr: usize,
  pPtr: usize,
  tPtr: usize,
  numPtr: usize,
  denPtr: usize,
): void {
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

/** 诊断：twist 点运算。op: 0=double, 1=add, 2=addFull。输入 a、b 为 Jacobian（192B），输出 Jacobian 192B。 */
export function g2OpsOut(op: u32, aPtr: usize, bPtr: usize, outPtr: usize): void {
  const A = readG2Jac(aPtr);
  const B = readG2Jac(bPtr);
  const R = op === 0 ? g2Double(A) : op === 1 ? g2Add(A, B) : g2AddFull(A, B);
  writeFp2(R.X, outPtr);
  writeFp2(R.Y, outPtr + 64);
  writeFp2(R.Z, outPtr + 128);
}

/** 诊断：割线 line function（Jacobian 输入）。T、P2 为 Jacobian 192B，Q 为 G1 64B。 */
export function lineJacOut(
  tPtr: usize,
  p2Ptr: usize,
  qPtr: usize,
  numPtr: usize,
  denPtr: usize,
): void {
  const g = evalGLine(readG2Jac(tPtr), readG2Jac(p2Ptr), readG1Affine(qPtr));
  writeFp12(g[0], numPtr);
  writeFp12(g[1], denPtr);
}

function readG2Jac(ptr: usize): G2 {
  const Q = new G2();
  Q.X = readFp2(ptr);
  Q.Y = readFp2(ptr + 64);
  Q.Z = readFp2(ptr + 128);
  return Q;
}

/** 诊断：签名私钥 ds = [ks/(H1+ks)]P1。输入 ks 32B、id idLen 字节，输出仿射 x||y 64B。 */
export function signDsOut(ksPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  const r = g1ToAffine(signExtractKeyDs(readU256(ksPtr), readBytes(idPtr, idLen), idLen));
  u256toBytes(r.X, outPtr);
  u256toBytes(r.Y, outPtr + 32);
}

/** 诊断：加密私钥 de = [ke/(H1+ke)]P2。输入 ke 32B、id，输出仿射 X||Y 128B。 */
export function encDeOut(kePtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  const r = g2ToAffine(encExtractKeyDe(readU256(kePtr), readBytes(idPtr, idLen), idLen));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

/** 诊断：SM9 签名。输出 h||Sx||Sy 共 96B。 */
export function sm9SignOut(
  ksPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  rPtr: usize,
  outPtr: usize,
): void {
  const ks = readU256(ksPtr);
  const ds = signExtractKeyDs(ks, readBytes(idPtr, idLen), idLen);
  const ppubs = signMasterPublic(ks);
  sm9Sign(ds, ppubs, msgPtr, msgLen, readU256(rPtr), outPtr);
}

/** 诊断：SM9 验签（sig 96B）。通过返回 1。 */
export function sm9VerifyOut(
  ksPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  sigPtr: usize,
): i32 {
  const ppubs = signMasterPublic(readU256(ksPtr));
  return sm9Verify(ppubs, idPtr, idLen, msgPtr, msgLen, sigPtr);
}

/** 诊断：SM9 加密。输出 C1||C3||C2，返回总长度。 */
export function sm9EncryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  rPtr: usize,
  outPtr: usize,
): i32 {
  const ppube = encMasterPublic(readU256(kePtr));
  return sm9Encrypt(ppube, idPtr, idLen, msgPtr, msgLen, readU256(rPtr), outPtr);
}

/** 诊断：SM9 解密。输出明文，返回长度；校验失败返回 -1。 */
export function sm9DecryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  ctPtr: usize,
  ctLen: i32,
  outPtr: usize,
): i32 {
  const de = encExtractKeyDe(readU256(kePtr), readBytes(idPtr, idLen), idLen);
  return sm9Decrypt(de, idPtr, idLen, ctPtr, ctLen, outPtr);
}

/** SM9 KEM 封装：输出 C1(65B) 与 K(klen)。返回 1 成功；0 需换 r 重试。 */
export function sm9KemEncryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  rPtr: usize,
  klen: i32,
  c1Ptr: usize,
  kPtr: usize,
): i32 {
  const ppube = encMasterPublic(readU256(kePtr));
  return sm9KemEncrypt(ppube, idPtr, idLen, readU256(rPtr), klen, c1Ptr, kPtr);
}

/** SM9 KEM 解封装：输入 C1(65B)，输出 K(klen)。返回 1 成功。 */
export function sm9KemDecryptOut(
  kePtr: usize,
  idPtr: usize,
  idLen: i32,
  c1Ptr: usize,
  klen: i32,
  kPtr: usize,
): i32 {
  const de = encExtractKeyDe(readU256(kePtr), readBytes(idPtr, idLen), idLen);
  return sm9KemDecrypt(de, idPtr, idLen, c1Ptr, klen, kPtr);
}

// ---------- 密钥交换（GM/T 0044.3） ----------

/** SM9 密钥交换：生成本端临时点 R（65B）。 */
export function sm9ExchEphemeralOut(
  kePtr: usize,
  peerIdPtr: usize,
  peerIdLen: i32,
  rPtr: usize,
  outPtr: usize,
): void {
  const ppube = encMasterPublic(readU256(kePtr));
  sm9ExchEphemeral(ppube, peerIdPtr, peerIdLen, readU256(rPtr), outPtr);
}

/** SM9 密钥交换：共享密钥 K（klen）。返回 1 成功；0 K 全 0。 */
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

/** SM9 密钥交换：确认值 S（32B）。prefix: 0x83 发起方 / 0x82 响应方。 */
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

/** SM9 密钥交换：一次算出 SA(0x83)、SB(0x82) 与 K(klen)。返回 1 成功。 */
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

/** 诊断：H1 值。hid 为 1（签名）或 3（加密）。输出 32B。 */
export function hash1Out(idPtr: usize, idLen: i32, hid: u32, outPtr: usize): void {
  u256toBytes(hash1(readBytes(idPtr, idLen), idLen, <u8>hid), outPtr);
}

/** 诊断：t2 = ks·(H1+ks)^{-1} mod n（签名）。输出 32B。 */
export function signT2Out(ksPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  u256toBytes(signT2(readU256(ksPtr), readBytes(idPtr, idLen), idLen), outPtr);
}

/** 诊断：签名主公钥 [ks]P2，输出仿射 128B。 */
export function signPubOut(ksPtr: usize, outPtr: usize): void {
  const r = g2ToAffine(signMasterPublic(readU256(ksPtr)));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

/** 诊断：加密主公钥 [ke]P1，输出仿射 64B。 */
export function encPubOut(kePtr: usize, outPtr: usize): void {
  const r = g1ToAffine(encMasterPublic(readU256(kePtr)));
  u256toBytes(r.X, outPtr);
  u256toBytes(r.Y, outPtr + 32);
}

// ---------- 主公钥形态入口（spec §6：verify / encrypt 直接吃主公钥） ----------

/** 用签名主公钥（G2 仿射 128B）验签。通过返回 1。 */
export function sm9VerifyPubOut(
  pubPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  sigPtr: usize,
): i32 {
  return sm9Verify(readG2Affine(pubPtr), idPtr, idLen, msgPtr, msgLen, sigPtr);
}

/** 用加密主公钥（G1 仿射 64B）加密。返回密文总长度。 */
export function sm9EncryptPubOut(
  pubPtr: usize,
  idPtr: usize,
  idLen: i32,
  msgPtr: usize,
  msgLen: i32,
  rPtr: usize,
  outPtr: usize,
): i32 {
  return sm9Encrypt(readG1Affine(pubPtr), idPtr, idLen, msgPtr, msgLen, readU256(rPtr), outPtr);
}

/** 用户加密公钥 Q = [H1(id, hid=3)]P1 + Ppub-e（G1 仿射 64B）。输入加密主公钥 64B。 */
export function sm9UserEncPubOut(pubPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  const ppube = readG1Affine(pubPtr);
  const t = hash1(readBytes(idPtr, idLen), idLen, 3);
  const r = g1ToAffine(g1Add(g1MulG(t), ppube));
  u256toBytes(r.X, outPtr);
  u256toBytes(r.Y, outPtr + 32);
}

/** 用户签名公钥 Q = [H1(id, hid=1)]P2 + Ppub-s（G2 仿射 128B）。输入签名主公钥 128B。 */
export function sm9UserSignPubOut(pubPtr: usize, idPtr: usize, idLen: i32, outPtr: usize): void {
  const ppubs = readG2Affine(pubPtr);
  const t = hash1(readBytes(idPtr, idLen), idLen, 1);
  const r = g2ToAffine(g2Add(g2MulG(t), ppubs));
  writeFp2(r.X, outPtr);
  writeFp2(r.Y, outPtr + 64);
}

function readBytes(ptr: usize, len: i32): StaticArray<u8> {
  const b = new StaticArray<u8>(len);
  for (let i = 0; i < len; i++) b[i] = load<u8>(ptr + i);
  return b;
}

/** 诊断：Fp12 幂。输入 f 384B、k 32B，输出 384B。 */
export function fp12PowOut(fPtr: usize, kPtr: usize, outPtr: usize): void {
  writeFp12(fp12Pow(readFp12(fPtr), readU256(kPtr)), outPtr);
}

function readU256(ptr: usize): StaticArray<u32> {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = load<u8>(ptr + i);
  return u256fromBytesShared(b, 0);
}

void fp2zero;
void fp4zero;
void fp12zero;
void fp2set;
void u256fromHex;
void g2Generator;
void g1Generator;

// kdfOut：从 sm9.kdf 实现（避免 AS export 冲突）
import { sm3HashInto } from '../../sm3/assembly/sm3-core';

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
/** 诊断：cyclotomic 平方自测（见 pairing.ts 的 sqrCycSelfTest）。返回 1=一致。 */
export function sqrCycSelfTestOut(seed: i32): i32 {
  return sqrCycSelfTest(<u32>seed);
}

export function kdfOut(zPtr: usize, zLen: i32, kPtr: usize, kLen: i32): void {
  const z = new StaticArray<u8>(zLen);
  for (let i = 0; i < zLen; i++) z[i] = load<u8>(zPtr + i);
  const K = kdfImpl(z, kLen);
  for (let i = 0; i < kLen; i++) store<u8>(kPtr + i, K[i]);
}

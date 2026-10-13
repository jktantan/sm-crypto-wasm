// SM9 曲线点运算（AssemblyScript）。
//
// - G1：Fp 上的点，Jacobian 坐标 (X, Y, Z)，仿射 (X/Z², Y/Z³)。
// - G2：Fp2 上的扭曲线点，Jacobian 坐标。
//
// 曲线：y² = x³ + 5（G1 在 Fp 上；G2 在扭曲线 y² = x³ + 5·u 上，b 项为 [0,5]）。
// 对齐 GmSSL 官方 SM9（view/SM9.js）。
//
// 参考：GM/T 0044-2016。

import { U256, fpAdd, fpSub, fpMul, fpSqr, fpInv, fpDiv2, fpNeg, pArr } from './fp';
import {
  Fp2, fp2zero, fp2one, fp2set, fp2isZero, fp2isOne, fp2copy, fp2Add, fp2Sub, fp2Neg,
  fp2Dbl, fp2Tri, fp2Div2, fp2Mul, fp2Sqr, fp2Inv,
} from './fp2';
import { u256zero, u256eq, u256fromHex, u256clone } from '../../common/assembly/field256';

/** G1 点（Fp 上），Jacobian。 */
export class G1 {
  X: U256;
  Y: U256;
  Z: U256;
  constructor() {
    this.X = u256zero();
    this.Y = u256zero();
    this.Z = u256zero();
  }
}

/** G2 点（Fp2 上），Jacobian。 */
export class G2 {
  X: Fp2;
  Y: Fp2;
  Z: Fp2;
  constructor() {
    this.X = fp2zero();
    this.Y = fp2zero();
    this.Z = fp2zero();
  }
}

// ---------- G1 ----------

/** SM9 基点 P1（G1）。 */
export function g1Generator(): G1 {
  const p = new G1();
  p.X = u256fromHex('93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD');
  p.Y = u256fromHex('21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616');
  p.Z = u256fromHex('0000000000000000000000000000000000000000000000000000000000000001');
  return p;
}

export function g1IsInfinity(P: G1): bool {
  return u256eq(P.Z, u256zero());
}

export function g1Copy(P: G1): G1 {
  const r = new G1();
  r.X = u256clone(P.X);
  r.Y = u256clone(P.Y);
  r.Z = u256clone(P.Z);
  return r;
}

export function g1Neg(P: G1): G1 {
  const r = new G1();
  r.X = P.X;
  r.Y = fpNeg(P.Y);
  r.Z = P.Z;
  return r;
}

/** 倍点（对齐 point_double）。 */
export function g1Double(P: G1): G1 {
  if (g1IsInfinity(P)) return g1Copy(P);
  const X1 = P.X, Y1 = P.Y, Z1 = P.Z;
  let T2 = fpMul(fpSqr(X1), u256fromHex('0000000000000000000000000000000000000000000000000000000000000003'));
  let Y3 = fpAdd(Y1, Y1);
  const Z3 = fpMul(Y3, Z1);
  Y3 = fpSqr(Y3);
  let T3 = fpMul(Y3, X1);
  Y3 = fpSqr(Y3);
  Y3 = fpDiv2(Y3);
  let X3 = fpSqr(T2);
  let T1 = fpAdd(T3, T3);
  X3 = fpSub(X3, T1);
  T1 = fpSub(T3, X3);
  T1 = fpMul(T1, T2);
  Y3 = fpSub(T1, Y3);
  const r = new G1();
  r.X = X3; r.Y = Y3; r.Z = Z3;
  return r;
}

/** 点加（完整 Jacobian，对齐 GmSSL sm9_z256_point_add）。 */
export function g1Add(P: G1, Q: G1): G1 {
  if (g1IsInfinity(Q)) return g1Copy(P);
  if (g1IsInfinity(P)) return g1Copy(Q);
  const X1 = P.X, Y1 = P.Y, Z1 = P.Z;
  const X2 = Q.X, Y2 = Q.Y, Z2 = Q.Z;
  let T1 = fpSqr(Z1);
  let T2 = fpSqr(Z2);
  let U1 = fpMul(X1, T2);
  let U2 = fpMul(X2, T1);
  let Z3 = fpSqr(fpAdd(Z1, Z2));
  Z3 = fpSub(Z3, T1);
  Z3 = fpSub(Z3, T2);
  T1 = fpMul(T1, Z1);
  T2 = fpMul(T2, Z2);
  let S1 = fpMul(Y1, T2);
  const S2 = fpMul(Y2, T1);
  const H = fpSub(U2, U1);
  U2 = fpSub(S2, S1);
  if (u256eq(H, u256zero())) {
    if (u256eq(U2, u256zero())) return g1Double(Q);
    const inf = new G1();
    inf.X = u256fromHex('0000000000000000000000000000000000000000000000000000000000000001');
    inf.Y = u256fromHex('0000000000000000000000000000000000000000000000000000000000000001');
    inf.Z = u256zero();
    return inf;
  }
  Z3 = fpMul(Z3, H);
  let I = fpSqr(fpAdd(H, H));
  const H3 = fpMul(H, I);
  I = fpMul(U1, I);
  U2 = fpAdd(U2, U2);
  let X3 = fpSqr(U2);
  X3 = fpSub(H3, X3);
  let Y3 = fpAdd(fpAdd(I, I), I);
  X3 = fpAdd(Y3, X3);
  Y3 = fpMul(U2, X3);
  S1 = fpMul(S1, H3);
  S1 = fpAdd(S1, S1);
  Y3 = fpSub(Y3, S1);
  X3 = fpSub(I, X3);
  const r = new G1();
  r.X = X3; r.Y = Y3; r.Z = Z3;
  return r;
}

/** 标量乘（MSB-first）。k 为 U256。 */
export function g1Mul(k: U256, P: G1): G1 {
  let Q = new G1(); // 无穷远
  for (let i = 255; i >= 0; i--) {
    Q = g1Double(Q);
    if (((k[i >> 5] >>> (i & 31)) & 1) === 1) {
      Q = g1Add(Q, P);
    }
  }
  return Q;
}

/** 标量乘基点 P1。 */
export function g1MulG(k: U256): G1 {
  return g1Mul(k, g1Generator());
}

/** 转仿射。Z==0 时原样返回。 */
export function g1ToAffine(P: G1): G1 {
  const r = g1Copy(P);
  if (u256eq(r.Z, u256zero())) return r;
  r.Z = fpInv(r.Z);
  r.Y = fpMul(r.Y, r.Z);
  r.Z = fpSqr(r.Z);
  r.X = fpMul(r.X, r.Z);
  r.Y = fpMul(r.Y, r.Z);
  r.Z = u256fromHex('0000000000000000000000000000000000000000000000000000000000000001');
  return r;
}

// ---------- G2（扭曲线，Fp2 坐标） ----------

/** SM9 基点 P2（G2）。 */
export function g2Generator(): G2 {
  const p = new G2();
  p.X = fp2set(
    u256fromHex('3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b'),
    u256fromHex('85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141'),
  );
  p.Y = fp2set(
    u256fromHex('a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7'),
    u256fromHex('17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96'),
  );
  p.Z = fp2one();
  return p;
}

export function g2IsInfinity(P: G2): bool {
  return fp2isZero(P.Z);
}

export function g2Copy(P: G2): G2 {
  const r = new G2();
  r.X = fp2copy(P.X);
  r.Y = fp2copy(P.Y);
  r.Z = fp2copy(P.Z);
  return r;
}

export function g2Neg(P: G2): G2 {
  const r = new G2();
  r.X = P.X; r.Y = fp2Neg(P.Y); r.Z = P.Z;
  return r;
}

/** b 项 [0, 5]。 */
function g2B(): Fp2 {
  return fp2set(u256zero(), u256fromHex('0000000000000000000000000000000000000000000000000000000000000005'));
}

/** 倍点（对齐 twist_point_double）。 */
export function g2Double(P: G2): G2 {
  if (g2IsInfinity(P)) return g2Copy(P);
  const X1 = P.X, Y1 = P.Y, Z1 = P.Z;
  const T2 = fp2Tri(fp2Sqr(X1));
  let Y3 = fp2Dbl(Y1);
  const Z3 = fp2Mul(Y3, Z1);
  Y3 = fp2Sqr(Y3);
  let T3 = fp2Mul(Y3, X1);
  Y3 = fp2Sqr(Y3);
  Y3 = fp2Div2(Y3);
  let X3 = fp2Sqr(T2);
  let T1 = fp2Dbl(T3);
  X3 = fp2Sub(X3, T1);
  T1 = fp2Sub(T3, X3);
  T1 = fp2Mul(T1, T2);
  Y3 = fp2Sub(T1, Y3);
  const r = new G2();
  r.X = X3; r.Y = Y3; r.Z = Z3;
  return r;
}

/** 点加（完整 Jacobian，对齐 GmSSL sm9_z256_twist_point_add）。 */
export function g2Add(P: G2, Q: G2): G2 {
  if (g2IsInfinity(Q)) return g2Copy(P);
  if (g2IsInfinity(P)) return g2Copy(Q);
  const X1 = P.X, Y1 = P.Y, Z1 = P.Z;
  const X2 = Q.X, Y2 = Q.Y, Z2 = Q.Z;
  let T1 = fp2Sqr(Z1);
  let T2 = fp2Sqr(Z2);
  let U1 = fp2Mul(X1, T2);
  let U2 = fp2Mul(X2, T1);
  let Z3 = fp2Sqr(fp2Add(Z1, Z2));
  Z3 = fp2Sub(Z3, T1);
  Z3 = fp2Sub(Z3, T2);
  T1 = fp2Mul(T1, Z1);
  T2 = fp2Mul(T2, Z2);
  let S1 = fp2Mul(Y1, T2);
  const S2 = fp2Mul(Y2, T1);
  const H = fp2Sub(U2, U1);
  U2 = fp2Sub(S2, S1);
  if (fp2isZero(H)) {
    if (fp2isZero(U2)) return g2Double(Q);
    const inf = new G2();
    inf.X = fp2one(); inf.Y = fp2one(); inf.Z = fp2zero();
    return inf;
  }
  Z3 = fp2Mul(Z3, H);
  let I = fp2Sqr(fp2Dbl(H));
  const H3 = fp2Mul(H, I);
  I = fp2Mul(U1, I);
  U2 = fp2Dbl(U2);
  let X3 = fp2Sqr(U2);
  X3 = fp2Sub(H3, X3);
  let Y3 = fp2Tri(I);
  X3 = fp2Add(Y3, X3);
  Y3 = fp2Mul(U2, X3);
  S1 = fp2Mul(S1, H3);
  S1 = fp2Dbl(S1);
  Y3 = fp2Sub(Y3, S1);
  X3 = fp2Sub(I, X3);
  const r = new G2();
  r.X = X3; r.Y = Y3; r.Z = Z3;
  return r;
}

/** 完整点加（对齐 twist_point_add_full）。 */
export function g2AddFull(P: G2, Q: G2): G2 {
  if (g2IsInfinity(Q)) return g2Copy(P);
  if (g2IsInfinity(P)) return g2Copy(Q);
  const X1 = P.X, Y1 = P.Y, Z1 = P.Z;
  const X2 = Q.X, Y2 = Q.Y, Z2 = Q.Z;
  let T1 = fp2Sqr(Z1);
  let T2 = fp2Sqr(Z2);
  let T3 = fp2Mul(X2, T1);
  let T4 = fp2Mul(X1, T2);
  let T5 = fp2Add(T3, T4);
  T3 = fp2Sub(T3, T4);
  T1 = fp2Mul(fp2Mul(T1, Z1), Y2);
  T2 = fp2Mul(fp2Mul(T2, Z2), Y1);
  let T6 = fp2Add(T1, T2);
  T1 = fp2Sub(T1, T2);
  if (fp2isZero(T1) && fp2isZero(T3)) return g2Double(P);
  if (fp2isZero(T1) && fp2isZero(T6)) {
    const inf = new G2();
    inf.X = fp2one(); inf.Y = fp2one(); inf.Z = fp2zero();
    return inf;
  }
  T6 = fp2Sqr(T1);
  let T7 = fp2Mul(fp2Mul(T3, Z1), Z2);
  const T8 = fp2Sqr(T3);
  T5 = fp2Mul(T5, T8);
  T3 = fp2Mul(T3, T8);
  T4 = fp2Mul(T4, T8);
  T6 = fp2Sub(T6, T5);
  T4 = fp2Sub(T4, T6);
  T1 = fp2Mul(T1, T4);
  T2 = fp2Mul(T2, T3);
  T1 = fp2Sub(T1, T2);
  const r = new G2();
  r.X = T6; r.Y = T1; r.Z = T7;
  return r;
}

/** 标量乘（MSB-first）。 */
export function g2Mul(k: U256, P: G2): G2 {
  let Q = new G2(); // 无穷远
  for (let i = 255; i >= 0; i--) {
    Q = g2Double(Q);
    if (((k[i >> 5] >>> (i & 31)) & 1) === 1) {
      Q = g2Add(Q, P);
    }
  }
  return Q;
}

/** 标量乘基点 P2。 */
export function g2MulG(k: U256): G2 {
  return g2Mul(k, g2Generator());
}

/** 转仿射。 */
export function g2ToAffine(P: G2): G2 {
  const r = g2Copy(P);
  if (fp2isZero(r.Z) || fp2isOne(r.Z)) return r;
  r.Z = fp2Inv(r.Z);
  r.Y = fp2Mul(r.Y, r.Z);
  r.Z = fp2Sqr(r.Z);
  r.X = fp2Mul(r.X, r.Z);
  r.Y = fp2Mul(r.Y, r.Z);
  r.Z = fp2one();
  return r;
}

void u256zero; void pArr; void g2B; void fp2set; void fpAdd;
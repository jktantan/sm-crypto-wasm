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
import { u256zero, u256eq, u256fromHex, u256clone, u256isOdd, u256isZero, u256shr1 } from '../../common/assembly/field256';

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

// ---------- 预构造常量 ----------
//
// 这些原先每次调用都用 u256fromHex 重新解析 64 个 hex 字符；其中 g1Double 里的
// 常量在一次标量乘里要被解析 256 次，属于纯浪费。它们都是只读使用（传给 fp*
// 或赋给新建点的字段），共享同一份 U256 是安全的。

const U256_ONE = u256fromHex('0000000000000000000000000000000000000000000000000000000000000001');
const U256_THREE = u256fromHex('0000000000000000000000000000000000000000000000000000000000000003');
const G1_GX = u256fromHex('93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD');
const G1_GY = u256fromHex('21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616');
const G2_GX0 = u256fromHex('3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b');
const G2_GX1 = u256fromHex('85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141');
const G2_GY0 = u256fromHex('a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7');
const G2_GY1 = u256fromHex('17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96');

// ---------- G1 ----------

/** SM9 基点 P1（G1）。 */
export function g1Generator(): G1 {
  const p = new G1();
  p.X = G1_GX;
  p.Y = G1_GY;
  p.Z = U256_ONE;
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
  let T2 = fpMul(fpSqr(X1), U256_THREE);
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
    inf.X = U256_ONE;
    inf.Y = U256_ONE;
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

// ---------- wNAF 标量乘 ----------
//
// 朴素 double-and-add 平均要做 ~128 次点加；宽度 5 的 NAF 把非零密度降到约
// 1/(w+1)，点加降到 ~43 次。Jacobian 坐标下点加明显贵于点倍，所以划算。

const WNAF_W = 5;
const WNAF_LEN = 257; // 256 位 + 1
const WNAF_HALF: u32 = <u32>1 << (WNAF_W - 1); // 16
const WNAF_MASK: u32 = (<u32>1 << WNAF_W) - 1; // 31
const WNAF_TABLE = 8; // 1 << (W - 2)，存 P, 3P, …, 15P

/** a -= v（v < 2^32，原地）。 */
function subSmallU32(a: U256, v: u32): void {
  let borrow: i64 = <i64>v;
  let i = 0;
  while (borrow !== 0 && i < 8) {
    const cur: i64 = <i64>a[i] - (borrow & 0xffffffff);
    if (cur < 0) {
      a[i] = <u32>(cur + 0x100000000);
      borrow = 1;
    } else {
      a[i] = <u32>cur;
      borrow = 0;
    }
    i++;
  }
}

/** a += v（v < 2^32，原地）。 */
function addSmallU32(a: U256, v: u32): void {
  let carry: u64 = <u64>v;
  let i = 0;
  while (carry !== 0 && i < 8) {
    const cur: u64 = <u64>a[i] + carry;
    a[i] = <u32>(cur & 0xffffffff);
    carry = cur >>> 32;
    i++;
  }
}

/**
 * 计算 k 的宽度 5 的 wNAF（非相邻形式），低位在前。
 * digit ∈ {0, ±1, ±3, …, ±15}；k 不被修改。
 *
 * @returns 有效位数（最高位 digit 必非零；k == 0 时返回 0）
 */
function wnaf(k: U256, out: StaticArray<i32>): i32 {
  const d = u256clone(k);
  let i = 0;
  while (!u256isZero(d)) {
    if (u256isOdd(d)) {
      const m: u32 = d[0] & WNAF_MASK;
      let digit: i32 = <i32>m;
      if (m > WNAF_HALF) digit -= 32; // m - 2^W
      out[i] = digit;
      // d -= digit（digit 为负则相当于加）
      if (digit > 0) subSmallU32(d, <u32>digit);
      else addSmallU32(d, <u32>(-digit));
    } else {
      out[i] = 0;
    }
    u256shr1(d);
    i++;
  }
  return i;
}

/** 标量乘（wNAF，w = 5）。k 为 U256。 */
export function g1Mul(k: U256, P: G1): G1 {
  const digits = new StaticArray<i32>(WNAF_LEN);
  const n = wnaf(k, digits);
  if (n === 0) return new G1(); // k == 0 → 无穷远

  // 预计算 P, 3P, 5P, …, 15P
  const table = new StaticArray<G1>(WNAF_TABLE);
  table[0] = g1Copy(P);
  const step = g1Double(P);
  for (let i = 1; i < WNAF_TABLE; i++) {
    table[i] = g1Add(table[i - 1], step);
  }

  const top = digits[n - 1];
  let Q: G1 = top > 0 ? g1Copy(table[(top - 1) >> 1]) : g1Neg(table[(-top - 1) >> 1]);
  for (let i = n - 2; i >= 0; i--) {
    Q = g1Double(Q);
    const d = digits[i];
    if (d > 0) Q = g1Add(Q, table[(d - 1) >> 1]);
    else if (d < 0) Q = g1Add(Q, g1Neg(table[(-d - 1) >> 1]));
  }
  return Q;
}

// ---------- 固定基点 comb 预计算 ----------
//
// 基点固定时，把标量的位按 i = j + t·d 重排（t = 0..w-1 段，j = 0..d-1 个 comb
// 位置），于是：
//   k·P = Σ_{j=0}^{d-1} 2^j · G[c_j]，  c_j = Σ_{t=0}^{w-1} b_{j + t·d} · 2^t
//   G[c] = Σ_{t: c_t = 1} (2^d)^t · P
// 表只有 2^w 项，而运行时只需 d-1 次倍点 + d 次点加（w=5 时 51+52），
// 对比 wNAF 的 255 次倍点 + ~43 次点加。表惰性构造一次后缓存。

const COMB_W = 5;
const COMB_D = 52; // ceil(256 / COMB_W)
const COMB_SIZE = 1 << COMB_W; // 32 项

/** v 的最低置位的位索引（要求 v > 0）。 */
function lowBitIndex(v: i32): i32 {
  let i = 0;
  while (((v >>> i) & 1) === 0) i++;
  return i;
}

/** 第 j 个 comb 位置的 w 位索引 c_j。 */
function combIndex(k: U256, j: i32): i32 {
  let c: i32 = 0;
  for (let t = COMB_W - 1; t >= 0; t--) {
    const i = j + t * COMB_D;
    const bit = i < 256 ? ((k[i >> 5] >>> (i & 31)) & 1) : 0;
    c = (c << 1) | bit;
  }
  return c;
}

/** 构造基点 P 的 comb 表 G。 */
function buildG1Comb(): StaticArray<G1> {
  const S = new StaticArray<G1>(COMB_W);
  S[0] = g1Generator();
  for (let t = 1; t < COMB_W; t++) {
    let s = S[t - 1];
    for (let k = 0; k < COMB_D; k++) s = g1Double(s);
    S[t] = s;
  }
  const G = new StaticArray<G1>(COMB_SIZE);
  G[0] = new G1(); // 无穷远
  for (let c = 1; c < COMB_SIZE; c++) {
    const low = c & -c;
    G[c] = g1Add(G[c ^ low], S[lowBitIndex(low)]);
  }
  return G;
}

let g1CombCache: StaticArray<G1> = new StaticArray<G1>(0);

/** 惰性取 comb 表（首次构造后缓存，之后零开销）。 */
function g1CombTable(): StaticArray<G1> {
  if (g1CombCache.length === 0) g1CombCache = buildG1Comb();
  return g1CombCache;
}

/** 标量乘基点 P1（固定基点 comb）。 */
export function g1MulG(k: U256): G1 {
  const G = g1CombTable();
  let Q: G1 = g1Copy(G[combIndex(k, COMB_D - 1)]);
  for (let j = COMB_D - 2; j >= 0; j--) {
    Q = g1Double(Q);
    Q = g1Add(Q, G[combIndex(k, j)]);
  }
  return Q;
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
  r.Z = U256_ONE;
  return r;
}

// ---------- G2（扭曲线，Fp2 坐标） ----------

/** SM9 基点 P2（G2）。 */
export function g2Generator(): G2 {
  const p = new G2();
  p.X = fp2set(G2_GX0, G2_GX1);
  p.Y = fp2set(G2_GY0, G2_GY1);
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

/** 标量乘（wNAF，w = 5）。 */
export function g2Mul(k: U256, P: G2): G2 {
  const digits = new StaticArray<i32>(WNAF_LEN);
  const n = wnaf(k, digits);
  if (n === 0) return new G2(); // k == 0 → 无穷远

  // 预计算 P, 3P, 5P, …, 15P
  const table = new StaticArray<G2>(WNAF_TABLE);
  table[0] = g2Copy(P);
  const step = g2Double(P);
  for (let i = 1; i < WNAF_TABLE; i++) {
    table[i] = g2Add(table[i - 1], step);
  }

  const top = digits[n - 1];
  let Q: G2 = top > 0 ? g2Copy(table[(top - 1) >> 1]) : g2Neg(table[(-top - 1) >> 1]);
  for (let i = n - 2; i >= 0; i--) {
    Q = g2Double(Q);
    const d = digits[i];
    if (d > 0) Q = g2Add(Q, table[(d - 1) >> 1]);
    else if (d < 0) Q = g2Add(Q, g2Neg(table[(-d - 1) >> 1]));
  }
  return Q;
}

/** 构造基点 P2 的 comb 表 G。 */
function buildG2Comb(): StaticArray<G2> {
  const S = new StaticArray<G2>(COMB_W);
  S[0] = g2Generator();
  for (let t = 1; t < COMB_W; t++) {
    let s = S[t - 1];
    for (let k = 0; k < COMB_D; k++) s = g2Double(s);
    S[t] = s;
  }
  const G = new StaticArray<G2>(COMB_SIZE);
  G[0] = new G2(); // 无穷远
  for (let c = 1; c < COMB_SIZE; c++) {
    const low = c & -c;
    G[c] = g2Add(G[c ^ low], S[lowBitIndex(low)]);
  }
  return G;
}

let g2CombCache: StaticArray<G2> = new StaticArray<G2>(0);

/** 惰性取 comb 表（首次构造后缓存，之后零开销）。 */
function g2CombTable(): StaticArray<G2> {
  if (g2CombCache.length === 0) g2CombCache = buildG2Comb();
  return g2CombCache;
}

/** 标量乘基点 P2（固定基点 comb）。 */
export function g2MulG(k: U256): G2 {
  const G = g2CombTable();
  let Q: G2 = g2Copy(G[combIndex(k, COMB_D - 1)]);
  for (let j = COMB_D - 2; j >= 0; j--) {
    Q = g2Double(Q);
    Q = g2Add(Q, G[combIndex(k, j)]);
  }
  return Q;
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
// SM9 曲线点运算（AssemblyScript）。
//
// - G1：Fp 上的点，Jacobian 坐标 (X, Y, Z)，仿射 (X/Z², Y/Z³)。
// - G2：Fp2 上的扭曲线点，Jacobian 坐标。
//
// 曲线：y² = x³ + 5（G1 在 Fp 上；G2 在扭曲线 y² = x³ + 5·u 上，b 项为 [0,5]）。
// 对齐 GmSSL 官方 SM9（view/SM9.js）。
//
// 参考：GM/T 0044-2016。

import {
  permAlloc,
  permU256,
  u256bit,
  u256clone,
  u256copy,
  u256fromHex,
  u256isOdd,
  u256isZero,
  u256shr1,
  u256zero,
} from '../../common/assembly/field256';
import {
  fpAdd,
  fpAddTo,
  fpDiv2To,
  fpInv,
  fpMontOne,
  fpMul,
  fpMulTo,
  fpNeg,
  fpSqr,
  fpSqrTo,
  fpSubTo,
  fpToMont,
  pArr,
  U256,
} from './fp';
import {
  Fp2,
  fp2AddTo,
  fp2copy,
  fp2DblTo,
  fp2Div2To,
  fp2Inv,
  fp2isOne,
  fp2isZero,
  fp2Mul,
  fp2MulTo,
  fp2Neg,
  fp2one,
  fp2Put,
  fp2Sqr,
  fp2SqrTo,
  fp2SubTo,
  fp2set,
  fp2TriTo,
  fp2zero,
} from './fp2';

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

const U256_ONE = fpMontOne(); // 「1」在 Montgomery 域中 = R mod p
const U256_THREE = fpToMont(
  u256fromHex('0000000000000000000000000000000000000000000000000000000000000003'),
);

// G1 点运算的 U256 工作区（fp 层 To 算子用，零堆分配；非重入：*Into 是叶子）。
const GE0 = u256zero();
const GE1 = u256zero();
const GE2 = u256zero();
const GE3 = u256zero();
const GE4 = u256zero();
const GE5 = u256zero();
const GE6 = u256zero();
const GE7 = u256zero();
const GE8 = u256zero();
const GE9 = u256zero();
const GE10 = u256zero();
const GE11 = u256zero();
// 基点坐标：标准域常量，进 Montgomery 域各转一次（模块初始化时做，只此一次）。
const G1_GX = fpToMont(
  u256fromHex('93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD'),
);
const G1_GY = fpToMont(
  u256fromHex('21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616'),
);
const G2_GX0 = fpToMont(
  u256fromHex('3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b'),
);
const G2_GX1 = fpToMont(
  u256fromHex('85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141'),
);
const G2_GY0 = fpToMont(
  u256fromHex('a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7'),
);
const G2_GY1 = fpToMont(
  u256fromHex('17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96'),
);

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
  return u256isZero(P.Z);
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

/** out = 2P（倍点，对齐 point_double）。允许 out 与 P 别名。 */
export function g1DoubleInto(out: G1, P: G1): void {
  if (g1IsInfinity(P)) {
    u256copy(P.X, out.X);
    u256copy(P.Y, out.Y);
    u256copy(P.Z, out.Z);
    return;
  }
  const X1 = P.X,
    Y1 = P.Y,
    Z1 = P.Z;
  fpSqrTo(GE0, X1);
  fpMulTo(GE0, GE0, U256_THREE); // T2 = 3 X1²
  fpAddTo(GE1, Y1, Y1); // Y3 = 2 Y1
  fpMulTo(out.Z, GE1, Z1); // Z3（Z1 此后不再使用）
  fpSqrTo(GE1, GE1);
  fpMulTo(GE2, GE1, X1); // T3 = Y3·X1
  fpSqrTo(GE1, GE1);
  fpDiv2To(GE1, GE1); // Y3 = Y3² / 2
  fpSqrTo(GE3, GE0); // X3 = T2²
  fpAddTo(GE4, GE2, GE2); // T1 = 2 T3
  fpSubTo(GE3, GE3, GE4); // X3 = X3 - T1
  fpSubTo(GE4, GE2, GE3); // T1 = T3 - X3
  fpMulTo(GE4, GE4, GE0); // T1 = T1·T2
  fpSubTo(GE1, GE4, GE1); // Y3 = T1 - Y3
  u256copy(GE3, out.X);
  u256copy(GE1, out.Y);
}

/** 倍点（对齐 point_double）。 */
export function g1Double(P: G1): G1 {
  const r = new G1();
  g1DoubleInto(r, P);
  return r;
}

/** out = P + Q（完整 Jacobian，对齐 GmSSL sm9_z256_point_add）。允许别名。 */
export function g1AddInto(out: G1, P: G1, Q: G1): void {
  if (g1IsInfinity(Q)) {
    u256copy(P.X, out.X);
    u256copy(P.Y, out.Y);
    u256copy(P.Z, out.Z);
    return;
  }
  if (g1IsInfinity(P)) {
    u256copy(Q.X, out.X);
    u256copy(Q.Y, out.Y);
    u256copy(Q.Z, out.Z);
    return;
  }
  const X1 = P.X,
    Y1 = P.Y,
    Z1 = P.Z;
  const X2 = Q.X,
    Y2 = Q.Y,
    Z2 = Q.Z;
  fpSqrTo(GE0, Z1); // T1
  fpSqrTo(GE1, Z2); // T2
  fpMulTo(GE2, X1, GE1); // U1
  fpMulTo(GE3, X2, GE0); // U2
  fpAddTo(GE4, Z1, Z2);
  fpSqrTo(GE4, GE4);
  fpSubTo(GE4, GE4, GE0);
  fpSubTo(GE4, GE4, GE1); // Z3
  fpMulTo(GE0, GE0, Z1); // T1 = T1·Z1
  fpMulTo(GE1, GE1, Z2); // T2 = T2·Z2
  fpMulTo(GE5, Y1, GE1); // S1
  fpMulTo(GE6, Y2, GE0); // S2
  fpSubTo(GE7, GE3, GE2); // H = U2 - U1
  fpSubTo(GE3, GE6, GE5); // U2 = S2 - S1
  if (u256isZero(GE7)) {
    if (u256isZero(GE3)) {
      g1DoubleInto(out, Q);
      return;
    }
    u256copy(U256_ONE, out.X);
    u256copy(U256_ONE, out.Y);
    u256copy(u256zero(), out.Z); // 无穷远
    return;
  }
  fpMulTo(GE4, GE4, GE7); // Z3 = Z3·H
  fpAddTo(GE8, GE7, GE7);
  fpSqrTo(GE8, GE8); // I = (2H)²
  fpMulTo(GE9, GE7, GE8); // H3 = H·I
  fpMulTo(GE8, GE2, GE8); // I = U1·I
  fpAddTo(GE3, GE3, GE3); // U2 = 2 U2
  fpSqrTo(GE10, GE3); // X3 = U2²
  fpSubTo(GE10, GE9, GE10); // X3 = H3 - X3
  fpAddTo(GE11, GE8, GE8);
  fpAddTo(GE11, GE11, GE8); // Y3 = 3 I
  fpAddTo(GE10, GE11, GE10); // X3 = Y3 + X3
  fpMulTo(GE11, GE3, GE10); // Y3 = U2·X3
  fpMulTo(GE5, GE5, GE9); // S1 = S1·H3
  fpAddTo(GE5, GE5, GE5); // S1 = 2 S1
  fpSubTo(GE11, GE11, GE5); // Y3 = Y3 - S1
  fpSubTo(GE10, GE8, GE10); // X3 = I - X3
  u256copy(GE10, out.X);
  u256copy(GE11, out.Y);
  u256copy(GE4, out.Z);
}

/** 点加（完整 Jacobian，对齐 GmSSL sm9_z256_point_add）。 */
export function g1Add(P: G1, Q: G1): G1 {
  const r = new G1();
  g1AddInto(r, P, Q);
  return r;
}

// ---------- wNAF 标量乘 ----------
//
// 朴素 double-and-add 平均要做 ~128 次点加；宽度 5 的 NAF 把非零密度降到约
// 1/(w+1)，点加降到 ~43 次。Jacobian 坐标下点加明显贵于点倍，所以划算。

const WNAF_W = 5;
const WNAF_LEN = 257; // 256 位 + 1
const WNAF_HALF: u32 = (<u32>1) << (WNAF_W - 1); // 16
const WNAF_MASK: u32 = ((<u32>1) << WNAF_W) - 1; // 31
const WNAF_TABLE = 8; // 1 << (W - 2)，存 P, 3P, …, 15P

/** a -= v（v < 2^32，原地）。 */
function subSmallU32(a: U256, v: u32): void {
  let borrow: i64 = <i64>v;
  let i = 0;
  while (borrow !== 0 && i < 8) {
    const cur: i64 = <i64>load<u32>(a + ((<usize>i) << 2)) - (borrow & 0xffffffff);
    if (cur < 0) {
      store<u32>(a + ((<usize>i) << 2), <u32>(cur + 0x100000000));
      borrow = 1;
    } else {
      store<u32>(a + ((<usize>i) << 2), <u32>cur);
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
    const cur: u64 = <u64>load<u32>(a + ((<usize>i) << 2)) + carry;
    store<u32>(a + ((<usize>i) << 2), <u32>(cur & 0xffffffff));
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
      const m: u32 = load<u32>(d) & WNAF_MASK;
      let digit: i32 = <i32>m;
      if (m > WNAF_HALF) digit -= 32; // m - 2^W
      out[i] = digit;
      // d -= digit（digit 为负则相当于加）
      if (digit > 0) subSmallU32(d, <u32>digit);
      else addSmallU32(d, <u32>-digit);
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

  // 预计算 P, 3P, 5P, …, 15P 及其负（循环内零分配）
  const table = new StaticArray<G1>(WNAF_TABLE);
  const negTable = new StaticArray<G1>(WNAF_TABLE);
  table[0] = g1Copy(P);
  const step = g1Double(P);
  for (let i = 1; i < WNAF_TABLE; i++) {
    table[i] = g1Add(table[i - 1], step);
  }
  for (let i = 0; i < WNAF_TABLE; i++) {
    negTable[i] = g1Neg(table[i]);
  }

  const top = digits[n - 1];
  const Q = top > 0 ? g1Copy(table[(top - 1) >> 1]) : g1Copy(negTable[(-top - 1) >> 1]);
  for (let i = n - 2; i >= 0; i--) {
    g1DoubleInto(Q, Q);
    const d = digits[i];
    if (d > 0) g1AddInto(Q, Q, table[(d - 1) >> 1]);
    else if (d < 0) g1AddInto(Q, Q, negTable[(-d - 1) >> 1]);
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
    const bit = i < 256 ? <i32>u256bit(k, i) : 0;
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
  if (g1CombCache.length === 0) {
    const t = buildG1Comb();
    // 缓存必须活在 arena 之外：arena 在每次导出调用入口回卷，落在里面的坐标
    // 会在下一次调用时被覆盖。逐个把坐标深拷贝到永久区。
    for (let i = 0; i < t.length; i++) {
      const p = t[i];
      p.X = permU256(p.X);
      p.Y = permU256(p.Y);
      p.Z = permU256(p.Z);
    }
    g1CombCache = t;
  }
  return g1CombCache;
}

/** 标量乘基点 P1（固定基点 comb）。 */
export function g1MulG(k: U256): G1 {
  const G = g1CombTable();
  const Q: G1 = g1Copy(G[combIndex(k, COMB_D - 1)]);
  for (let j = COMB_D - 2; j >= 0; j--) {
    g1DoubleInto(Q, Q);
    g1AddInto(Q, Q, G[combIndex(k, j)]);
  }
  return Q;
}

/** 转仿射。Z==0 时原样返回。 */
export function g1ToAffine(P: G1): G1 {
  const r = g1Copy(P);
  if (u256isZero(r.Z)) return r;
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
  r.X = P.X;
  r.Y = fp2Neg(P.Y);
  r.Z = P.Z;
  return r;
}

/** b 项 [0, 5]（Montgomery 域）。 */
function g2B(): Fp2 {
  return fp2set(
    u256zero(),
    fpToMont(u256fromHex('0000000000000000000000000000000000000000000000000000000000000005')),
  );
}

/** 倍点（对齐 twist_point_double）。 */
// G2/G1 点运算的 Fp2 工作区（To 算子，零堆分配；非重入：下面的 *Into 是叶子，
// 内部只调 fp2 的 To 算子，后者有独立 scratch）。PE_ONE / PE_ZERO 为只读常量。
const PE_ONE: Fp2 = fp2one();
const PE_ZERO: Fp2 = fp2zero();
const PE0: Fp2 = fp2zero();
const PE1: Fp2 = fp2zero();
const PE2: Fp2 = fp2zero();
const PE3: Fp2 = fp2zero();
const PE4: Fp2 = fp2zero();
const PE5: Fp2 = fp2zero();
const PE6: Fp2 = fp2zero();
const PE7: Fp2 = fp2zero();
const PE8: Fp2 = fp2zero();
const PE9: Fp2 = fp2zero();
const PE10: Fp2 = fp2zero();
const PE11: Fp2 = fp2zero();
const _PE12: Fp2 = fp2zero();
const _PE13: Fp2 = fp2zero();

/**
 * out = 2P（Jacobian 倍点，对齐 point_double）。
 *
 * 允许 out 与 P 别名：写 out 的三个分量都排在所有对 P 的读取之后
 * （out.Z 虽是中途写出，但 Z1 在那一行之后不再被用到，已在注释中标明）。
 */
export function g2DoubleInto(out: G2, P: G2): void {
  if (g2IsInfinity(P)) {
    fp2Put(out.X, P.X);
    fp2Put(out.Y, P.Y);
    fp2Put(out.Z, P.Z);
    return;
  }
  const X1 = P.X,
    Y1 = P.Y,
    Z1 = P.Z;
  fp2SqrTo(PE0, X1);
  fp2TriTo(PE0, PE0); // T2 = 3 X1²
  fp2DblTo(PE1, Y1); // Y3 = 2 Y1
  fp2MulTo(out.Z, PE1, Z1); // Z3 = Y3·Z1（Z1 此后不再使用）
  fp2SqrTo(PE1, PE1);
  fp2MulTo(PE3, PE1, X1); // T3 = Y3·X1
  fp2SqrTo(PE1, PE1);
  fp2Div2To(PE1, PE1); // Y3 = Y3² / 2
  fp2SqrTo(PE4, PE0); // X3 = T2²
  fp2DblTo(PE5, PE3); // T1 = 2 T3
  fp2SubTo(PE4, PE4, PE5); // X3 = X3 - T1
  fp2SubTo(PE5, PE3, PE4); // T1 = T3 - X3
  fp2MulTo(PE5, PE5, PE0); // T1 = T1·T2
  fp2SubTo(PE1, PE5, PE1); // Y3 = T1 - Y3
  fp2Put(out.X, PE4);
  fp2Put(out.Y, PE1);
}

export function g2Double(P: G2): G2 {
  const r = new G2();
  g2DoubleInto(r, P);
  return r;
}

/** out = P + Q（完整 Jacobian，对齐 GmSSL sm9_z256_twist_point_add）。允许别名。 */
export function g2AddInto(out: G2, P: G2, Q: G2): void {
  if (g2IsInfinity(Q)) {
    fp2Put(out.X, P.X);
    fp2Put(out.Y, P.Y);
    fp2Put(out.Z, P.Z);
    return;
  }
  if (g2IsInfinity(P)) {
    fp2Put(out.X, Q.X);
    fp2Put(out.Y, Q.Y);
    fp2Put(out.Z, Q.Z);
    return;
  }
  const X1 = P.X,
    Y1 = P.Y,
    Z1 = P.Z;
  const X2 = Q.X,
    Y2 = Q.Y,
    Z2 = Q.Z;
  fp2SqrTo(PE0, Z1); // T1
  fp2SqrTo(PE1, Z2); // T2
  fp2MulTo(PE2, X1, PE1); // U1
  fp2MulTo(PE3, X2, PE0); // U2
  fp2AddTo(PE4, Z1, Z2);
  fp2SqrTo(PE4, PE4);
  fp2SubTo(PE4, PE4, PE0);
  fp2SubTo(PE4, PE4, PE1); // Z3
  fp2MulTo(PE0, PE0, Z1); // T1 = T1·Z1
  fp2MulTo(PE1, PE1, Z2); // T2 = T2·Z2
  fp2MulTo(PE5, Y1, PE1); // S1
  fp2MulTo(PE6, Y2, PE0); // S2
  fp2SubTo(PE7, PE3, PE2); // H = U2 - U1
  fp2SubTo(PE3, PE6, PE5); // U2 = S2 - S1
  if (fp2isZero(PE7)) {
    if (fp2isZero(PE3)) {
      g2DoubleInto(out, Q);
      return;
    }
    fp2Put(out.X, PE_ONE);
    fp2Put(out.Y, PE_ONE);
    fp2Put(out.Z, PE_ZERO); // 无穷远
    return;
  }
  fp2MulTo(PE4, PE4, PE7); // Z3 = Z3·H
  fp2DblTo(PE8, PE7);
  fp2SqrTo(PE8, PE8); // I = (2H)²
  fp2MulTo(PE9, PE7, PE8); // H3 = H·I
  fp2MulTo(PE8, PE2, PE8); // I = U1·I
  fp2DblTo(PE3, PE3); // U2 = 2 U2
  fp2SqrTo(PE10, PE3); // X3 = U2²
  fp2SubTo(PE10, PE9, PE10); // X3 = H3 - X3
  fp2TriTo(PE11, PE8); // Y3 = 3 I
  fp2AddTo(PE10, PE11, PE10); // X3 = Y3 + X3
  fp2MulTo(PE11, PE3, PE10); // Y3 = U2·X3
  fp2MulTo(PE5, PE5, PE9); // S1 = S1·H3
  fp2DblTo(PE5, PE5); // S1 = 2 S1
  fp2SubTo(PE11, PE11, PE5); // Y3 = Y3 - S1
  fp2SubTo(PE10, PE8, PE10); // X3 = I - X3
  fp2Put(out.X, PE10);
  fp2Put(out.Y, PE11);
  fp2Put(out.Z, PE4);
}

/** 点加（完整 Jacobian，对齐 GmSSL sm9_z256_twist_point_add）。 */
export function g2Add(P: G2, Q: G2): G2 {
  const r = new G2();
  g2AddInto(r, P, Q);
  return r;
}

/** out = P + Q（完整点加，对齐 twist_point_add_full）。允许别名。 */
export function g2AddFullInto(out: G2, P: G2, Q: G2): void {
  if (g2IsInfinity(Q)) {
    fp2Put(out.X, P.X);
    fp2Put(out.Y, P.Y);
    fp2Put(out.Z, P.Z);
    return;
  }
  if (g2IsInfinity(P)) {
    fp2Put(out.X, Q.X);
    fp2Put(out.Y, Q.Y);
    fp2Put(out.Z, Q.Z);
    return;
  }
  const X1 = P.X,
    Y1 = P.Y,
    Z1 = P.Z;
  const X2 = Q.X,
    Y2 = Q.Y,
    Z2 = Q.Z;
  fp2SqrTo(PE0, Z1); // T1
  fp2SqrTo(PE1, Z2); // T2
  fp2MulTo(PE2, X2, PE0); // T3
  fp2MulTo(PE3, X1, PE1); // T4
  fp2AddTo(PE4, PE2, PE3); // T5
  fp2SubTo(PE2, PE2, PE3); // T3 = T3 - T4
  fp2MulTo(PE0, PE0, Z1);
  fp2MulTo(PE0, PE0, Y2); // T1 = T1·Z1·Y2
  fp2MulTo(PE1, PE1, Z2);
  fp2MulTo(PE1, PE1, Y1); // T2 = T2·Z2·Y1
  fp2AddTo(PE5, PE0, PE1); // T6
  fp2SubTo(PE0, PE0, PE1); // T1 = T1 - T2
  if (fp2isZero(PE0) && fp2isZero(PE2)) {
    g2DoubleInto(out, P);
    return;
  }
  if (fp2isZero(PE0) && fp2isZero(PE5)) {
    fp2Put(out.X, PE_ONE);
    fp2Put(out.Y, PE_ONE);
    fp2Put(out.Z, PE_ZERO); // 无穷远
    return;
  }
  fp2SqrTo(PE6, PE0); // T6 = T1²
  fp2MulTo(PE7, PE2, Z1);
  fp2MulTo(PE7, PE7, Z2); // T7 = T3·Z1·Z2
  fp2SqrTo(PE8, PE2); // T8 = T3²
  fp2MulTo(PE4, PE4, PE8); // T5 = T5·T8
  fp2MulTo(PE2, PE2, PE8); // T3 = T3·T8
  fp2MulTo(PE3, PE3, PE8); // T4 = T4·T8
  fp2SubTo(PE6, PE6, PE4); // T6 = T6 - T5
  fp2SubTo(PE3, PE3, PE6); // T4 = T4 - T6
  fp2MulTo(PE0, PE0, PE3); // T1 = T1·T4
  fp2MulTo(PE1, PE1, PE2); // T2 = T2·T3
  fp2SubTo(PE0, PE0, PE1); // T1 = T1 - T2
  fp2Put(out.X, PE6);
  fp2Put(out.Y, PE0);
  fp2Put(out.Z, PE7);
}

/** 完整点加（对齐 twist_point_add_full）。 */
export function g2AddFull(P: G2, Q: G2): G2 {
  const r = new G2();
  g2AddFullInto(r, P, Q);
  return r;
}

/** 标量乘（wNAF，w = 5）。 */
export function g2Mul(k: U256, P: G2): G2 {
  const digits = new StaticArray<i32>(WNAF_LEN);
  const n = wnaf(k, digits);
  if (n === 0) return new G2(); // k == 0 → 无穷远

  // 预计算 P, 3P, 5P, …, 15P 及其负（循环内零分配）
  const table = new StaticArray<G2>(WNAF_TABLE);
  const negTable = new StaticArray<G2>(WNAF_TABLE);
  table[0] = g2Copy(P);
  const step = g2Double(P);
  for (let i = 1; i < WNAF_TABLE; i++) {
    table[i] = g2Add(table[i - 1], step);
  }
  for (let i = 0; i < WNAF_TABLE; i++) {
    negTable[i] = g2Neg(table[i]);
  }

  const top = digits[n - 1];
  const Q = top > 0 ? g2Copy(table[(top - 1) >> 1]) : g2Copy(negTable[(-top - 1) >> 1]);
  for (let i = n - 2; i >= 0; i--) {
    g2DoubleInto(Q, Q);
    const d = digits[i];
    if (d > 0) g2AddInto(Q, Q, table[(d - 1) >> 1]);
    else if (d < 0) g2AddInto(Q, Q, negTable[(-d - 1) >> 1]);
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
  if (g2CombCache.length === 0) {
    const t = buildG2Comb();
    // 同 G1：缓存必须落在永久区，否则下一次 arenaRewind 会覆盖这些坐标。
    for (let i = 0; i < t.length; i++) {
      const p = t[i];
      p.X = permFp2(p.X);
      p.Y = permFp2(p.Y);
      p.Z = permFp2(p.Z);
    }
    g2CombCache = t;
  }
  return g2CombCache;
}

/** 把一个 Fp2（64 字节）深拷贝到永久区。 */
function permFp2(src: Fp2): Fp2 {
  const p = permAlloc(64);
  memory.copy(p, src, 64);
  return p;
}

/** 标量乘基点 P2（固定基点 comb）。 */
export function g2MulG(k: U256): G2 {
  const G = g2CombTable();
  const Q: G2 = g2Copy(G[combIndex(k, COMB_D - 1)]);
  for (let j = COMB_D - 2; j >= 0; j--) {
    g2DoubleInto(Q, Q);
    g2AddInto(Q, Q, G[combIndex(k, j)]);
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

void u256zero;
void pArr;
void g2B;
void fp2set;
void fpAdd;

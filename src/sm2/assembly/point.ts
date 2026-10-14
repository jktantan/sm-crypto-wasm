// SM2 椭圆曲线点运算（AssemblyScript）。
//
// 曲线：y² = x³ + a·x + b (mod p)，a = p - 3。
// 参数（GM/T 0003-2012）：
//   b  = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
//   Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
//   Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
//   n  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
//
// 坐标：Jacobian (X, Y, Z) 表示仿射 (X/Z², Y/Z³)。无穷远点 Z = 0。
//
// oracle 验证：plan Task 6；对点加/倍点/标量乘用 gmkitx 或 Node bigint 校验。

import {
  arenaAlloc,
  fpAddTo,
  fpInv,
  fpMul,
  fpMulTo,
  fpSqr,
  fpSqrTo,
  fpSub,
  fpSubTo,
  nArr,
  pArr,
  permU256,
  U256,
  u256bit,
  u256clone,
  u256cmp,
  u256copy,
  u256fromBytes,
  u256fromU32,
  u256isOdd,
  u256isZero,
  u256shr1,
  u256subRaw,
  u256zero,
} from './field';

/** Jacobian 点。 */
export class JPoint {
  x: U256;
  y: U256;
  z: U256;
  constructor() {
    this.x = u256zero();
    this.y = u256zero();
    this.z = u256zero(); // Z = 0 即无穷远点
  }
}

/** 曲线参数 b。 */
export function curveB(): U256 {
  const b = new Uint8Array(32);
  const hex = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93';
  hexToBytesInto(hex, b);
  return u256fromBytes(b, 0);
}

/** 基点 G（仿射）。 */
export function basePoint(): JPoint {
  const p = new JPoint();
  const gx = new Uint8Array(32);
  const gy = new Uint8Array(32);
  hexToBytesInto('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', gx);
  hexToBytesInto('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', gy);
  p.x = u256fromBytes(gx, 0);
  p.y = u256fromBytes(gy, 0);
  p.z = u256fromU32(1);
  return p;
}

function hexToBytesInto(hex: string, out: Uint8Array): void {
  for (let i = 0; i < out.length; i++) {
    const hi = hexChar(hex.charCodeAt(i * 2));
    const lo = hexChar(hex.charCodeAt(i * 2 + 1));
    out[i] = <u8>((hi << 4) | lo);
  }
}

function hexChar(code: i32): i32 {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return 0;
}

/** 无穷远点判定：Z == 0。 */
export function isInfinity(p: JPoint): bool {
  return u256isZero(p.z);
}

/** P = -P（Y = p - Y）。 */
export function negate(p: JPoint): JPoint {
  const r = new JPoint();
  r.x = p.x;
  const pv = pArr();
  r.y = fpSub(pv, p.y);
  r.z = p.z;
  return r;
}

/**
 * Jacobian 倍点：R = 2·P。
 * 公式（dbl-2007-bl，a = -3 优化版）：
 *   delta = Z1²
 *   gamma = Y1²
 *   beta  = X1·gamma
 *   alpha = 3·(X1 - delta)·(X1 + delta)   （因 a = -3）
 *   X3 = alpha² - 8·beta
 *   Y3 = alpha·(4·beta - X3) - 8·gamma²
 *   Z3 = 2·Y1·Z1
 */
/**
 * out = 2·P（Jacobian 倍点，dbl-2007-bl，a = −3）。允许 out 与 P 别名。
 *
 * 全程原地写模块级 scratch，零堆分配：原实现一次倍点要 ~10 次 `new U256`
 * （arena 分配）加一个 JPoint，而标量乘会调用它几百次。
 *
 * 别名安全的关键：**所有对 P 的读取都排在最前面**（含 Z3 = 2·Y1·Z1），这些算完之后
 * 才写 out —— 否则 out === P 时写 out.x/out.y 会把后面还要用的 P 字段弄脏。
 */
export function doubleInto(out: JPoint, p: JPoint): void {
  if (isInfinity(p) || u256isZero(p.y)) {
    setZero(out);
    return;
  }
  fpSqrTo(DE0, p.z); // delta = Z1²
  fpSqrTo(DE1, p.y); // gamma = Y1²
  fpMulTo(DE2, p.x, DE1); // beta = X1·gamma
  fpSubTo(DE3, p.x, DE0); // X1 − delta
  fpAddTo(DE4, p.x, DE0); // X1 + delta
  fpMulTo(DE3, DE3, DE4); // alpha = (X1−delta)(X1+delta)
  fpAddTo(DE5, DE3, DE3); // 2·alpha
  fpAddTo(DE3, DE5, DE3); // 3·alpha = 2·alpha + alpha
  fpMulTo(DE4, p.y, p.z); // —— 最后一次读 P
  mulSmallTo(DE4, DE4, 2); // z3 = 2·Y1·Z1

  fpSqrTo(DE5, DE3); // alpha²
  mulSmallTo(DE6, DE2, 8); // 8·beta
  fpSubTo(out.x, DE5, DE6); // X3 = alpha² − 8·beta
  mulSmallTo(DE6, DE2, 4); // 4·beta
  fpSubTo(DE6, DE6, out.x); // 4·beta − X3
  fpMulTo(DE6, DE3, DE6); // alpha·(4·beta − X3)
  fpSqrTo(DE0, DE1); // gamma²
  mulSmallTo(DE5, DE0, 8); // 8·gamma²
  fpSubTo(out.y, DE6, DE5); // Y3 = alpha·(4·beta − X3) − 8·gamma²
  u256copy(DE4, out.z);
}

/** Jacobian 倍点：R = 2·P（分配版包装）。 */
export function doublePoint(p: JPoint): JPoint {
  const r = new JPoint();
  doubleInto(r, p);
  return r;
}

/**
 * Jacobian 点加：R = P + Q（P、Q 均非无穷远）。
 * 公式（add-2007-bl）。
 */
/**
 * out = P + Q（完整 Jacobian，add-2007-bl）。允许 out 与 P / Q 别名。
 *
 * 与 doubleInto 同样的别名纪律：Z3 = Z1·Z2·H 依赖 P、Q 的字段，所以在写 out 之前
 * 就要算完。
 */
export function addInto(out: JPoint, p: JPoint, q: JPoint): void {
  if (isInfinity(p)) {
    u256copy(q.x, out.x);
    u256copy(q.y, out.y);
    u256copy(q.z, out.z);
    return;
  }
  if (isInfinity(q)) {
    u256copy(p.x, out.x);
    u256copy(p.y, out.y);
    u256copy(p.z, out.z);
    return;
  }
  fpSqrTo(AE0, p.z); // z1z1
  fpSqrTo(AE1, q.z); // z2z2
  fpMulTo(AE2, p.x, AE1); // U1
  fpMulTo(AE3, q.x, AE0); // U2
  fpMulTo(AE4, q.z, AE1);
  fpMulTo(AE4, p.y, AE4); // S1
  fpMulTo(AE5, p.z, AE0);
  fpMulTo(AE5, q.y, AE5); // S2
  fpSubTo(AE6, AE3, AE2); // H = U2 − U1
  fpSubTo(AE7, AE5, AE4); // R = S2 − S1

  if (u256isZero(AE6)) {
    if (u256isZero(AE7)) {
      doubleInto(out, p);
      return;
    }
    setZero(out); // 互为逆元 → 无穷远
    return;
  }

  fpMulTo(AE15, p.z, q.z);
  fpMulTo(AE15, AE15, AE6); // Z3 = Z1·Z2·H —— 最后一次读 P / Q

  fpSqrTo(AE8, AE6); // HH = H²
  fpMulTo(AE9, AE6, AE8); // HHH = H·HH
  fpMulTo(AE10, AE2, AE8); // V = U1·HH
  fpSqrTo(AE11, AE7); // R²
  fpSubTo(AE11, AE11, AE9); // R² − HHH
  mulSmallTo(AE12, AE10, 2); // 2V
  fpSubTo(out.x, AE11, AE12); // X3 = R² − HHH − 2V
  fpSubTo(AE13, AE10, out.x); // V − X3
  fpMulTo(AE13, AE7, AE13); // R·(V − X3)
  fpMulTo(AE14, AE4, AE9); // S1·HHH
  fpSubTo(out.y, AE13, AE14); // Y3 = R·(V − X3) − S1·HHH
  u256copy(AE15, out.z);
}

/** 点加：R = P + Q（分配版包装）。 */
export function addPoints(p: JPoint, q: JPoint): JPoint {
  const r = new JPoint();
  addInto(r, p, q);
  return r;
}

/** 无穷远点。 */
export function infinity(): JPoint {
  return new JPoint(); // Z = 0 by default
}

export function clonePoint(p: JPoint): JPoint {
  const r = new JPoint();
  u256copy(p.x, r.x);
  u256copy(p.y, r.y);
  u256copy(p.z, r.z);
  return r;
}

// ---------- 点运算的模块级工作区 ----------
//
// 倍点/点加各占一套（addInto 在 h == 0 && r == 0 时会调 doubleInto，所以不能共用）。
// 非重入约束：这两个 Into 算子是叶子，内部只调 fp 层的 To 算子（它们各自用
// field256 的 scratch），不再回调点层的 Into 算子。
const DE0 = u256zero();
const DE1 = u256zero();
const DE2 = u256zero();
const DE3 = u256zero();
const DE4 = u256zero();
const DE5 = u256zero();
const DE6 = u256zero();

const AE0 = u256zero();
const AE1 = u256zero();
const AE2 = u256zero();
const AE3 = u256zero();
const AE4 = u256zero();
const AE5 = u256zero();
const AE6 = u256zero();
const AE7 = u256zero();
const AE8 = u256zero();
const AE9 = u256zero();
const AE10 = u256zero();
const AE11 = u256zero();
const AE12 = u256zero();
const AE13 = u256zero();
const AE14 = u256zero();
const AE15 = u256zero();

const ZERO_U256 = u256zero(); // 只读零常量

/** out = 0（无穷远点的坐标）。 */
function setZero(out: JPoint): void {
  u256copy(ZERO_U256, out.x);
  u256copy(ZERO_U256, out.y);
  u256copy(ZERO_U256, out.z);
}

/**
 * out = k·a mod p，k ∈ {2,3,4,8}。
 *
 * 全部用加倍/加法实现 —— 原先走 `fpMul(a, u256fromU32(k))`，即**整次模乘**
 * （64 次 32×32 乘法 + 归约）。倍点里有 4 处、点加里有 2 处这种调用，一次标量乘
 * 累计上千次，改成模加（各一次条件减）后这部分开销基本消失。
 *
 * k = 3 时 out 可能与 a 别名，故先把 a 备份到 scratch（否则第二个 fpAddTo 读到的是
 * 已被覆盖成 2a 的 a，会算成 4a）。k ∈ {2,4,8} 不需要 a 的原值。
 */
const MS_TMP = u256zero();

function mulSmallTo(out: U256, a: U256, k: u32): void {
  if (k === 3) {
    u256copy(a, MS_TMP);
    fpAddTo(out, a, a); // 2a
    fpAddTo(out, out, MS_TMP); // 2a + a = 3a
    return;
  }
  fpAddTo(out, a, a); // 2a
  if (k === 2) return;
  fpAddTo(out, out, out); // 4a
  if (k === 4) return;
  fpAddTo(out, out, out); // 8a
}

// ---------- 标量模运算（mod n） ----------

/** 把标量（256-bit）折到 [0, n)。假定输入 < 2^256，n 接近 2^256，最多减一次。 */
function _reduceModN(a: U256): U256 {
  const n = nArr();
  if (u256cmp(a, n) >= 0) {
    return fpSubRaw(a, n);
  }
  return a;
}

/** 原始 256-bit 减法（不 mod p），借位忽略（假定 a >= b）。 */
function fpSubRaw(a: U256, b: U256): U256 {
  const r = u256clone(a);
  u256subRaw(r, b);
  return r;
}

// ---------- wNAF 标量乘（任意点） ----------
//
// 朴素双倍-点加平均要做 ~128 次点加；宽度 5 的 wNAF 把非零密度降到约 1/(w+1)，
// 点加降到 ~43 次。Jacobian 下点加明显贵于点倍，所以划算。
// 固定基点走 comb 表（见本文件 scalarMulG），这里服务任意点：verify 的 t·P、
// decrypt 的 d·C1、以及密钥交换。

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
 * 计算 k 的宽度 5 的 wNAF（非相邻形式），低位在前，写入 out（i32 数组）。
 * digit ∈ {0, ±1, ±3, …, ±15}；k 不被修改。
 *
 * @returns 有效位数（k == 0 时返回 0）
 */
function wnaf(k: U256, out: usize): i32 {
  const d = u256clone(k);
  let i = 0;
  while (!u256isZero(d)) {
    if (u256isOdd(d)) {
      const m: u32 = load<u32>(d) & WNAF_MASK;
      let digit: i32 = <i32>m;
      if (m > WNAF_HALF) digit -= 32; // m - 2^W
      store<i32>(out + ((<usize>i) << 2), digit);
      if (digit > 0) subSmallU32(d, <u32>digit);
      else addSmallU32(d, <u32>-digit);
    } else {
      store<i32>(out + ((<usize>i) << 2), 0);
    }
    u256shr1(d);
    i++;
  }
  return i;
}

/**
 * 标量乘：R = k · P（任意点，wNAF w = 5）。
 */
export function scalarMul(k: U256, p: JPoint): JPoint {
  const digits = arenaAlloc(<usize>WNAF_LEN * 4);
  const n = wnaf(k, digits);
  if (n === 0) return infinity(); // k == 0

  // 预计算 P, 3P, 5P, …, 15P 及其负（循环内零分配）
  const table = new StaticArray<JPoint>(WNAF_TABLE);
  const negTable = new StaticArray<JPoint>(WNAF_TABLE);
  table[0] = clonePoint(p);
  const step = doublePoint(p);
  for (let i = 1; i < WNAF_TABLE; i++) table[i] = addPoints(table[i - 1], step);
  for (let i = 0; i < WNAF_TABLE; i++) negTable[i] = negate(table[i]);

  const top = load<i32>(digits + ((<usize>(n - 1)) << 2));
  const Q = top > 0 ? clonePoint(table[(top - 1) >> 1]) : clonePoint(negTable[(-top - 1) >> 1]);
  for (let i = n - 2; i >= 0; i--) {
    doubleInto(Q, Q);
    const d = load<i32>(digits + ((<usize>i) << 2));
    if (d > 0) addInto(Q, Q, table[(d - 1) >> 1]);
    else if (d < 0) addInto(Q, Q, negTable[(-d - 1) >> 1]);
  }
  return Q;
}

/**
 * 标量乘 G：R = k · G。
 *
 * 基点固定，故用 comb 预计算表（与 SM9 侧同一套构造）：
 *   k·G = Σ_{j=0}^{d-1} 2^j · G[c_j]，  c_j = Σ_{t=0}^{w-1} b_{j + t·d} · 2^t
 *   G[c] = Σ_{t: c_t = 1} (2^d)^t · G
 * 表只有 2^w = 32 项，运行时 d-1 = 51 次倍点 + 52 次点加，取代逐位双倍-点加的
 * 255 次倍点 + ~128 次点加。表惰性构造一次后缓存在永久区。
 */
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

/** 构造基点 G 的 comb 表。 */
function buildComb(): StaticArray<JPoint> {
  const S = new StaticArray<JPoint>(COMB_W);
  S[0] = basePoint();
  for (let t = 1; t < COMB_W; t++) {
    let s = S[t - 1];
    for (let j = 0; j < COMB_D; j++) s = doublePoint(s);
    S[t] = s;
  }
  const G = new StaticArray<JPoint>(COMB_SIZE);
  G[0] = new JPoint(); // 无穷远
  for (let c = 1; c < COMB_SIZE; c++) {
    const low = c & -c;
    G[c] = addPoints(G[c ^ low], S[lowBitIndex(low)]);
  }
  return G;
}

let g1CombCache: StaticArray<JPoint> = new StaticArray<JPoint>(0);

/** 惰性取 comb 表（首次构造后缓存；坐标深拷贝到永久区，免被 arena 回卷覆盖）。 */
function combTable(): StaticArray<JPoint> {
  if (g1CombCache.length === 0) {
    const t = buildComb();
    for (let i = 0; i < t.length; i++) {
      const p = t[i];
      p.x = permU256(p.x);
      p.y = permU256(p.y);
      p.z = permU256(p.z);
    }
    g1CombCache = t;
  }
  return g1CombCache;
}

/** 标量乘 G：R = k · G（固定基点 comb）。 */
export function scalarMulG(k: U256): JPoint {
  const G = combTable();
  const Q = clonePoint(G[combIndex(k, COMB_D - 1)]);
  for (let j = COMB_D - 2; j >= 0; j--) {
    doubleInto(Q, Q);
    addInto(Q, Q, G[combIndex(k, j)]);
  }
  return Q;
}

/** Jacobian → 仿射：返回 (x, y)。Z == 0 时返回全 0。 */
export function toAffine(p: JPoint): JPoint {
  const out = new JPoint();
  if (isInfinity(p)) {
    return out; // (0,0,0)
  }
  const zinv = fpInv(p.z);
  const zinv2 = fpSqr(zinv);
  const zinv3 = fpMul(zinv2, zinv);
  out.x = fpMul(p.x, zinv2);
  out.y = fpMul(p.y, zinv3);
  out.z = u256fromU32(1);
  return out;
}

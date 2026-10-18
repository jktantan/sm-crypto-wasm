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
//
// SM2 elliptic-curve point arithmetic (AssemblyScript).
//
// Curve: y² = x³ + a·x + b (mod p), a = p - 3.
// Parameters (GM/T 0003-2012):
//   b  = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
//   Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
//   Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
//   n  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
//
// Coordinates: Jacobian (X, Y, Z) stands for the affine point (X/Z², Y/Z³). The point at
// infinity has Z = 0.
//
// Oracle checks: plan Task 6; point addition / doubling / scalar multiplication are
// verified against gmkitx or Node bigint.

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
  permAlloc,
  permU256,
  U256,
  u256bit,
  u256clone,
  u256cmp,
  u256copy,
  u256fromBytes,
  u256fromMemBE,
  u256fromU32,
  u256isOdd,
  u256isZero,
  u256shr1,
  u256subRaw,
  u256zero,
} from './field';

/**
 * Jacobian 点。
 *
 * 三个字段即 (X, Y, Z)，均为 U256（小端 limb）；Z = 0 表示无穷远点。
 *
 * A Jacobian point.
 *
 * The three fields are (X, Y, Z), each a U256 (little-endian limbs); Z = 0 means the
 * point at infinity.
 */
export class JPoint {
  x: U256;
  y: U256;
  z: U256;
  constructor() {
    this.x = u256zero();
    this.y = u256zero();
    this.z = u256zero(); // Z = 0 即无穷远点
    //
    // Z = 0 means the point at infinity
  }
}

/**
 * 曲线参数 b。
 *
 * Curve parameter b.
 */
export function curveB(): U256 {
  const b = new Uint8Array(32);
  const hex = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93';
  hexToBytesInto(hex, b);
  return u256fromBytes(b, 0);
}

/**
 * 基点 G（仿射）。
 *
 * The base point G (affine).
 */
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

/**
 * 把 64 个 hex 字符解码到 32 字节输出（不分配，直接写 out）。
 *
 * Decode 64 hex characters into a 32-byte output (writes into out, no allocation).
 */
function hexToBytesInto(hex: string, out: Uint8Array): void {
  for (let i = 0; i < out.length; i++) {
    const hi = hexChar(hex.charCodeAt(i * 2));
    const lo = hexChar(hex.charCodeAt(i * 2 + 1));
    out[i] = <u8>((hi << 4) | lo);
  }
}

/**
 * 单个 hex 字符 → 4-bit 值（非 hex 字符返回 0）。
 *
 * One hex character → 4-bit value (non-hex characters yield 0).
 */
function hexChar(code: i32): i32 {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return 0;
}

/**
 * 无穷远点判定：Z == 0。
 *
 * Point-at-infinity test: Z == 0.
 */
export function isInfinity(p: JPoint): bool {
  return u256isZero(p.z);
}

/**
 * P = -P（Y = p - Y）。
 *
 * P = -P (Y = p - Y).
 */
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
 *
 * Jacobian doubling: R = 2·P.
 * Formulas (dbl-2007-bl, optimised for a = -3):
 *   delta = Z1²
 *   gamma = Y1²
 *   beta  = X1·gamma
 *   alpha = 3·(X1 - delta)·(X1 + delta)   (since a = -3)
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
 *
 * out = 2·P (Jacobian doubling, dbl-2007-bl, a = −3). out may alias P.
 *
 * Everything is written in place into module-level scratch, with zero heap allocation:
 * the old version needed ~10 `new U256` arena allocations plus one JPoint per doubling,
 * and scalar multiplication calls it hundreds of times.
 *
 * The key to alias safety: **every read of P happens up front** (including
 * Z3 = 2·Y1·Z1), and out is written only afterwards — otherwise, with out === P,
 * writing out.x/out.y would clobber P fields still needed later.
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
  //
  // the last read of P
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

/**
 * Jacobian 倍点：R = 2·P（分配版包装）。
 *
 * Jacobian doubling: R = 2·P (allocating wrapper).
 */
export function doublePoint(p: JPoint): JPoint {
  const r = new JPoint();
  doubleInto(r, p);
  return r;
}

/**
 * Jacobian 点加：R = P + Q（P、Q 均非无穷远）。
 * 公式（add-2007-bl）。
 *
 * Jacobian point addition: R = P + Q (both P and Q are non-infinite).
 * Formulas (add-2007-bl).
 */
/**
 * out = P + Q（完整 Jacobian，add-2007-bl）。允许 out 与 P / Q 别名。
 *
 * 与 doubleInto 同样的别名纪律：Z3 = Z1·Z2·H 依赖 P、Q 的字段，所以在写 out 之前
 * 就要算完。
 *
 * out = P + Q (full Jacobian addition, add-2007-bl). out may alias P / Q.
 *
 * The same alias discipline as doubleInto: Z3 = Z1·Z2·H depends on fields of P and Q,
 * so it must be computed before out is written.
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
    //
    // mutually inverse → the point at infinity
    return;
  }

  fpMulTo(AE15, p.z, q.z);
  // Z3 = Z1·Z2·H —— 最后一次读 P / Q
  //
  // Z3 = Z1·Z2·H — last read of P / Q.
  fpMulTo(AE15, AE15, AE6);

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

/**
 * 点加：R = P + Q（分配版包装）。
 *
 * Point addition: R = P + Q (allocating wrapper).
 */
export function addPoints(p: JPoint, q: JPoint): JPoint {
  const r = new JPoint();
  addInto(r, p, q);
  return r;
}

/**
 * 混合坐标点加：out = P + Q，其中 **Q 为仿射点（Z2 = 1）**。
 * 公式 madd-2007-bl：8M + 3S，比通用 Jacobian 点加（12M + 4S）省约 1/3。
 *
 * 前提：Q 非无穷远（调用方保证；本函数不检查 Q.z）。
 * 别名纪律与 addInto 相同：写入 out 之前已读完 P、Q 的所有字段。
 *
 * Mixed-coordinate point addition: out = P + Q, where **Q is affine (Z2 = 1)**.
 * Formulas (madd-2007-bl): 8M + 3S, about 1/3 cheaper than the general Jacobian addition
 * (12M + 4S).
 *
 * Precondition: Q is not the point at infinity (guaranteed by the caller; this function
 * does not check Q.z). The alias discipline matches addInto: every field of P and Q is
 * read before out is written.
 */
export function addMixedInto(out: JPoint, p: JPoint, q: JPoint): void {
  if (isInfinity(p)) {
    u256copy(q.x, out.x);
    u256copy(q.y, out.y);
    u256copy(ONE_U256, out.z);
    return;
  }
  fpSqrTo(ME0, p.z); // Z1Z1 = Z1²
  fpMulTo(ME1, q.x, ME0); // U2 = X2·Z1Z1
  fpMulTo(ME2, p.z, ME0); // Z1·Z1Z1
  fpMulTo(ME2, q.y, ME2); // S2 = Y2·Z1³
  fpSubTo(ME3, ME1, p.x); // H = U2 − X1
  fpSubTo(ME4, ME2, p.y); // S2 − Y1

  if (u256isZero(ME3)) {
    if (u256isZero(ME4)) {
      doubleInto(out, p); // 同点：退化为倍点
      //
      // same point: degrade to doubling
      return;
    }
    setZero(out); // 互为逆元 → 无穷远
    //
    // mutually inverse → the point at infinity
    return;
  }

  fpAddTo(ME4, ME4, ME4); // r = 2·(S2 − Y1)
  fpSqrTo(ME5, ME3); // HH = H²
  fpAddTo(ME6, ME5, ME5); // 2·HH
  fpAddTo(ME6, ME6, ME6); // I = 4·HH
  fpMulTo(ME7, ME3, ME6); // J = H·I
  fpMulTo(ME8, p.x, ME6); // V = X1·I
  fpSqrTo(ME9, ME4); // r²
  fpSubTo(ME9, ME9, ME7); // r² − J
  fpAddTo(ME10, ME8, ME8); // 2V
  fpSubTo(out.x, ME9, ME10); // X3 = r² − J − 2V
  fpSubTo(ME9, ME8, out.x); // V − X3
  fpMulTo(ME9, ME4, ME9); // r·(V − X3)
  fpMulTo(ME11, p.y, ME7); // Y1·J
  fpAddTo(ME11, ME11, ME11); // 2·Y1·J
  fpSubTo(out.y, ME9, ME11); // Y3 = r·(V − X3) − 2·Y1·J
  fpAddTo(ME12, p.z, ME3); // Z1 + H
  fpSqrTo(ME12, ME12); // (Z1 + H)²
  fpSubTo(ME12, ME12, ME0); // − Z1Z1
  fpSubTo(out.z, ME12, ME5); // Z3 = (Z1+H)² − Z1Z1 − HH
}

/**
 * 批量归一化：把 n 个 Jacobian 点一次性转成仿射（Z = 1）。
 *
 * 用 Montgomery 求逆技巧：n 次求逆换取 1 次求逆 + 3n 次乘法。
 * comb 表（32 项）若逐点 fpInv，一次性成本 32×12.5µs ≈ 400µs；此处约 25µs。
 * z == 0 的项（无穷远）原样保留。
 *
 * Batch normalisation: convert n Jacobian points to affine (Z = 1) in one pass.
 *
 * Uses the Montgomery inversion trick: n inversions become 1 inversion plus 3n
 * multiplications. Inverting the 32-entry comb table point by point would cost
 * 32×12.5µs ≈ 400µs once; here it is about 25µs.
 * Entries with z == 0 (the point at infinity) are left untouched.
 */
function batchToAffine(points: StaticArray<JPoint>): void {
  const n = points.length;
  const prod = arenaAlloc(<usize>n * 32); // 前缀积
  //
  // prefix products
  const acc = arenaAlloc(32);
  u256copy(ONE_U256, acc);
  for (let i = 0; i < n; i++) {
    u256copy(acc, prod + ((<usize>i) << 5)); // prod[i] = acc
    const z = points[i].z;
    if (!u256isZero(z)) fpMulTo(acc, acc, z); // 跳过无穷远
    //
    // skip the point at infinity
  }

  const inv = fpInv(acc); // 唯一一次求逆
  //
  // the one and only inversion
  for (let i = n - 1; i >= 0; i--) {
    const p = points[i];
    if (u256isZero(p.z)) continue;
    const zi = arenaAlloc(32);
    const zinv = arenaAlloc(32);
    const z2 = arenaAlloc(32);
    const z3 = arenaAlloc(32);
    u256copy(prod + ((<usize>i) << 5), zi); // zi = prod[i]
    fpMulTo(zinv, inv, zi); // z_i^{-1}
    fpMulTo(inv, inv, p.z); // inv *= z_i（回推下一个）
    //
    // inv *= z_i (back-substitute the next entry)
    fpSqrTo(z2, zinv);
    fpMulTo(z3, z2, zinv);
    fpMulTo(p.x, p.x, z2);
    fpMulTo(p.y, p.y, z3);
    u256copy(ONE_U256, p.z);
  }
}

/**
 * 无穷远点。
 *
 * The point at infinity.
 */
export function infinity(): JPoint {
  return new JPoint(); // Z = 0 by default
}

/**
 * 深拷贝一个 Jacobian 点（新分配的 U256，不共享内存）。
 *
 * Deep-copy a Jacobian point (freshly allocated U256s, no shared memory).
 */
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
//
// ---------- Module-level workspaces for point arithmetic ----------
//
// Doubling and addition each own a set (addInto calls doubleInto when h == 0 && r == 0,
// so they cannot share one).
// Non-reentrancy constraint: these two Into operators are leaves; they only call the
// field-level To operators (which use field256's own scratch) and never call back into
// the point-level Into operators.
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

// 混合坐标点加（addMixedInto，Q 为仿射）的工作区。
//
// Workspace for mixed-coordinate addition (addMixedInto, Q affine).
const ME0 = u256zero();
const ME1 = u256zero();
const ME2 = u256zero();
const ME3 = u256zero();
const ME4 = u256zero();
const ME5 = u256zero();
const ME6 = u256zero();
const ME7 = u256zero();
const ME8 = u256zero();
const ME9 = u256zero();
const ME10 = u256zero();
const ME11 = u256zero();
const ME12 = u256zero();

const ZERO_U256 = u256zero(); // 只读零常量
//
// read-only zero constant
const ONE_U256 = u256fromU32(1); // 只读常量 1（仿射点的 Z）
//
// read-only constant 1 (the Z of an affine point)

/**
 * out = 0（无穷远点的坐标）。
 *
 * out = 0 (the coordinates of the point at infinity).
 */
function setZero(out: JPoint): void {
  u256copy(ZERO_U256, out.x);
  u256copy(ZERO_U256, out.y);
  u256copy(ZERO_U256, out.z);
}

const MS_TMP = u256zero();

/**
 * out = k·a mod p，k ∈ {2,3,4,8}。
 *
 * 全部用加倍/加法实现 —— 原先走 `fpMul(a, u256fromU32(k))`，即**整次模乘**
 * （64 次 32×32 乘法 + 归约）。倍点里有 4 处、点加里有 2 处这种调用，一次标量乘
 * 累计上千次，改成模加（各一次条件减）后这部分开销基本消失。
 *
 * k = 3 时 out 可能与 a 别名，故先把 a 备份到 scratch（否则第二个 fpAddTo 读到的是
 * 已被覆盖成 2a 的 a，会算成 4a）。k ∈ {2,4,8} 不需要 a 的原值。
 *
 * out = k·a mod p for k ∈ {2,3,4,8}.
 *
 * Everything is done with doublings / additions — it used to go through
 * `fpMul(a, u256fromU32(k))`, i.e. **a full modular multiplication** (64 32×32
 * multiplications plus reduction). There are 4 such calls in doubling and 2 in addition,
 * accumulating to thousands per scalar multiplication; with modular additions (one
 * conditional subtraction each) that cost essentially disappears.
 *
 * For k = 3, out may alias a, so a is backed up into scratch first (otherwise the second
 * fpAddTo would read an a already overwritten with 2a and produce 4a). k ∈ {2,4,8}
 * does not need the original a.
 */
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
// ---------- Scalar modular arithmetic (mod n) ----------

/**
 * 把标量（256-bit）折到 [0, n)。假定输入 < 2^256，n 接近 2^256，最多减一次。
 *
 * Reduce a scalar (256-bit) into [0, n). Assumes the input is < 2^256; since n is close
 * to 2^256, a single subtraction suffices.
 */
function _reduceModN(a: U256): U256 {
  const n = nArr();
  if (u256cmp(a, n) >= 0) {
    return fpSubRaw(a, n);
  }
  return a;
}

/**
 * 原始 256-bit 减法（不 mod p），借位忽略（假定 a >= b）。
 *
 * Raw 256-bit subtraction (no mod p); the borrow is ignored (assumes a >= b).
 */
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
//
// ---------- wNAF scalar multiplication (arbitrary points) ----------
//
// Naive double-and-add needs ~128 additions on average; width-5 wNAF lowers the non-zero
// density to about 1/(w+1), i.e. ~43 additions. In Jacobian coordinates an addition is
// clearly more expensive than a doubling, so this pays off.
// A fixed base point uses the comb table (see scalarMulG in this file); this path serves
// arbitrary points: t·P in verify, d·C1 in decrypt, and key exchange.

const WNAF_W = 5;
const WNAF_LEN = 257; // 256 位 + 1
//
// 256 bits + 1
const WNAF_HALF: u32 = (<u32>1) << (WNAF_W - 1); // 16
const WNAF_MASK: u32 = ((<u32>1) << WNAF_W) - 1; // 31
const WNAF_TABLE = 8; // 1 << (W - 2)，存 P, 3P, …, 15P
//
// 1 << (W - 2); holds P, 3P, …, 15P

/**
 * a -= v（v < 2^32，原地）。
 *
 * a -= v (v < 2^32, in place).
 */
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

/**
 * a += v（v < 2^32，原地）。
 *
 * a += v (v < 2^32, in place).
 */
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
 *
 * Compute the width-5 wNAF (non-adjacent form) of k, least-significant digit first, into
 * out (an i32 array). digit ∈ {0, ±1, ±3, …, ±15}; k itself is not modified.
 *
 * @returns The number of significant digits (0 when k == 0).
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
 *
 * Scalar multiplication: R = k · P (arbitrary point, wNAF w = 5).
 */
export function scalarMul(k: U256, p: JPoint): JPoint {
  const digits = arenaAlloc(<usize>WNAF_LEN * 4);
  const n = wnaf(k, digits);
  if (n === 0) return infinity(); // k == 0

  // 预计算 P, 3P, 5P, …, 15P 及其负（循环内零分配）
  //
  // Precompute P, 3P, 5P, …, 15P and their negatives (no allocation inside the loop)
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
 *
 * Scalar multiplication by G: R = k · G.
 *
 * The base point is fixed, so a precomputed comb table is used (the same construction as
 * on the SM9 side):
 *   k·G = Σ_{j=0}^{d-1} 2^j · G[c_j],  c_j = Σ_{t=0}^{w-1} b_{j + t·d} · 2^t
 *   G[c] = Σ_{t: c_t = 1} (2^d)^t · G
 * The table holds only 2^w = 32 entries, and a run costs d-1 = 51 doublings plus 52
 * additions, replacing the digit-by-digit 255 doublings and ~128 additions. The table is
 * built lazily once and cached in permanent memory.
 */
const COMB_W = 5;
const COMB_D = 52; // ceil(256 / COMB_W)
const COMB_SIZE = 1 << COMB_W; // 32 项
//
// 32 entries

/**
 * v 的最低置位的位索引（要求 v > 0）。
 *
 * The bit index of the lowest set bit of v (requires v > 0).
 */
function lowBitIndex(v: i32): i32 {
  let i = 0;
  while (((v >>> i) & 1) === 0) i++;
  return i;
}

/**
 * 第 j 个 comb 位置的 w 位索引 c_j。
 *
 * The w-bit index c_j of the j-th comb position.
 */
function combIndex(k: U256, j: i32): i32 {
  let c: i32 = 0;
  for (let t = COMB_W - 1; t >= 0; t--) {
    const i = j + t * COMB_D;
    const bit = i < 256 ? <i32>u256bit(k, i) : 0;
    c = (c << 1) | bit;
  }
  return c;
}

/**
 * 构造任意点 P 的 comb 表（P 无特殊要求，内部自行克隆）。
 *
 * Build the comb table for an arbitrary point P (no constraints on P; it is cloned
 * internally).
 */
function buildCombFor(p: JPoint): StaticArray<JPoint> {
  const S = new StaticArray<JPoint>(COMB_W);
  S[0] = clonePoint(p);
  for (let t = 1; t < COMB_W; t++) {
    let s = S[t - 1];
    for (let j = 0; j < COMB_D; j++) s = doublePoint(s);
    S[t] = s;
  }
  const G = new StaticArray<JPoint>(COMB_SIZE);
  G[0] = new JPoint(); // 无穷远
  //
  // the point at infinity
  for (let c = 1; c < COMB_SIZE; c++) {
    const low = c & -c;
    G[c] = addPoints(G[c ^ low], S[lowBitIndex(low)]);
  }
  return G;
}

/**
 * 构造基点 G 的 comb 表。
 *
 * Build the comb table for the base point G.
 */
function buildComb(): StaticArray<JPoint> {
  return buildCombFor(basePoint());
}

let g1CombCache: StaticArray<JPoint> = new StaticArray<JPoint>(0);

/**
 * 惰性取 comb 表（首次构造后缓存；坐标深拷贝到永久区，免被 arena 回卷覆盖）。
 *
 * 表项**转成仿射**（Z = 1）：构建时用一次 Montgomery 批量求逆（约 25µs，一次性），
 * 之后每次 scalarMulG 的 52 次点加都能走混合坐标（8M+3S 而非 12M+4S）。
 *
 * Fetch the comb table lazily (built once and cached; coordinates are deep-copied into
 * permanent memory so an arena rewind cannot overwrite them).
 *
 * Table entries are **converted to affine** (Z = 1): construction pays for one Montgomery
 * batch inversion (about 25µs, once), and afterwards each scalarMulG runs its 52
 * additions in mixed coordinates (8M+3S instead of 12M+4S).
 */
function combTable(): StaticArray<JPoint> {
  if (g1CombCache.length === 0) {
    const t = buildComb();
    for (let i = 0; i < t.length; i++) {
      const p = t[i];
      p.x = permU256(p.x);
      p.y = permU256(p.y);
      p.z = permU256(p.z);
    }
    batchToAffine(t); // G[0] 为无穷远（Z = 0），批量归一化会跳过
    //
    // G[0] is the point at infinity (Z = 0), which the batch normalisation skips
    g1CombCache = t;
  }
  return g1CombCache;
}

/**
 * 标量乘 G：R = k · G（固定基点 comb，仿射表 + 混合坐标点加）。
 *
 * Scalar multiplication by G: R = k · G (fixed-base comb, affine table plus mixed-
 * coordinate additions).
 */
export function scalarMulG(k: U256): JPoint {
  const G = combTable();
  const Q = clonePoint(G[combIndex(k, COMB_D - 1)]);
  for (let j = COMB_D - 2; j >= 0; j--) {
    doubleInto(Q, Q);
    const c = combIndex(k, j);
    if (c !== 0) addMixedInto(Q, Q, G[c]); // G[0] 是无穷远，跳过
    //
    // G[0] is the point at infinity, so skip it
  }
  return Q;
}

// ---------- 联合标量乘 s·G + t·P（验签用） ----------
//
// 「comb 算 s·G + wNAF 算 t·P 再相加」要 51 + 256 = 307 次倍点；两条 wNAF 共享
// 同一串倍点后只需 256 次（省掉 comb 那 51 次倍点），代价是 s 侧要多做 ~43 次点加
// （G 的 wNAF 表），而点加远比倍点便宜。G 的表与 comb 表一样惰性缓存、且转仿射。
//
// ---------- Joint scalar multiplication s·G + t·P (for verification) ----------
//
// "comb for s·G plus wNAF for t·P, then add" costs 51 + 256 = 307 doublings; once the two
// wNAFs share one doubling chain it is only 256 (saving the 51 comb doublings), at the
// price of ~43 extra additions on the s side (G's wNAF table) — and an addition is far
// cheaper than a doubling. G's table is lazily cached like the comb table and converted
// to affine.

let g1WnafCache: StaticArray<JPoint> = new StaticArray<JPoint>(0); // 16 项：0..7 正，8..15 负
//
// 16 entries: 0..7 positive, 8..15 negative

/**
 * G 的 wNAF 预计算表（G, 3G, …, 15G 及其负），转仿射后永久缓存。
 * 仿射 → 联合循环里的 G 侧加法可走混合坐标（8M+3S）。
 *
 * G's wNAF precomputation table (G, 3G, …, 15G and their negatives), cached permanently
 * after conversion to affine.
 * Affine ⇒ the G-side additions in the joint loop can use mixed coordinates (8M+3S).
 */
function gWnafTable(): StaticArray<JPoint> {
  if (g1WnafCache.length === 0) {
    const all = new StaticArray<JPoint>(WNAF_TABLE * 2);
    all[0] = basePoint();
    const step = doublePoint(all[0]); // 2G
    for (let i = 1; i < WNAF_TABLE; i++) all[i] = addPoints(all[i - 1], step);
    for (let i = 0; i < WNAF_TABLE; i++) all[WNAF_TABLE + i] = negate(all[i]);
    for (let i = 0; i < all.length; i++) {
      const q = all[i];
      q.x = permU256(q.x);
      q.y = permU256(q.y);
      q.z = permU256(q.z);
    }
    batchToAffine(all);
    g1WnafCache = all;
  }
  return g1WnafCache;
}

/**
 * 联合标量乘：R = s·G + t·P（Jacobian，未归一化）。
 *
 * 两条 wNAF（宽度 5）共享同一条倍点链 —— 每轮一次倍点，然后按各自的 digit
 * 各加一次。G 侧走缓存的仿射表 + 混合坐标加法，P 侧是每次现算的 Jacobian 表。
 * 返回未归一点，调用方自行 toAffine（合并后只付 1 次求逆）。
 *
 * Joint scalar multiplication: R = s·G + t·P (Jacobian, not normalised).
 *
 * The two wNAFs (width 5) share a single doubling chain — one doubling per round, then
 * one addition per side according to its digit. The G side uses the cached affine table
 * with mixed-coordinate additions; the P side uses a Jacobian table computed per call.
 * The result is unnormalised; the caller runs toAffine (paying one inversion for the
 * merged point).
 */
export function scalarMulGAnd(s: U256, t: U256, p: JPoint): JPoint {
  const ds = arenaAlloc(<usize>WNAF_LEN * 4);
  const dt = arenaAlloc(<usize>WNAF_LEN * 4);
  const ns = wnaf(s, ds);
  const nt = wnaf(t, dt);
  const G = gWnafTable();

  // P 的预计算表 P, 3P, …, 15P 及其负（P 每次不同，只能现算）
  //
  // P's precomputed table P, 3P, …, 15P and their negatives (P differs every call, so it
  // must be computed here)
  const table = new StaticArray<JPoint>(WNAF_TABLE);
  const negTable = new StaticArray<JPoint>(WNAF_TABLE);
  table[0] = clonePoint(p);
  const step = doublePoint(p);
  for (let i = 1; i < WNAF_TABLE; i++) table[i] = addPoints(table[i - 1], step);
  for (let i = 0; i < WNAF_TABLE; i++) negTable[i] = negate(table[i]);

  const len = ns > nt ? ns : nt;
  const Q = new JPoint(); // 无穷远
  //
  // the point at infinity
  for (let i = len - 1; i >= 0; i--) {
    if (i !== len - 1) doubleInto(Q, Q);
    if (i < ns) {
      const d = load<i32>(ds + ((<usize>i) << 2));
      if (d > 0) addMixedInto(Q, Q, G[(d - 1) >> 1]);
      else if (d < 0) addMixedInto(Q, Q, G[WNAF_TABLE + ((-d - 1) >> 1)]);
    }
    if (i < nt) {
      const d = load<i32>(dt + ((<usize>i) << 2));
      if (d > 0) addInto(Q, Q, table[(d - 1) >> 1]);
      else if (d < 0) addInto(Q, Q, negTable[(-d - 1) >> 1]);
    }
  }
  return Q;
}

/**
 * Jacobian → 仿射：返回 (x, y)。Z == 0 时返回全 0。
 *
 * Jacobian → affine: returns (x, y). Returns all zeros when Z == 0.
 */
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

// ---------- 公钥预计算（多槽 comb 表 + LRU） ----------
//
// 任意固定点 P 的 comb 表：与 scalarMulG 同构。构建一次后 k·P 从 256 次倍点
// 降到 52 次（实测底层 encryptOut 2.1×、端到端 1.9×），代价是一次性建表（约 280 µs）。
//
// 槽位固定 8 个，每槽 3 KiB，全部落在永久区一块**固定**的 24 KiB 里：prepare 只覆盖
// 槽位，不追加分配，永久区不会随公钥数量增长。满了按 LRU（最近最少使用）淘汰。
//
// **只有显式 prepare 才会建表**：encrypt 命中就 comb，不命中直接回退 wNAF，绝不隐式
// 建表 —— 否则外部可控的公钥就能反复触发 280 µs 建表，形成放大面。
//
// ---------- Public-key precomputation (multi-slot comb table + LRU) ----------
//
// The comb table for an arbitrary fixed point P is isomorphic to scalarMulG. Once built,
// k·P drops from 256 doublings to 52 (measured 2.1× at the encryptOut level and 1.9× end
// to end), at the cost of one table build (about 280 µs).
//
// There are a fixed 8 slots of 3 KiB each, all inside one **fixed** 24 KiB block of
// permanent memory: prepare only overwrites a slot and never allocates further, so
// permanent memory does not grow with the number of public keys. When full, the LRU
// (least recently used) slot is evicted.
//
// **A table is only built by an explicit prepare**: on a hit encrypt uses comb, on a miss
// it falls back to wNAF and never builds implicitly — otherwise an externally controlled
// public key could repeatedly trigger a 280 µs table build, creating an amplification
// surface.

const COMB_SLOTS = 8;

const PREPARED_COMB_BASE: usize = permAlloc(COMB_SLOTS * COMB_SIZE * 3 * 32);
const PREPARED_PUB: usize = permAlloc(COMB_SLOTS * 64); // 每槽公钥指纹 x || y
//
// the public-key fingerprint (x || y) of each slot

const PREPARED_POINTS = new StaticArray<JPoint>(COMB_SLOTS * COMB_SIZE);
for (let s = 0; s < COMB_SLOTS; s++) {
  for (let i = 0; i < COMB_SIZE; i++) {
    const q = new JPoint();
    const base = PREPARED_COMB_BASE + <usize>(s * COMB_SIZE + i) * 96;
    q.x = base;
    q.y = base + 32;
    q.z = base + 64;
    PREPARED_POINTS[s * COMB_SIZE + i] = q;
  }
}

const SLOT_VALID = new StaticArray<u8>(COMB_SLOTS);
const SLOT_TICK = new StaticArray<u64>(COMB_SLOTS);
let slotCapacity = COMB_SLOTS;
let tick: u64 = 0;

/**
 * 两个 32 字节大端数是否逐字节相等。
 *
 * Whether two 32-byte big-endian numbers are byte-for-byte equal.
 */
function ptrEq32(a: usize, b: usize): bool {
  for (let i: usize = 0; i < 32; i += 8) {
    if (load<u64>(a + i) !== load<u64>(b + i)) return false;
  }
  return true;
}

/**
 * 设置可用槽数（1..COMB_SLOTS）。缩小后高槽位不再被查找。
 *
 * Set the number of usable slots (1..COMB_SLOTS). After shrinking, the higher slots are
 * no longer looked up.
 */
export function setCombCapacity(capacity: i32): void {
  if (capacity < 1) capacity = 1;
  if (capacity > COMB_SLOTS) capacity = COMB_SLOTS;
  slotCapacity = capacity;
}

/**
 * 查找公钥对应的槽，命中时刷新 LRU 时间戳。
 *
 * @returns 槽索引，未命中返回 -1。
 *
 * Look up the slot for a public key, refreshing its LRU timestamp on a hit.
 *
 * @returns The slot index, or -1 on a miss.
 */
export function lookupCombSlot(xPtr: usize, yPtr: usize): i32 {
  for (let s = 0; s < slotCapacity; s++) {
    if (SLOT_VALID[s] === 0) continue;
    const fp = PREPARED_PUB + <usize>s * 64;
    if (ptrEq32(fp, xPtr) && ptrEq32(fp + 32, yPtr)) {
      tick++;
      SLOT_TICK[s] = tick;
      return s;
    }
  }
  return -1;
}

/**
 * 为公钥构建 comb 表；同一公钥已存在则直接复用。
 *
 * 满了按 LRU 淘汰：取 `SLOT_TICK` 最小的槽覆盖。
 *
 * @returns 槽索引。
 *
 * Build the comb table for a public key; reused directly when the same key is present.
 *
 * When full, LRU eviction overwrites the slot with the smallest `SLOT_TICK`.
 *
 * @returns The slot index.
 */
export function prepareCombFor(xPtr: usize, yPtr: usize): i32 {
  const existing = lookupCombSlot(xPtr, yPtr);
  if (existing >= 0) return existing;

  let slot = -1;
  for (let s = 0; s < slotCapacity; s++) {
    if (SLOT_VALID[s] === 0) {
      slot = s;
      break;
    }
  }
  if (slot < 0) {
    slot = 0;
    for (let s = 1; s < slotCapacity; s++) {
      if (SLOT_TICK[s] < SLOT_TICK[slot]) slot = s;
    }
  }

  const p = new JPoint();
  p.x = u256fromMemBE(xPtr);
  p.y = u256fromMemBE(yPtr);
  p.z = u256fromU32(1);

  const t = buildCombFor(p);
  batchToAffine(t); // 仿射表 → 后续点加可走混合坐标 8M+3S
  //
  // affine table → later additions can use mixed coordinates, 8M+3S
  const base = slot * COMB_SIZE;
  for (let i = 0; i < COMB_SIZE; i++) {
    const src = t[i];
    const dst = PREPARED_POINTS[base + i];
    memory.copy(dst.x, src.x, 32);
    memory.copy(dst.y, src.y, 32);
    memory.copy(dst.z, src.z, 32);
  }
  memory.copy(PREPARED_PUB + <usize>slot * 64, xPtr, 32);
  memory.copy(PREPARED_PUB + <usize>slot * 64 + 32, yPtr, 32);
  SLOT_VALID[slot] = 1;
  tick++;
  SLOT_TICK[slot] = tick;
  return slot;
}

/**
 * 清空所有槽（encrypt 立即回退到 wNAF）。
 *
 * Clear every slot (encrypt immediately falls back to wNAF).
 */
export function clearPreparedComb(): void {
  for (let s = 0; s < COMB_SLOTS; s++) {
    SLOT_VALID[s] = 0;
    SLOT_TICK[s] = 0;
  }
  tick = 0;
  memory.fill(PREPARED_PUB, 0, COMB_SLOTS * 64);
}

/**
 * 读某槽的公钥指纹（64 字节 x||y）；槽无效返回 0。
 *
 * Read a slot's public-key fingerprint (64 bytes x||y); returns 0 for an invalid slot.
 */
export function combSlotKeyOut(slot: i32, outPtr: usize): i32 {
  if (slot < 0 || slot >= slotCapacity) return 0;
  if (SLOT_VALID[slot] === 0) return 0;
  memory.copy(outPtr, PREPARED_PUB + <usize>slot * 64, 64);
  return 1;
}

/**
 * k·P，使用指定槽的预计算表。调用方须先确认槽有效。
 *
 * k·P using the precomputed table in the given slot. The caller must ensure the slot is
 * valid first.
 */
export function scalarMulPrepared(k: U256, slot: i32): JPoint {
  const base = slot * COMB_SIZE;
  const Q = clonePoint(PREPARED_POINTS[base + combIndex(k, COMB_D - 1)]);
  for (let j = COMB_D - 2; j >= 0; j--) {
    doubleInto(Q, Q);
    const c = combIndex(k, j);
    if (c !== 0) addMixedInto(Q, Q, PREPARED_POINTS[base + c]);
  }
  return Q;
}

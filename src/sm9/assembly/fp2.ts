// SM9 二次扩域 Fp2（AssemblyScript）。
//
// 定义：Fp2 = Fp[u]/(u² + 2)，即 u² = -2。
//   元素 a = a0 + a1·u，用**连续 64 字节裸指针**表示：a0 在 a、a1 在 a + 32
//   （每个分量是 field256 的 U256）。
//
// 所有运算复用 `./fp`（SM9 素域）。对齐 GmSSL 官方 SM9 实现（view/SM9.js）。
//
// 分配策略：每个算子分两层——
//   `fp2*To(out, …)` 原地写入调用者的 out（内部只用模块级 U256 scratch，
//     零堆分配）；`fp2*(…)` 薄包装：从 arena 分配 out 再调 To 版本。
//   扩域链（fp4/fp12/point）内部互相调用 To 版本，逐次分配的压力因此基本消失。
//
// 参考：GM/T 0044-2016。

import {
  arenaAlloc,
  u256copy,
  u256eq,
  u256fromBytes as u256fromBytesShared,
  u256fromU32,
  u256isZero,
  u256zero,
} from '../../common/assembly/field256';
import {
  fpAdd,
  fpAddTo,
  fpDiv2To,
  fpInv,
  fpMul,
  fpMulTo,
  fpSqr,
  fpSqrTo,
  fpSubTo,
  U256,
} from './fp';

/** Fp2 元素：64 字节，a0 在偏移 0、a1 在偏移 32。 */
export type Fp2 = usize;

/** Fp2 的字节数。 */
export const FP2_BYTES: usize = 64;

/** a1（虚部）地址。 */
function a1of(a: Fp2): U256 {
  return a + 32;
}

// ---------- 构造 / 转换 ----------

export function fp2zero(): Fp2 {
  const r = arenaAlloc(FP2_BYTES);
  memory.fill(r, 0, FP2_BYTES);
  return r;
}

export function fp2one(): Fp2 {
  const r = fp2zero();
  u256copy(ONE, r);
  return r;
}

/** 从 (a0, a1) 构造。 */
export function fp2set(a0: U256, a1: U256): Fp2 {
  const r = arenaAlloc(FP2_BYTES);
  u256copy(a0, r);
  u256copy(a1, a1of(r));
  return r;
}

/** 从字节数组读（a0 在前，各 32 字节大端）。 */
export function fp2fromBytes(b: Uint8Array, off: usize): Fp2 {
  const r = arenaAlloc(FP2_BYTES);
  u256copy(u256fromBytesShared(b, off), r);
  u256copy(u256fromBytesShared(b, off + 32), a1of(r));
  return r;
}

export function fp2copy(a: Fp2): Fp2 {
  const r = arenaAlloc(FP2_BYTES);
  u256copy(a, r);
  u256copy(a1of(a), a1of(r));
  return r;
}

/** 就地写入：dst := src（保持 dst 的地址不变）。 */
export function fp2Put(dst: Fp2, src: Fp2): void {
  u256copy(src, dst);
  u256copy(a1of(src), a1of(dst));
}

export function fp2isZero(a: Fp2): bool {
  return u256isZero(a) && u256isZero(a1of(a));
}

export function fp2eq(a: Fp2, b: Fp2): bool {
  return u256eq(a, b) && u256eq(a1of(a), a1of(b));
}

// ---------- scratch（To 算子内部工作区） ----------
//
// 非重入约束：这些算子都是叶子（内部只调 fp 层的 To/普通函数，不再调 fp2 层
// 的 To 算子），一次调用期间独占 scratch。
const S0 = u256zero();
const S1 = u256zero();
const S2 = u256zero();
const S3 = u256zero();
const S4 = u256zero();
const S5 = u256zero();
const ZERO = u256zero(); // 只读零常量
const ONE: U256 = u256fromU32(1);
const TRIPLE_TMP: Fp2 = arenaAlloc(FP2_BYTES); // fp2TriTo 的 Fp2 级暂存

// ---------- 加法 / 减法 / 取负 ----------

/** out = a + b（逐分量），允许 out 与 a / b 别名。 */
export function fp2AddTo(out: Fp2, a: Fp2, b: Fp2): void {
  fpAddTo(out, a, b);
  fpAddTo(a1of(out), a1of(a), a1of(b));
}

/** 加法：逐分量加。 */
export function fp2Add(a: Fp2, b: Fp2): Fp2 {
  const r = fp2zero();
  fp2AddTo(r, a, b);
  return r;
}

/** out = a - b。 */
export function fp2SubTo(out: Fp2, a: Fp2, b: Fp2): void {
  fpSubTo(out, a, b);
  fpSubTo(a1of(out), a1of(a), a1of(b));
}

/** 减法。 */
export function fp2Sub(a: Fp2, b: Fp2): Fp2 {
  const r = fp2zero();
  fp2SubTo(r, a, b);
  return r;
}

/** out = -a。 */
export function fp2NegTo(out: Fp2, a: Fp2): void {
  fpSubTo(out, ZERO, a);
  fpSubTo(a1of(out), ZERO, a1of(a));
}

/** 取负。 */
export function fp2Neg(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2NegTo(r, a);
  return r;
}

/** 乘 2（= a + a）。 */
export function fp2Dbl(a: Fp2): Fp2 {
  return fp2Add(a, a);
}

/** out = 2a。 */
export function fp2DblTo(out: Fp2, a: Fp2): void {
  fp2AddTo(out, a, a);
}

/** 乘 3（= 2a + a）。 */
export function fp2Tri(a: Fp2): Fp2 {
  return fp2Add(fp2Dbl(a), a);
}

/** out = 3a（允许 out 与 a 别名：先算到 scratch，避免第二次加法读到被覆盖的 a）。 */
export function fp2TriTo(out: Fp2, a: Fp2): void {
  fp2AddTo(TRIPLE_TMP, a, a); // TRIPLE_TMP = 2a
  fp2AddTo(out, TRIPLE_TMP, a); // out = 2a + a
}

/** out = a / 2（逐分量）。 */
export function fp2Div2To(out: Fp2, a: Fp2): void {
  fpDiv2To(out, a);
  fpDiv2To(a1of(out), a1of(a));
}

/** 除以 2（逐分量 mod p 减半）。 */
export function fp2Div2(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2Div2To(r, a);
  return r;
}

/** out = a · k（k ∈ Fp 标量）。 */
export function fp2MulFpTo(out: Fp2, a: Fp2, k: U256): void {
  fpMulTo(out, a, k);
  fpMulTo(a1of(out), a1of(a), k);
}

/** 乘以 Fp 标量。 */
export function fp2MulFp(a: Fp2, k: U256): Fp2 {
  const r = fp2zero();
  fp2MulFpTo(r, a, k);
  return r;
}

// ---------- 乘法 / 平方 ----------

/**
 * out = a · b：(a0 + a1 u)(b0 + b1 u)，u² = -2
 *   r0 = a0*b0 - 2*a1*b1
 *   r1 = a0*b1 + a1*b0
 *
 * Karatsuba：交叉项由 (a0+a1)(b0+b1) 一次求出，Fp 乘法 4 → 3 次。
 * 全部中间量落在 scratch，允许 out 与 a / b 别名（所有读取都发生在写 out 之前）。
 */
export function fp2MulTo(out: Fp2, a: Fp2, b: Fp2): void {
  fpMulTo(S0, a, b); // t0 = a0b0
  fpMulTo(S1, a1of(a), a1of(b)); // t1 = a1b1
  fpAddTo(S2, a, a1of(a));
  fpAddTo(S3, b, a1of(b));
  fpMulTo(S2, S2, S3); // s = (a0+a1)(b0+b1)
  fpSubTo(a1of(out), S2, S0);
  fpSubTo(a1of(out), a1of(out), S1); // r1 = s - t0 - t1
  fpAddTo(S3, S1, S1); // 2 t1
  fpSubTo(out, S0, S3); // r0 = t0 - 2 t1
}

/**
 * 乘法：(a0 + a1 u)(b0 + b1 u)，u² = -2
 *   r0 = a0*b0 - 2*a1*b1
 *   r1 = a0*b1 + a1*b0
 *
 * Karatsuba：交叉项由 (a0+a1)(b0+b1) 一次求出，Fp 乘法 4 → 3 次。
 */
export function fp2Mul(a: Fp2, b: Fp2): Fp2 {
  const r = fp2zero();
  fp2MulTo(r, a, b);
  return r;
}

/**
 * out = (a · b) · u（对齐 GmSSL fp2_mul_u）：
 *   r0 = -2·(a0 b1 + a1 b0)
 *   r1 = a0 b0 - 2·a1 b1
 *
 * 先用 Karatsuba 求 a*b 的两个分量，再乘 u。
 */
export function fp2MulUTo(out: Fp2, a: Fp2, b: Fp2): void {
  fpMulTo(S0, a, b);
  fpMulTo(S1, a1of(a), a1of(b));
  fpAddTo(S2, a, a1of(a));
  fpAddTo(S3, b, a1of(b));
  fpMulTo(S2, S2, S3);
  fpAddTo(S4, S1, S1);
  fpSubTo(S4, S0, S4); // m0 = a0b0 - 2 a1b1
  fpSubTo(S5, S2, S0);
  fpSubTo(S5, S5, S1); // m1 = a0b1 + a1b0
  fpAddTo(S0, S5, S5);
  fpSubTo(out, ZERO, S0); // r0 = -2 m1
  u256copy(S4, a1of(out)); // r1 = m0
}

/** (a · b) · u（对齐 GmSSL fp2_mul_u）。 */
export function fp2MulU(a: Fp2, b: Fp2): Fp2 {
  const r = fp2zero();
  fp2MulUTo(r, a, b);
  return r;
}

/**
 * out = a · u（单参，a·u）：
 *   r0 = -2 a1
 *   r1 = a0
 */
export function fp2TimesUTo(out: Fp2, a: Fp2): void {
  fpAddTo(S0, a1of(a), a1of(a));
  fpSubTo(out, ZERO, S0);
  u256copy(a, a1of(out));
}

/** a · u（单参）。 */
export function fp2TimesU(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2TimesUTo(r, a);
  return r;
}

/**
 * out = a²（复平方公式，2 次 Fp 乘法）：
 *   r0 = a0² - 2 a1²
 *   r1 = 2 a0 a1
 *
 * 取 m = a0·a1、p = (a0+a1)(a0−2a1)，则 r0 = p + m、r1 = 2m。
 */
export function fp2SqrTo(out: Fp2, a: Fp2): void {
  fpMulTo(S0, a, a1of(a)); // m = a0 a1
  fpAddTo(S1, a, a1of(a));
  fpAddTo(S2, a1of(a), a1of(a));
  fpSubTo(S2, a, S2); // a0 - 2a1
  fpMulTo(S1, S1, S2); // p = (a0+a1)(a0-2a1)
  fpAddTo(a1of(out), S0, S0); // r1 = 2m
  fpAddTo(out, S1, S0); // r0 = p + m
}

/**
 * 平方（复平方公式，2 次 Fp 乘法）。
 */
export function fp2Sqr(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2SqrTo(r, a);
  return r;
}

/**
 * out = a²  · u（对齐 GmSSL fp2_sqr_u）：
 *   r0 = -4 a0 a1
 *   r1 = a0² - 2 a1²
 */
export function fp2SqrUTo(out: Fp2, a: Fp2): void {
  fpMulTo(S0, a, a1of(a));
  fpAddTo(S1, S0, S0);
  fpAddTo(S1, S1, S1); // 4 a0 a1
  fpSubTo(out, ZERO, S1);
  fpSqrTo(S2, a);
  fpSqrTo(S3, a1of(a));
  fpAddTo(S3, S3, S3); // 2 a1²
  fpSubTo(a1of(out), S2, S3); // a0² - 2a1²
}

/**
 * (a0 + a1 u)² * u（对齐 GmSSL fp2_sqr_u）。
 */
export function fp2SqrU(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2SqrUTo(r, a);
  return r;
}

// ---------- 逆 / 共轭 ----------

/**
 * out = a^{-1}（对齐 GmSSL）：
 *   若 a0 == 0: r = (0, -1/(2 a1))
 *   若 a1 == 0: r = (1/a0, 0)
 *   否则 k = 1/(a0² + 2 a1²); r = (a0 k, -a1 k)
 */
export function fp2InvTo(out: Fp2, a: Fp2): void {
  if (u256isZero(a)) {
    fpAddTo(S0, a1of(a), a1of(a));
    const inv = fpInv(S0);
    fpSubTo(a1of(out), ZERO, inv);
    u256copy(ZERO, out);
    return;
  }
  if (u256isZero(a1of(a))) {
    const inv = fpInv(a);
    u256copy(inv, out);
    u256copy(ZERO, a1of(out));
    return;
  }
  fpSqrTo(S0, a);
  fpSqrTo(S1, a1of(a));
  fpAddTo(S1, S1, S1);
  fpAddTo(S0, S0, S1); // a0² + 2 a1²
  const k = fpInv(S0);
  fpMulTo(out, a, k);
  fpMulTo(a1of(out), a1of(a), k);
  fpSubTo(a1of(out), ZERO, a1of(out));
}

/** 逆（对齐 GmSSL）。 */
export function fp2Inv(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2InvTo(r, a);
  return r;
}

/** out = 共轭：a0 - a1 u。 */
export function fp2ConjugateTo(out: Fp2, a: Fp2): void {
  u256copy(a, out);
  fpSubTo(a1of(out), ZERO, a1of(a));
}

/** 共轭：a0 - a1 u。 */
export function fp2Conjugate(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2ConjugateTo(r, a);
  return r;
}

/** 是否等于 1 + 0u。 */
export function fp2isOne(a: Fp2): bool {
  return u256eq(a, ONE) && u256isZero(a1of(a));
}

void fpAdd;
void fpMul;
void fpSqr;

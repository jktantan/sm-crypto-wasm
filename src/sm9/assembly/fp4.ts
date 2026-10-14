// SM9 四次扩域 Fp4（AssemblyScript）。
//
// 定义：Fp4 = Fp2[v]/(v² − u)，元素 a = a0 + a1·v，用 StaticArray<Fp2>(2) 表示。
// 对齐 GmSSL 官方 SM9 实现（view/SM9.js）：fp4_mul 的交叉项用 fp2_mul_u。
//
// 分配策略同 fp2：`fp4*To` 原地写入 out（内部只用模块级 Fp4 scratch +
// fp2 的 To 算子，零堆分配），`fp4*` 薄包装分配 out 后调 To 版本。
//
// 参考：GM/T 0044-2016。

import { U256 } from './fp';
import {
  Fp2,
  fp2AddTo,
  fp2ConjugateTo,
  fp2eq,
  fp2InvTo,
  fp2isOne,
  fp2isZero,
  fp2MulFpTo,
  fp2MulTo,
  fp2MulUTo,
  fp2NegTo,
  fp2one,
  fp2Put,
  fp2SqrTo,
  fp2SqrUTo,
  fp2SubTo,
  fp2TimesUTo,
  fp2zero,
} from './fp2';

/** Fp4 元素：[a0, a1]，各为 Fp2。 */
export type Fp4 = StaticArray<Fp2>;

// ---------- 构造 / 转换 ----------

export function fp4zero(): Fp4 {
  const r = new StaticArray<Fp2>(2);
  r[0] = fp2zero();
  r[1] = fp2zero();
  return r;
}

export function fp4one(): Fp4 {
  const r = new StaticArray<Fp2>(2);
  r[0] = fp2one();
  r[1] = fp2zero();
  return r;
}

export function fp4set(a0: Fp2, a1: Fp2): Fp4 {
  const r = new StaticArray<Fp2>(2);
  r[0] = fp2cloneOf(a0);
  r[1] = fp2cloneOf(a1);
  return r;
}

/** fp2copy 的本地别名（避免 fp4set 每次调用多一层 import 间接）。 */
function fp2cloneOf(a: Fp2): Fp2 {
  const r = fp2zero();
  fp2Put(r, a);
  return r;
}

export function fp4copy(a: Fp4): Fp4 {
  return fp4set(a[0], a[1]);
}

export function fp4isZero(a: Fp4): bool {
  return fp2isZero(a[0]) && fp2isZero(a[1]);
}

export function fp4isOne(a: Fp4): bool {
  return fp2isOne(a[0]) && fp2isZero(a[1]);
}

export function fp4eq(a: Fp4, b: Fp4): bool {
  return fp2eq(a[0], b[0]) && fp2eq(a[1], b[1]);
}

// ---------- scratch ----------
const T0: Fp4 = fp4zero();
const T1: Fp4 = fp4zero();
const T2: Fp4 = fp4zero();
const T3: Fp4 = fp4zero();
const T4: Fp4 = fp4zero();
const T5: Fp4 = fp4zero();

// ---------- 加法 / 减法 / 取负 ----------

/** out = a + b。 */
export function fp4AddTo(out: Fp4, a: Fp4, b: Fp4): void {
  fp2AddTo(out[0], a[0], b[0]);
  fp2AddTo(out[1], a[1], b[1]);
}

export function fp4Add(a: Fp4, b: Fp4): Fp4 {
  const r = fp4zero();
  fp4AddTo(r, a, b);
  return r;
}

/** out = a - b。 */
export function fp4SubTo(out: Fp4, a: Fp4, b: Fp4): void {
  fp2SubTo(out[0], a[0], b[0]);
  fp2SubTo(out[1], a[1], b[1]);
}

export function fp4Sub(a: Fp4, b: Fp4): Fp4 {
  const r = fp4zero();
  fp4SubTo(r, a, b);
  return r;
}

/** out = -a。 */
export function fp4NegTo(out: Fp4, a: Fp4): void {
  fp2NegTo(out[0], a[0]);
  fp2NegTo(out[1], a[1]);
}

export function fp4Neg(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4NegTo(r, a);
  return r;
}

export function fp4Dbl(a: Fp4): Fp4 {
  return fp4Add(a, a);
}

/** out = a · b（Fp2 标量）。 */
export function fp4MulFp2To(out: Fp4, a: Fp4, b: Fp2): void {
  fp2MulTo(out[0], a[0], b);
  fp2MulTo(out[1], a[1], b);
}

/** 乘以 Fp2 标量。 */
export function fp4MulFp2(a: Fp4, b: Fp2): Fp4 {
  const r = fp4zero();
  fp4MulFp2To(r, a, b);
  return r;
}

/** out = a · k（Fp 标量）。 */
export function fp4MulFpTo(out: Fp4, a: Fp4, k: U256): void {
  fp2MulFpTo(out[0], a[0], k);
  fp2MulFpTo(out[1], a[1], k);
}

/** 乘以 Fp 标量。 */
export function fp4MulFp(a: Fp4, k: U256): Fp4 {
  const r = fp4zero();
  fp4MulFpTo(r, a, k);
  return r;
}

// ---------- 乘法 / 平方 ----------

/**
 * out = a · b，普通乘法 (a0 + a1 v)(b0 + b1 v)，v² = u：
 *   r0 = a0 b0 + u·(a1 b1)
 *   r1 = a0 b1 + a1 b0
 *
 * Karatsuba：交叉项 r1 由 (a0+a1)(b0+b1) 一次求出，fp2Mul 4 → 3 次。
 * 所有对 a / b 的读取都发生在写 out 之前，允许 out 与入参别名。
 */
export function fp4MulTo(out: Fp4, a: Fp4, b: Fp4): void {
  fp2MulTo(T0[0], a[0], b[0]); // t0
  fp2MulTo(T1[0], a[1], b[1]); // t1
  fp2AddTo(T2[0], a[0], a[1]);
  fp2AddTo(T3[0], b[0], b[1]);
  fp2MulTo(T2[0], T2[0], T3[0]); // s
  fp2TimesUTo(T3[0], T1[0]);
  fp2AddTo(out[0], T0[0], T3[0]); // r0 = t0 + u·t1
  fp2SubTo(out[1], T2[0], T0[0]);
  fp2SubTo(out[1], out[1], T1[0]); // r1 = s - t0 - t1
}

/**
 * 普通乘法 (a0 + a1 v)(b0 + b1 v)，v² = u。
 */
export function fp4Mul(a: Fp4, b: Fp4): Fp4 {
  const r = fp4zero();
  fp4MulTo(r, a, b);
  return r;
}

/**
 * out = (a·b)·v。设 m = a·b，则 m·v = u·m1 + m0·v。
 *   r0 = u·m1
 *   r1 = m0
 *
 * 其中 m 用 Karatsuba 求（fp2Mul 4 → 3 次），原实现直接展开成 4 次乘法。
 */
export function fp4MulVTo(out: Fp4, a: Fp4, b: Fp4): void {
  fp2MulTo(T0[0], a[0], b[0]);
  fp2MulTo(T1[0], a[1], b[1]);
  fp2AddTo(T2[0], a[0], a[1]);
  fp2AddTo(T3[0], b[0], b[1]);
  fp2MulTo(T2[0], T2[0], T3[0]);
  fp2TimesUTo(T4[0], T1[0]);
  fp2AddTo(T4[0], T0[0], T4[0]); // m0
  fp2SubTo(T5[0], T2[0], T0[0]);
  fp2SubTo(T5[0], T5[0], T1[0]); // m1
  fp2TimesUTo(out[0], T5[0]); // r0 = u·m1
  fp2Put(out[1], T4[0]); // r1 = m0
}

/** 乘以 v：(a·b)·v。 */
export function fp4MulV(a: Fp4, b: Fp4): Fp4 {
  const r = fp4zero();
  fp4MulVTo(r, a, b);
  return r;
}

/** out = a·v：(b0 + b1 v)·v = u·b1 + b0·v。 */
export function fp4TimesVTo(out: Fp4, a: Fp4): void {
  fp2Put(T0[0], a[0]); // 先存 a0，避免 out 与 a 别名时被覆盖
  fp2TimesUTo(out[0], a[1]);
  fp2Put(out[1], T0[0]);
}

/** 乘以 v（单参）：(b0 + b1 v)·v = u·b1 + b0·v。 */
export function fp4TimesV(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4TimesVTo(r, a);
  return r;
}

/**
 * out = a²（对齐 fp4_sqr）：
 *   r0 = a0² + (a1²·u)
 *   r1 = 2 a0 a1
 *
 * 交叉项用 Karatsuba 形式 (a0+a1)² − a0² − a1²，三次都是 fp2Sqr（比一次 fp2Mul 便宜）。
 */
export function fp4SqrTo(out: Fp4, a: Fp4): void {
  fp2SqrTo(T0[0], a[0]);
  fp2SqrTo(T1[0], a[1]);
  fp2AddTo(T2[0], a[0], a[1]);
  fp2SqrTo(T2[0], T2[0]);
  fp2TimesUTo(T3[0], T1[0]);
  fp2AddTo(out[0], T0[0], T3[0]);
  fp2SubTo(out[1], T2[0], T0[0]);
  fp2SubTo(out[1], out[1], T1[0]);
}

/**
 * 平方（对齐 fp4_sqr）。
 */
export function fp4Sqr(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4SqrTo(r, a);
  return r;
}

/**
 * out = v²·a 的平方（对齐 fp4_sqr_v）：
 *   r0 = 2·u·(a0 a1)
 *   r1 = a0² + a1²·u
 */
export function fp4SqrVTo(out: Fp4, a: Fp4): void {
  fp2MulUTo(T0[0], a[0], a[1]);
  fp2AddTo(T1[0], T0[0], T0[0]);
  fp2Put(out[0], T1[0]);
  fp2SqrTo(T2[0], a[0]);
  fp2SqrUTo(T3[0], a[1]);
  fp2AddTo(out[1], T2[0], T3[0]);
}

/** v²·a 的平方（对齐 fp4_sqr_v）。 */
export function fp4SqrV(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4SqrVTo(r, a);
  return r;
}

/**
 * out = a^{-1}（对齐 fp4_inv）：
 *   k = 1/(u·a1² − a0²)
 *   r0 = -(a0 k)
 *   r1 = a1 k
 */
export function fp4InvTo(out: Fp4, a: Fp4): void {
  fp2SqrUTo(T0[0], a[1]);
  fp2SqrTo(T1[0], a[0]);
  fp2SubTo(T0[0], T0[0], T1[0]); // k0 = u·a1² - a0²
  fp2InvTo(T2[0], T0[0]); // k
  fp2MulTo(T3[0], a[0], T2[0]);
  fp2NegTo(out[0], T3[0]);
  fp2MulTo(out[1], a[1], T2[0]);
}

/** 逆（对齐 fp4_inv）。 */
export function fp4Inv(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4InvTo(r, a);
  return r;
}

/** out = 共轭：a0 − a1 v。 */
export function fp4ConjugateTo(out: Fp4, a: Fp4): void {
  fp2Put(T0[0], a[0]);
  fp2NegTo(T1[0], a[1]);
  fp2Put(out[0], T0[0]);
  fp2Put(out[1], T1[0]);
}

/** 共轭：a0 − a1 v。 */
export function fp4Conjugate(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4ConjugateTo(r, a);
  return r;
}

/** out = Frobenius(a)，beta 为常数。 */
export function fp4FrobeniusTo(out: Fp4, a: Fp4, beta: Fp2): void {
  fp2ConjugateTo(T0[0], a[1]);
  fp2ConjugateTo(out[0], a[0]);
  fp2MulTo(out[1], T0[0], beta);
}

/** Frobenius（p 次幂）映射，对齐 fp4_frobenius。beta 为常数。 */
export function fp4Frobenius(a: Fp4, beta: Fp2): Fp4 {
  const r = fp4zero();
  fp4FrobeniusTo(r, a, beta);
  return r;
}

/** Frobenius²（= 共轭），对齐 fp4_frobenius2。 */
export function fp4Frobenius2(a: Fp4): Fp4 {
  return fp4Conjugate(a);
}

/** Frobenius³，对齐 fp4_frobenius3。 */
export function fp4Frobenius3(a: Fp4, beta: Fp2): Fp4 {
  const r = fp4zero();
  fp2ConjugateTo(r[0], a[0]);
  fp2ConjugateTo(T0[0], a[1]);
  fp2MulTo(T1[0], T0[0], beta);
  fp2NegTo(r[1], T1[0]);
  return r;
}

// 供上层使用的小工具。
export function fp4Zero(): Fp4 {
  return fp4zero();
}

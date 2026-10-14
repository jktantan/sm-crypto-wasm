// SM9 四次扩域 Fp4（AssemblyScript）。
//
// 定义：Fp4 = Fp2[v]/(v² − u)，元素 a = a0 + a1·v，用**连续 128 字节裸指针**
// 表示：a0 在 a、a1 在 a + 64（每个分量是 Fp2）。
// 对齐 GmSSL 官方 SM9 实现（view/SM9.js）：fp4_mul 的交叉项用 fp2_mul_u。
//
// 分配策略同 fp2：`fp4*To` 原地写入 out（内部只用模块级 Fp4 scratch +
// fp2 的 To 算子，零堆分配），`fp4*` 薄包装从 arena 分配 out 后调 To 版本。
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
} from './fp2';
import { arenaAlloc } from '../../common/assembly/field256';

/** Fp4 元素：128 字节，a0 在偏移 0、a1 在偏移 64。 */
export type Fp4 = usize;

/** Fp4 的字节数。 */
export const FP4_BYTES: usize = 128;

/** a1 的地址。 */
function a1of(a: Fp4): Fp2 {
  return a + 64;
}

// ---------- 构造 / 转换 ----------

export function fp4zero(): Fp4 {
  const r = arenaAlloc(FP4_BYTES);
  memory.fill(r, 0, FP4_BYTES);
  return r;
}

export function fp4one(): Fp4 {
  const r = fp4zero();
  fp2Put(r, fp2one());
  return r;
}

export function fp4set(a0: Fp2, a1: Fp2): Fp4 {
  const r = arenaAlloc(FP4_BYTES);
  fp2Put(r, a0);
  fp2Put(a1of(r), a1);
  return r;
}

export function fp4copy(a: Fp4): Fp4 {
  return fp4set(a, a1of(a));
}

/** 就地拷贝：dst := src（保持 dst 地址不变）。 */
export function fp4CopyInto(dst: Fp4, src: Fp4): void {
  fp2Put(dst, src);
  fp2Put(a1of(dst), a1of(src));
}

export function fp4isZero(a: Fp4): bool {
  return fp2isZero(a) && fp2isZero(a1of(a));
}

export function fp4isOne(a: Fp4): bool {
  return fp2isOne(a) && fp2isZero(a1of(a));
}

export function fp4eq(a: Fp4, b: Fp4): bool {
  return fp2eq(a, b) && fp2eq(a1of(a), a1of(b));
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
  fp2AddTo(out, a, b);
  fp2AddTo(a1of(out), a1of(a), a1of(b));
}

export function fp4Add(a: Fp4, b: Fp4): Fp4 {
  const r = fp4zero();
  fp4AddTo(r, a, b);
  return r;
}

/** out = a - b。 */
export function fp4SubTo(out: Fp4, a: Fp4, b: Fp4): void {
  fp2SubTo(out, a, b);
  fp2SubTo(a1of(out), a1of(a), a1of(b));
}

export function fp4Sub(a: Fp4, b: Fp4): Fp4 {
  const r = fp4zero();
  fp4SubTo(r, a, b);
  return r;
}

/** out = -a。 */
export function fp4NegTo(out: Fp4, a: Fp4): void {
  fp2NegTo(out, a);
  fp2NegTo(a1of(out), a1of(a));
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
  fp2MulTo(out, a, b);
  fp2MulTo(a1of(out), a1of(a), b);
}

/** 乘以 Fp2 标量。 */
export function fp4MulFp2(a: Fp4, b: Fp2): Fp4 {
  const r = fp4zero();
  fp4MulFp2To(r, a, b);
  return r;
}

/** out = a · k（Fp 标量）。 */
export function fp4MulFpTo(out: Fp4, a: Fp4, k: U256): void {
  fp2MulFpTo(out, a, k);
  fp2MulFpTo(a1of(out), a1of(a), k);
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
  fp2MulTo(T0, a, b); // t0
  fp2MulTo(T1, a1of(a), a1of(b)); // t1
  fp2AddTo(T2, a, a1of(a));
  fp2AddTo(T3, b, a1of(b));
  fp2MulTo(T2, T2, T3); // s
  fp2TimesUTo(T3, T1);
  fp2AddTo(out, T0, T3); // r0 = t0 + u·t1
  fp2SubTo(a1of(out), T2, T0);
  fp2SubTo(a1of(out), a1of(out), T1); // r1 = s - t0 - t1
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
  fp2MulTo(T0, a, b);
  fp2MulTo(T1, a1of(a), a1of(b));
  fp2AddTo(T2, a, a1of(a));
  fp2AddTo(T3, b, a1of(b));
  fp2MulTo(T2, T2, T3);
  fp2TimesUTo(T4, T1);
  fp2AddTo(T4, T0, T4); // m0
  fp2SubTo(T5, T2, T0);
  fp2SubTo(T5, T5, T1); // m1
  fp2TimesUTo(out, T5); // r0 = u·m1
  fp2Put(a1of(out), T4); // r1 = m0
}

/** 乘以 v：(a·b)·v。 */
export function fp4MulV(a: Fp4, b: Fp4): Fp4 {
  const r = fp4zero();
  fp4MulVTo(r, a, b);
  return r;
}

/** out = a·v：(b0 + b1 v)·v = u·b1 + b0·v。 */
export function fp4TimesVTo(out: Fp4, a: Fp4): void {
  fp2Put(T0, a); // 先存 a0，避免 out 与 a 别名时被覆盖
  fp2TimesUTo(out, a1of(a));
  fp2Put(a1of(out), T0);
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
  fp2SqrTo(T0, a);
  fp2SqrTo(T1, a1of(a));
  fp2AddTo(T2, a, a1of(a));
  fp2SqrTo(T2, T2);
  fp2TimesUTo(T3, T1);
  fp2AddTo(out, T0, T3);
  fp2SubTo(a1of(out), T2, T0);
  fp2SubTo(a1of(out), a1of(out), T1);
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
  fp2MulUTo(T0, a, a1of(a));
  fp2AddTo(T1, T0, T0);
  fp2Put(out, T1);
  fp2SqrTo(T2, a);
  fp2SqrUTo(T3, a1of(a));
  fp2AddTo(a1of(out), T2, T3);
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
  fp2SqrUTo(T0, a1of(a));
  fp2SqrTo(T1, a);
  fp2SubTo(T0, T0, T1); // k0 = u·a1² - a0²
  fp2InvTo(T2, T0); // k
  fp2MulTo(T3, a, T2);
  fp2NegTo(out, T3);
  fp2MulTo(a1of(out), a1of(a), T2);
}

/** 逆（对齐 fp4_inv）。 */
export function fp4Inv(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4InvTo(r, a);
  return r;
}

/** out = 共轭：a0 − a1 v。 */
export function fp4ConjugateTo(out: Fp4, a: Fp4): void {
  fp2Put(T0, a);
  fp2NegTo(T1, a1of(a));
  fp2Put(out, T0);
  fp2Put(a1of(out), T1);
}

/** 共轭：a0 − a1 v。 */
export function fp4Conjugate(a: Fp4): Fp4 {
  const r = fp4zero();
  fp4ConjugateTo(r, a);
  return r;
}

/** out = Frobenius(a)，beta 为常数。 */
export function fp4FrobeniusTo(out: Fp4, a: Fp4, beta: Fp2): void {
  fp2ConjugateTo(T0, a1of(a));
  fp2ConjugateTo(out, a);
  fp2MulTo(a1of(out), T0, beta);
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
  fp2ConjugateTo(r, a);
  fp2ConjugateTo(T0, a1of(a));
  fp2MulTo(T1, T0, beta);
  fp2NegTo(a1of(r), T1);
  return r;
}

// 供上层使用的小工具。
export function fp4Zero(): Fp4 {
  return fp4zero();
}

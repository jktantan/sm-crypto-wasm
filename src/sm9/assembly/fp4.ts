// SM9 四次扩域 Fp4（AssemblyScript）。
//
// 定义：Fp4 = Fp2[v]/(v² − u)，元素 a = a0 + a1·v，用 StaticArray<Fp2>(2) 表示。
// 对齐 GmSSL 官方 SM9 实现（view/SM9.js）：fp4_mul 的交叉项用 fp2_mul_u。
//
// 参考：GM/T 0044-2016。

import { U256 } from './fp';
import {
  Fp2,
  fp2zero,
  fp2one,
  fp2set,
  fp2copy,
  fp2isZero,
  fp2isOne,
  fp2eq,
  fp2Add,
  fp2Sub,
  fp2Neg,
  fp2Dbl,
  fp2Mul,
  fp2Sqr,
  fp2SqrU,
  fp2Inv,
  fp2Conjugate,
  fp2MulU,
  fp2MulFp,
} from './fp2';
import { u256zero } from '../../common/assembly/field256';

/** Fp4 元素：[a0, a1]，各为 Fp2。 */
export type Fp4 = StaticArray<Fp2>;

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
  r[0] = fp2copy(a0);
  r[1] = fp2copy(a1);
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

export function fp4Add(a: Fp4, b: Fp4): Fp4 {
  return fp4set(fp2Add(a[0], b[0]), fp2Add(a[1], b[1]));
}

export function fp4Sub(a: Fp4, b: Fp4): Fp4 {
  return fp4set(fp2Sub(a[0], b[0]), fp2Sub(a[1], b[1]));
}

export function fp4Neg(a: Fp4): Fp4 {
  return fp4set(fp2Neg(a[0]), fp2Neg(a[1]));
}

export function fp4Dbl(a: Fp4): Fp4 {
  return fp4Add(a, a);
}

/** 乘以 Fp2 标量。 */
export function fp4MulFp2(a: Fp4, b: Fp2): Fp4 {
  return fp4set(fp2Mul(a[0], b), fp2Mul(a[1], b));
}

/**
 * 普通乘法 (a0 + a1 v)(b0 + b1 v)，v² = u：
 *   r0 = a0 b0 + u·(a1 b1)
 *   r1 = a0 b1 + a1 b0
 */
export function fp4Mul(a: Fp4, b: Fp4): Fp4 {
  const t = fp2MulU(a[1], b[1]);
  const r0 = fp2Add(fp2Mul(a[0], b[0]), t);
  const r1 = fp2Add(fp2Mul(a[0], b[1]), fp2Mul(a[1], b[0]));
  return fp4set(r0, r1);
}

/**
 * 乘以 v：(a0 + a1 v)·v = a0 v + a1 v² = u·a1 + a0 v
 *   r0 = u·a1
 *   r1 = a0
 */
export function fp4MulV(a: Fp4, b: Fp4): Fp4 {
  const r0 = fp2Add(fp2MulU(a[0], b[1]), fp2MulU(a[1], b[0]));
  const r1 = fp2Add(fp2Mul(a[0], b[0]), fp2MulU(a[1], b[1]));
  return fp4set(r0, r1);
}

/**
 * 平方（对齐 fp4_sqr）：
 *   r0 = a0² + (a1²·u)
 *   r1 = 2 a0 a1
 */
export function fp4Sqr(a: Fp4): Fp4 {
  const r0 = fp2Add(fp2Sqr(a[0]), fp2SqrU(a[1]));
  const r1 = fp2Dbl(fp2Mul(a[0], a[1]));
  return fp4set(r0, r1);
}

/**
 * v²·a 的平方（对齐 fp4_sqr_v）：
 *   r0 = 2·u·(a0 a1)
 *   r1 = a0² + a1²·u
 */
export function fp4SqrV(a: Fp4): Fp4 {
  const r0 = fp2Dbl(fp2MulU(a[0], a[1]));
  const r1 = fp2Add(fp2Sqr(a[0]), fp2SqrU(a[1]));
  return fp4set(r0, r1);
}

/**
 * 逆（对齐 fp4_inv）：
 *   k = 1/(u·a1² − a0²)
 *   r0 = -(a0 k)
 *   r1 = a1 k
 */
export function fp4Inv(a: Fp4): Fp4 {
  const k0 = fp2Sub(fp2SqrU(a[1]), fp2Sqr(a[0]));
  const k = fp2Inv(k0);
  const r0 = fp2Neg(fp2Mul(a[0], k));
  const r1 = fp2Mul(a[1], k);
  return fp4set(r0, r1);
}

/** 共轭：a0 − a1 v。 */
export function fp4Conjugate(a: Fp4): Fp4 {
  return fp4set(a[0], fp2Neg(a[1]));
}

/** 乘以 Fp 标量。 */
export function fp4MulFp(a: Fp4, k: U256): Fp4 {
  return fp4set(fp2MulFp(a[0], k), fp2MulFp(a[1], k));
}

/** Frobenius（p 次幂）映射，对齐 fp4_frobenius。beta 为常数。 */
export function fp4Frobenius(a: Fp4, beta: Fp2): Fp4 {
  const r0 = fp2Conjugate(a[0]);
  const r1 = fp2Mul(fp2Conjugate(a[1]), beta);
  return fp4set(r0, r1);
}

/** Frobenius²（= 共轭），对齐 fp4_frobenius2。 */
export function fp4Frobenius2(a: Fp4): Fp4 {
  return fp4Conjugate(a);
}

/** Frobenius³，对齐 fp4_frobenius3。 */
export function fp4Frobenius3(a: Fp4, beta: Fp2): Fp4 {
  const r0 = fp2Conjugate(a[0]);
  const r1 = fp2Neg(fp2Mul(fp2Conjugate(a[1]), beta));
  return fp4set(r0, r1);
}

// 供上层使用的小工具。
export function fp4Zero(): Fp4 {
  return fp4zero();
}

void fp2one;
void u256zero;
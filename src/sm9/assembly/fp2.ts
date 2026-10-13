// SM9 二次扩域 Fp2（AssemblyScript）。
//
// 定义：Fp2 = Fp[u]/(u² + 2)，即 u² = -2。
//   元素 a = a0 + a1·u，用 StaticArray<U256>(2) 表示 {a0, a1}。
//
// 所有运算复用 `./fp`（SM9 素域）。对齐 GmSSL 官方 SM9 实现（view/SM9.js）。
//
// 参考：GM/T 0044-2016。

import {
  U256,
  fpAdd,
  fpSub,
  fpMul,
  fpSqr,
  fpInv,
  fpDiv2,
} from './fp';
import { u256zero, u256clone, u256isZero, u256eq, u256fromBytes as u256fromBytesShared } from '../../common/assembly/field256';

/** Fp2 元素：[a0, a1]。 */
export type Fp2 = StaticArray<U256>;

export function fp2zero(): Fp2 {
  const r = new StaticArray<U256>(2);
  r[0] = u256zero();
  r[1] = u256zero();
  return r;
}

export function fp2one(): Fp2 {
  const r = new StaticArray<U256>(2);
  r[0] = u256zero();
  r[0][0] = 1;
  r[1] = u256zero();
  return r;
}

/** 从 (a0, a1) 构造。 */
export function fp2set(a0: U256, a1: U256): Fp2 {
  const r = new StaticArray<U256>(2);
  r[0] = u256clone(a0);
  r[1] = u256clone(a1);
  return r;
}

/** 从字节数组读（a0 在前，各 32 字节大端）。 */
export function fp2fromBytes(b: Uint8Array, off: usize): Fp2 {
  const r = new StaticArray<U256>(2);
  r[0] = u256fromBytesShared(b, off);
  r[1] = u256fromBytesShared(b, off + 32);
  return r;
}

export function fp2copy(a: Fp2): Fp2 {
  return fp2set(a[0], a[1]);
}

export function fp2isZero(a: Fp2): bool {
  return u256isZero(a[0]) && u256isZero(a[1]);
}

export function fp2eq(a: Fp2, b: Fp2): bool {
  return u256eq(a[0], b[0]) && u256eq(a[1], b[1]);
}

/** 加法：逐分量加。 */
export function fp2Add(a: Fp2, b: Fp2): Fp2 {
  return fp2set(fpAdd(a[0], b[0]), fpAdd(a[1], b[1]));
}

/** 减法。 */
export function fp2Sub(a: Fp2, b: Fp2): Fp2 {
  return fp2set(fpSub(a[0], b[0]), fpSub(a[1], b[1]));
}

/** 取负。 */
export function fp2Neg(a: Fp2): Fp2 {
  const z = u256zero();
  return fp2set(fpSub(z, a[0]), fpSub(z, a[1]));
}

/** 乘 2。 */
export function fp2Dbl(a: Fp2): Fp2 {
  return fp2Add(a, a);
}

/** 乘 3。 */
export function fp2Tri(a: Fp2): Fp2 {
  return fp2Add(fp2Dbl(a), a);
}

/** 除以 2（逐分量 mod p 减半）。 */
export function fp2Div2(a: Fp2): Fp2 {
  return fp2set(fpDiv2(a[0]), fpDiv2(a[1]));
}

/** 乘以 Fp 标量。 */
export function fp2MulFp(a: Fp2, k: U256): Fp2 {
  return fp2set(fpMul(a[0], k), fpMul(a[1], k));
}

/**
 * 乘法：(a0 + a1 u)(b0 + b1 u)，u² = -2
 *   r0 = a0*b0 - 2*a1*b1
 *   r1 = a0*b1 + a1*b0
 */
export function fp2Mul(a: Fp2, b: Fp2): Fp2 {
  const t0 = fpMul(a[0], b[0]);
  const t1 = fpMul(a[1], b[1]);
  const r0 = fpSub(t0, fpAdd(t1, t1)); // a0b0 - 2 a1b1
  const r1 = fpAdd(fpMul(a[0], b[1]), fpMul(a[1], b[0]));
  return fp2set(r0, r1);
}

/**
 * (a * b) * u（对齐 GmSSL fp2_mul_u）：
 *   r0 = -2·(a0 b1 + a1 b0)
 *   r1 = a0 b0 - 2·a1 b1
 */
export function fp2MulU(a: Fp2, b: Fp2): Fp2 {
  const r0 = fpSub(u256zero(), fpAdd(fpAdd(fpMul(a[0], b[1]), fpMul(a[1], b[0])), fpAdd(fpMul(a[0], b[1]), fpMul(a[1], b[0]))));
  const r1 = fpSub(fpMul(a[0], b[0]), fpAdd(fpMul(a[1], b[1]), fpMul(a[1], b[1])));
  return fp2set(r0, r1);
}

/**
 * a * u（单参，a·u）：
 *   r0 = -2 a1
 *   r1 = a0
 */
export function fp2TimesU(a: Fp2): Fp2 {
  return fp2set(fpSub(u256zero(), fpAdd(a[1], a[1])), a[0]);
}

/**
 * 平方：
 *   r0 = a0² - 2 a1²
 *   r1 = 2 a0 a1
 */
export function fp2Sqr(a: Fp2): Fp2 {
  const r0 = fpSub(fpSqr(a[0]), fpAdd(fpSqr(a[1]), fpSqr(a[1])));
  const t = fpMul(a[0], a[1]);
  const r1 = fpAdd(t, t);
  return fp2set(r0, r1);
}

/**
 * 逆（对齐 GmSSL）：
 *   若 a0 == 0: r = (0, -1/(2 a1))
 *   若 a1 == 0: r = (1/a0, 0)
 *   否则 k = 1/(a0² + 2 a1²); r = (a0 k, -a1 k)
 */
export function fp2Inv(a: Fp2): Fp2 {
  if (u256isZero(a[0])) {
    const z = u256zero();
    const d = fpAdd(a[1], a[1]);
    return fp2set(z, fpSub(u256zero(), fpInv(d)));
  }
  if (u256isZero(a[1])) {
    return fp2set(fpInv(a[0]), u256zero());
  }
  const s = fpAdd(fpSqr(a[0]), fpAdd(fpSqr(a[1]), fpSqr(a[1])));
  const k = fpInv(s);
  const r0 = fpMul(a[0], k);
  const r1 = fpSub(u256zero(), fpMul(a[1], k));
  return fp2set(r0, r1);
}

/** 共轭：a0 - a1 u。 */
export function fp2Conjugate(a: Fp2): Fp2 {
  return fp2set(a[0], fpSub(u256zero(), a[1]));
}

/**
 * (a0 + a1 u)² * u（对齐 GmSSL fp2_sqr_u）：
 *   r0 = -4 a0 a1
 *   r1 = a0² - 2 a1²
 */
export function fp2SqrU(a: Fp2): Fp2 {
  const t = fpMul(a[0], a[1]);
  const r0 = fpSub(u256zero(), fpAdd(fpAdd(t, t), fpAdd(t, t))); // -4 a0 a1
  const r1 = fpSub(fpSqr(a[0]), fpAdd(fpSqr(a[1]), fpSqr(a[1]))); // a0² - 2a1²
  return fp2set(r0, r1);
}

/** 是否等于 1 + 0u。 */
export function fp2isOne(a: Fp2): bool {
  const z = u256zero();
  const one = u256zero();
  one[0] = 1;
  return u256eq(a[0], one) && u256eq(a[1], z);
}
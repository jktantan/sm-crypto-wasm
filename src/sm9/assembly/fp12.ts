// SM9 十二次扩域 Fp12（AssemblyScript）。
//
// 定义：Fp12 = Fp4[w]/(w³ − v)，元素 a = a0 + a1·w + a2·w²，用 StaticArray<Fp4>(3)。
// 对齐 GmSSL 官方 SM9（view/SM9.js）的 fp12_* 实现。
//
// 参考：GM/T 0044-2016。

import { U256 } from './fp';
import {
  Fp2, fp2zero, fp2one, fp2set, fp2copy, fp2eq, fp2Conjugate, fp2MulFp, fp2Neg,
} from './fp2';
import {
  Fp4, fp4zero, fp4one, fp4copy, fp4isZero, fp4eq, fp4Add, fp4Sub, fp4Neg, fp4Dbl,
  fp4Mul, fp4MulV, fp4Sqr, fp4SqrV, fp4Inv, fp4Conjugate, fp4MulFp, fp4MulFp2,
} from './fp4';
import { u256zero } from '../../common/assembly/field256';

/** Fp12 元素：[a0, a1, a2]，各为 Fp4。 */
export type Fp12 = StaticArray<Fp4>;

export function fp12zero(): Fp12 {
  const r = new StaticArray<Fp4>(3);
  r[0] = fp4zero();
  r[1] = fp4zero();
  r[2] = fp4zero();
  return r;
}

export function fp12one(): Fp12 {
  const r = new StaticArray<Fp4>(3);
  r[0] = fp4one();
  r[1] = fp4zero();
  r[2] = fp4zero();
  return r;
}

export function fp12set(a0: Fp4, a1: Fp4, a2: Fp4): Fp12 {
  const r = new StaticArray<Fp4>(3);
  r[0] = fp4copy(a0);
  r[1] = fp4copy(a1);
  r[2] = fp4copy(a2);
  return r;
}

export function fp12copy(a: Fp12): Fp12 {
  return fp12set(a[0], a[1], a[2]);
}

export function fp12isZero(a: Fp12): bool {
  return fp4isZero(a[0]) && fp4isZero(a[1]) && fp4isZero(a[2]);
}

export function fp12eq(a: Fp12, b: Fp12): bool {
  return fp4eq(a[0], b[0]) && fp4eq(a[1], b[1]) && fp4eq(a[2], b[2]);
}

export function fp12Add(a: Fp12, b: Fp12): Fp12 {
  return fp12set(fp4Add(a[0], b[0]), fp4Add(a[1], b[1]), fp4Add(a[2], b[2]));
}

export function fp12Sub(a: Fp12, b: Fp12): Fp12 {
  return fp12set(fp4Sub(a[0], b[0]), fp4Sub(a[1], b[1]), fp4Sub(a[2], b[2]));
}

export function fp12Neg(a: Fp12): Fp12 {
  return fp12set(fp4Neg(a[0]), fp4Neg(a[1]), fp4Neg(a[2]));
}

export function fp12Dbl(a: Fp12): Fp12 {
  return fp12Add(a, a);
}

/**
 * 乘法（对齐 fp12_mul），w³ = v：
 *   r0 = a0 b0 + v·(a1 b2 + a2 b1)
 *   r1 = a0 b1 + a1 b0 + v·(a2 b2)
 *   r2 = a0 b2 + a1 b1 + a2 b0
 */
export function fp12Mul(a: Fp12, b: Fp12): Fp12 {
  let r0 = fp4Mul(a[0], b[0]);
  r0 = fp4Add(r0, fp4MulV(a[1], b[2]));
  r0 = fp4Add(r0, fp4MulV(a[2], b[1]));

  let r1 = fp4Mul(a[0], b[1]);
  r1 = fp4Add(r1, fp4Mul(a[1], b[0]));
  r1 = fp4Add(r1, fp4MulV(a[2], b[2]));

  let r2 = fp4Mul(a[0], b[2]);
  r2 = fp4Add(r2, fp4Mul(a[1], b[1]));
  r2 = fp4Add(r2, fp4Mul(a[2], b[0]));

  return fp12set(r0, r1, r2);
}

/**
 * 平方（对齐 fp12_sqr）：
 *   r0 = a0² + 2·v·(a1 a2)
 *   r1 = 2 a0 a1 + v·a2²
 *   r2 = 2 a0 a2 + a1²
 */
export function fp12Sqr(a: Fp12): Fp12 {
  let r0 = fp4Sqr(a[0]);
  r0 = fp4Add(r0, fp4Dbl(fp4MulV(a[1], a[2])));

  let r1 = fp4Dbl(fp4Mul(a[0], a[1]));
  r1 = fp4Add(r1, fp4SqrV(a[2]));

  let r2 = fp4Dbl(fp4Mul(a[0], a[2]));
  r2 = fp4Add(r2, fp4Sqr(a[1]));

  return fp12set(r0, r1, r2);
}

/**
 * 逆（对齐 fp12_inv，分 a2 == 0 与否两支）。
 */
export function fp12Inv(a: Fp12): Fp12 {
  if (fp4isZero(a[2])) {
    // k = 1/(a0³ + v·a1³)
    let k = fp4Sqr(a[0]);
    k = fp4Mul(k, a[0]);
    let t = fp4SqrV(a[1]);
    t = fp4Mul(t, a[1]);
    k = fp4Add(k, t);
    k = fp4Inv(k);

    let r2 = fp4Mul(fp4Sqr(a[1]), k);
    let r1 = fp4Neg(fp4Mul(fp4Mul(a[0], a[1]), k));
    let r0 = fp4Mul(fp4Sqr(a[0]), k);
    return fp12set(r0, r1, r2);
  }
  // 通用分支
  let t0 = fp4Sub(fp4Sqr(a[1]), fp4Mul(a[0], a[2]));
  let t1 = fp4Sub(fp4Mul(a[0], a[1]), fp4SqrV(a[2]));
  let t2 = fp4Sub(fp4Sqr(a[0]), fp4MulV(a[1], a[2]));

  let t3 = fp4Sqr(t1);
  const prod = fp4Mul(t0, t2);
  t3 = fp4Sub(t3, prod);
  t3 = fp4Inv(t3);
  t3 = fp4Mul(a[2], t3);

  const r0 = fp4Mul(t2, t3);
  const r1 = fp4Neg(fp4Mul(t1, t3));
  const r2 = fp4Mul(t0, t3);
  return fp12set(r0, r1, r2);
}

/** 幂 a^k（k 为 256-bit uint，MSB-first）。k 以 U256（8×u32 小端）给出。 */
export function fp12Pow(a: Fp12, k: U256): Fp12 {
  let result = fp12one();
  let base = fp12copy(a);
  for (let i = 0; i < 256; i++) {
    if (((k[i >> 5] >>> (i & 31)) & 1) === 1) {
      result = fp12Mul(result, base);
    }
    base = fp12Sqr(base);
  }
  return result;
}

/** 幂 a^k（k 为小整数 u32）。 */
export function fp12PowSmall(a: Fp12, k: u32): Fp12 {
  let result = fp12one();
  let base = fp12copy(a);
  let e = k;
  while (e > 0) {
    if ((e & 1) === 1) result = fp12Mul(result, base);
    base = fp12Sqr(base);
    e >>= 1;
  }
  return result;
}

// ---------- Frobenius 映射 ----------

function fp2FromFp(k: U256): Fp2 {
  const r = fp2zero();
  r[0] = k;
  return r;
}

/** Fp12 的 p 次幂（Frobenius），对齐 fp12_frobenius。 */
export function fp12Frobenius(x: Fp12, alphas: StaticArray<U256>): Fp12 {
  // alphas = [alpha1, alpha2, alpha3, alpha4, alpha5]（均为 Fp 标量）
  const a1 = alphas[0], a2 = alphas[1], a3 = alphas[2], a4 = alphas[3], a5 = alphas[4];
  const xa = x[0], xb = x[1], xc = x[2];

  const ra = fp4set(fp2Conjugate(xa[0]), fp2MulFp(fp2Conjugate(xa[1]), a3));

  const rb = fp4set(
    fp2MulFp(fp2Conjugate(xb[0]), a1),
    fp2MulFp(fp2Conjugate(xb[1]), a4),
  );

  const rc = fp4set(
    fp2MulFp(fp2Conjugate(xc[0]), a2),
    fp2MulFp(fp2Conjugate(xc[1]), a5),
  );

  return fp12set(ra, rb, rc);
}

/** Fp12 的 p² 次幂，对齐 fp12_frobenius2。 */
export function fp12Frobenius2(x: Fp12, a2: U256, a4: U256): Fp12 {
  const a = fp4Conjugate(x[0]);
  const b = fp4MulFp(fp4Conjugate(x[1]), a2);
  const c = fp4MulFp(fp4Conjugate(x[2]), a4);
  return fp12set(a, b, c);
}

/** Fp12 的 p³ 次幂，对齐 fp12_frobenius3。 */
export function fp12Frobenius3(x: Fp12, beta: U256): Fp12 {
  const xa = x[0], xb = x[1], xc = x[2];

  const ra = fp4set(
    fp2Conjugate(xa[0]),
    fp2Neg(fp2MulFp(fp2Conjugate(xa[1]), beta)),
  );
  const rb = fp4set(
    fp2MulFp(fp2Conjugate(xb[0]), beta),
    fp2Conjugate(xb[1]),
  );
  const rc = fp4set(
    fp2Neg(fp2Conjugate(xc[0])),
    fp2MulFp(fp2Conjugate(xc[1]), beta),
  );
  return fp12set(ra, rb, rc);
}

/** Fp12 的 p⁶ 次幂，对齐 fp12_frobenius6。 */
export function fp12Frobenius6(x: Fp12): Fp12 {
  const a = fp4Conjugate(x[0]);
  const b = fp4Neg(fp4Conjugate(x[1]));
  const c = fp4Conjugate(x[2]);
  return fp12set(a, b, c);
}

export function fp12MulFp4(a: Fp12, b: Fp4): Fp12 {
  return fp12set(fp4Mul(a[0], b), fp4Mul(a[1], b), fp4Mul(a[2], b));
}

void fp2one; void fp2set; void fp2copy; void fp2eq; void fp4MulFp; void fp12MulFp4;
void u256zero; void fp2FromFp;
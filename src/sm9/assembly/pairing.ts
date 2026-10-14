// SM9 R-ate pairing（AssemblyScript）。
//
// 对齐 GmSSL 官方 SM9 实现（view/SM9.js）：
//   line function（eval_g_tangent / eval_g_line）→ Miller loop →
//   π1 / π2 校正 → 最终幂（final exponent）。
//
// 记法：twist 点（G2，Fp2 坐标）记作大写 Q，base 点（G1，Fp 坐标）记作 P。
// 与 GmSSL 的 _g 命名一致：num / den 两个 Fp12 分别累积分子与分母。
//
// 参考：GM/T 0044-2016。

import { U256, u256 } from './fp';
import {
  fp2Conjugate,
  fp2copy,
  fp2Div2,
  fp2Mul,
  fp2MulFp,
  fp2Neg,
  fp2Put,
  fp2Sqr,
  fp2Sub,
  fp2Tri,
} from './fp2';
import {
  Fp12,
  fp12Frobenius,
  fp12Frobenius2,
  fp12Frobenius3,
  fp12Frobenius6,
  fp12Inv,
  fp12Mul,
  fp12one,
  fp12Pow,
  fp12PowSmall,
  fp12Sqr,
  fp12zero,
} from './fp12';
import { G1, G2, g2Add, g2AddFull, g2Copy, g2Double } from './point';

// ---------- twist 点自同构 ----------

const PI1_C = '3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b';
const PI2_C = 'f300000002a3a6f2780272354f8b78f4d5fc11967be65334';

// 预构造：原先每次 twist 调用都重新解析一遍 hex。
const PI1_C_U = u256(PI1_C);
const PI2_C_U = u256(PI2_C);

/** π1：Frobenius 自同构。 */
export function twistPi1(Q: G2): G2 {
  const r = g2Copy(Q);
  fp2Put(r.X, fp2Conjugate(r.X));
  fp2Put(r.Y, fp2Conjugate(r.Y));
  fp2Put(r.Z, fp2MulFp(fp2Conjugate(r.Z), PI1_C_U));
  return r;
}

/** π2：乘以 twistor。 */
export function twistPi2(Q: G2): G2 {
  const r = g2Copy(Q);
  fp2Put(r.Z, fp2MulFp(r.Z, PI2_C_U));
  return r;
}

/** -π2。 */
export function twistNegPi2(Q: G2): G2 {
  const r = g2Copy(Q);
  fp2Put(r.Y, fp2Neg(r.Y));
  fp2Put(r.Z, fp2MulFp(r.Z, PI2_C_U));
  return r;
}

// ---------- line function ----------

/**
 * 切线（tangent）的分子/分母，对应 GmSSL 的 eval_g_tangent(num, den, T, Q)：
 *   T 为 twist 点（G2），Q 为 base 点（G1）。
 * 返回 [num, den]。
 */
export function evalGTangent(T: G2, Q: G1): StaticArray<Fp12> {
  const XP = T.X,
    YP = T.Y,
    ZP = T.Z;
  const xQ = Q.X,
    yQ = Q.Y;

  let t0 = fp2Sqr(ZP);
  let t1 = fp2Mul(t0, ZP);
  const b1v = fp2Mul(t1, YP);
  const a1v = fp2Neg(fp2MulFp(b1v, yQ));

  t1 = fp2Sqr(XP);
  t0 = fp2Mul(t0, t1);
  t0 = fp2MulFp(t0, xQ);
  t0 = fp2Tri(t0);
  const a4v = fp2Div2(t0);

  t1 = fp2Mul(t1, XP);
  t1 = fp2Tri(t1);
  t1 = fp2Div2(t1);
  t0 = fp2Sqr(YP);
  const a0v = fp2Sub(t0, t1);

  const num = fp12zero();
  const den = fp12zero();
  fp2Put(num[0][0], a0v);
  fp2Put(num[0][1], a1v);
  fp2Put(num[2][0], a4v);
  fp2Put(den[0][1], b1v);
  return staticPair(num, den);
}

/**
 * 割线（line）的分子/分母，对应 GmSSL 的 eval_g_line(num, den, T, P, Q)：
 *   T、P 为 twist 点（G2），Q 为 base 点（G1）。
 * 返回 [num, den]。
 */
export function evalGLine(T: G2, P: G2, Q: G1): StaticArray<Fp12> {
  const XT = T.X,
    YT = T.Y,
    ZT = T.Z;
  const XP = P.X,
    YP = P.Y,
    ZP = P.Z;
  const xQ = Q.X,
    yQ = Q.Y;

  let T0 = fp2Sqr(ZP);
  let T1 = fp2Mul(T0, XT);
  T0 = fp2Mul(T0, ZP);
  let T2 = fp2Sqr(ZT);
  let T3 = fp2Mul(T2, XP);
  T2 = fp2Mul(T2, ZT);
  T2 = fp2Mul(T2, YP);
  T1 = fp2Sub(T1, T3);
  T1 = fp2Mul(T1, ZT);
  T1 = fp2Mul(T1, ZP);
  const T4 = fp2Mul(T1, T0);
  const b1v = fp2copy(T4);

  T1 = fp2Mul(T1, YP);
  T3 = fp2Mul(T0, YT);
  T3 = fp2Sub(T3, T2);
  T0 = fp2Mul(T0, T3);
  T0 = fp2MulFp(T0, xQ);
  const a4v = fp2copy(T0);

  T3 = fp2Mul(T3, XP);
  T3 = fp2Mul(T3, ZP);
  T1 = fp2Sub(T1, T3);
  const a0v = fp2copy(T1);

  T2 = fp2MulFp(T4, yQ);
  const a1v = fp2Neg(T2);

  const num = fp12zero();
  const den = fp12zero();
  fp2Put(num[0][0], a0v);
  fp2Put(num[0][1], a1v);
  fp2Put(num[2][0], a4v);
  fp2Put(den[0][1], b1v);
  return staticPair(num, den);
}

function staticPair(a: Fp12, b: Fp12): StaticArray<Fp12> {
  const r = new StaticArray<Fp12>(2);
  r[0] = a;
  r[1] = b;
  return r;
}

// ---------- 最终幂常量 ----------

const ALPHA1 = '3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b';
const ALPHA2 = 'f300000002a3a6f2780272354f8b78f4d5fc11967be65334';
const ALPHA3 = '6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011';
const ALPHA4 = 'f300000002a3a6f2780272354f8b78f4d5fc11967be65333';
const ALPHA5 = '2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686';

const FE_A2 = 'd8000000019062ed0000b98b0cb27659';
const FE_A3 = '2400000000215d941';

// 预构造：原先每次 final exponent 都把这些 hex 重新解析一遍。
const ALPHA1_U = u256(ALPHA1);
const ALPHA2_U = u256(ALPHA2);
const ALPHA3_U = u256(ALPHA3);
const ALPHA4_U = u256(ALPHA4);
const ALPHA5_U = u256(ALPHA5);
const FE_A2_U = u256(FE_A2);
const FE_A3_U = u256(FE_A3);

/** Frobenius 系数（模块级常量，finalExponentHardPart 每次调用都用到）。 */
const ALPHAS: StaticArray<U256> = [ALPHA1_U, ALPHA2_U, ALPHA3_U, ALPHA4_U, ALPHA5_U];

/** 最终幂的 hard part，对应 GmSSL 的 final_exponent_hard_part。 */
function finalExponentHardPart(f: Fp12): Fp12 {
  const a2 = FE_A2_U;
  const a3 = FE_A3_U;
  const beta = ALPHA3_U;

  let t0 = fp12Pow(f, a3);
  t0 = fp12Inv(t0);
  let t1 = fp12Frobenius(t0, ALPHAS);
  t1 = fp12Mul(t0, t1);

  t0 = fp12Mul(t0, t1);
  let t2 = fp12Frobenius(f, ALPHAS);
  let t3 = fp12Mul(t2, f);
  t3 = fp12PowSmall(t3, 9);

  t0 = fp12Mul(t0, t3);
  t3 = fp12PowSmall(f, 4);
  t0 = fp12Mul(t0, t3);
  t2 = fp12Sqr(t2);
  t2 = fp12Mul(t2, t1);
  t1 = fp12Frobenius2(f, ALPHA2_U, ALPHA4_U);
  t1 = fp12Mul(t1, t2);

  t2 = fp12Pow(t1, a2);
  t0 = fp12Mul(t2, t0);
  t1 = fp12Frobenius3(f, beta);
  t1 = fp12Mul(t1, t0);
  return t1;
}

/** 最终幂，对应 GmSSL 的 final_exponent。 */
export function finalExponent(f: Fp12): Fp12 {
  let t0 = fp12Frobenius6(f);
  const t1 = fp12Inv(f);
  t0 = fp12Mul(t0, t1);
  const t1b = fp12Frobenius2(t0, ALPHA2_U, ALPHA4_U);
  t0 = fp12Mul(t0, t1b);
  return finalExponentHardPart(t0);
}

// ---------- Miller loop ----------

// 循环参数 a 的二进制串（与 GmSSL 一致）。
const ABITS = '00100000000000000000000000000000000000010000101011101100100111110';

// 预展开为位图：热循环里逐字符 charCodeAt 换成下标访问（ABITS.length == 65 == i32 位宽）。
const ABITS_LEN = ABITS.length;
const ABITS_BITS = new StaticArray<i32>(ABITS_LEN);
for (let i = 0; i < ABITS_LEN; i++) ABITS_BITS[i] = ABITS.charCodeAt(i) - 0x30;

/**
 * Miller loop 累积结果（final exponent 之前）。
 *
 * 只累乘分子：line function 的分母恒为 `b1v · v`（b1v ∈ Fp2，v 是 Fp4 生成元），
 * 而 v^((p⁶−1)(p²+1)) = (v^(p²−1))^(p²+1) = (−1)^(p²+1) = 1，b1v 同理 ——
 * 分母被 final exponent 的 easy part 整个消掉（6 次 twist 曲线的分母消除）。
 * GmSSL 的实现保留了分子分母两路，每次迭代要多一次 fp12Sqr 和 fp12Mul。
 */
export function millerLoop(Q: G2, P: G1): Fp12 {
  let T = g2Copy(Q);
  let f = fp12one();

  for (let i = 0; i < ABITS_LEN; i++) {
    f = fp12Sqr(f);
    const g1 = evalGTangent(T, P);
    f = fp12Mul(f, g1[0]);

    T = g2Double(T);

    if (ABITS_BITS[i] === 1) {
      const g2 = evalGLine(T, Q, P);
      f = fp12Mul(f, g2[0]);
      T = g2Add(T, Q);
    }
  }

  const Q1 = twistPi1(Q);
  const Q2 = twistNegPi2(Q);

  const g3 = evalGLine(T, Q1, P);
  f = fp12Mul(f, g3[0]);
  T = g2AddFull(T, Q1);

  const g4 = evalGLine(T, Q2, P);
  f = fp12Mul(f, g4[0]);
  T = g2AddFull(T, Q2);

  return f;
}

// ---------- 诊断：逐步 Miller loop ----------

/** 诊断：跑到第 step 步时的 T。 */
export function millerStepT(step: i32, Q: G2, P: G1): G2 {
  let T = g2Copy(Q);
  let fNum = fp12one();
  let fDen = fp12one();
  for (let i = 0; i < ABITS.length && i < step; i++) {
    fNum = fp12Sqr(fNum);
    fDen = fp12Sqr(fDen);
    const g1 = evalGTangent(T, P);
    fNum = fp12Mul(fNum, g1[0]);
    fDen = fp12Mul(fDen, g1[1]);
    T = g2Double(T);
    if (ABITS.charCodeAt(i) === 0x31) {
      const g2 = evalGLine(T, Q, P);
      fNum = fp12Mul(fNum, g2[0]);
      fDen = fp12Mul(fDen, g2[1]);
      T = g2Add(T, Q);
    }
  }
  // 追加步骤：step 66 → 加 Q1；step 67 → 加 Q2
  if (step > ABITS.length) {
    const Q1 = twistPi1(Q);
    const g3 = evalGLine(T, Q1, P);
    fNum = fp12Mul(fNum, g3[0]);
    fDen = fp12Mul(fDen, g3[1]);
    T = g2AddFull(T, Q1);
    if (step > ABITS.length + 1) {
      const Q2 = twistNegPi2(Q);
      const g4 = evalGLine(T, Q2, P);
      fNum = fp12Mul(fNum, g4[0]);
      fDen = fp12Mul(fDen, g4[1]);
      T = g2AddFull(T, Q2);
    }
  }
  return T;
}

/** 诊断：跑到第 step 步时的 [fNum, fDen]。 */
export function millerStepF(step: i32, Q: G2, P: G1): StaticArray<Fp12> {
  let T = g2Copy(Q);
  let fNum = fp12one();
  let fDen = fp12one();
  for (let i = 0; i < ABITS.length && i < step; i++) {
    fNum = fp12Sqr(fNum);
    fDen = fp12Sqr(fDen);
    const g1 = evalGTangent(T, P);
    fNum = fp12Mul(fNum, g1[0]);
    fDen = fp12Mul(fDen, g1[1]);
    T = g2Double(T);
    if (ABITS.charCodeAt(i) === 0x31) {
      const g2 = evalGLine(T, Q, P);
      fNum = fp12Mul(fNum, g2[0]);
      fDen = fp12Mul(fDen, g2[1]);
      T = g2Add(T, Q);
    }
  }
  if (step > ABITS.length) {
    const Q1 = twistPi1(Q);
    const g3 = evalGLine(T, Q1, P);
    fNum = fp12Mul(fNum, g3[0]);
    fDen = fp12Mul(fDen, g3[1]);
    T = g2AddFull(T, Q1);
    if (step > ABITS.length + 1) {
      const Q2 = twistNegPi2(Q);
      const g4 = evalGLine(T, Q2, P);
      fNum = fp12Mul(fNum, g4[0]);
      fDen = fp12Mul(fDen, g4[1]);
      T = g2AddFull(T, Q2);
    }
  }
  return staticPair(fNum, fDen);
}

/**
 * SM9 R-ate pairing：e(Q, P)。
 * @param Q twist 点（G2）
 * @param P base 点（G1）
 * @returns Fp12 中的配对值。
 */
export function sm9Pairing(Q: G2, P: G1): Fp12 {
  return finalExponent(millerLoop(Q, P));
}

// SM9 十二次扩域 Fp12（AssemblyScript）。
//
// 定义：Fp12 = Fp4[w]/(w³ − v)，元素 a = a0 + a1·w + a2·w²，用 StaticArray<Fp4>(3)。
// 对齐 GmSSL 官方 SM9（view/SM9.js）的 fp12_* 实现。
//
// 参考：GM/T 0044-2016。

import {
  u256clone,
  u256isOdd,
  u256isZero,
  u256shr1,
  u256zero,
} from '../../common/assembly/field256';
import { U256 } from './fp';
import {
  Fp2,
  fp2Add,
  fp2AddTo,
  fp2Conjugate,
  fp2copy,
  fp2eq,
  fp2Mul,
  fp2MulFp,
  fp2MulTo,
  fp2Neg,
  fp2one,
  fp2Put,
  fp2set,
  fp2SqrTo,
  fp2Sub,
  fp2SubTo,
  fp2TimesU,
  fp2TimesUTo,
  fp2zero,
} from './fp2';
import {
  Fp4,
  fp4Add,
  fp4AddTo,
  fp4Conjugate,
  fp4ConjugateTo,
  fp4copy,
  fp4eq,
  fp4Inv,
  fp4isZero,
  fp4Mul,
  fp4MulFp,
  fp4MulFp2To,
  fp4MulTo,
  fp4MulV,
  fp4Neg,
  fp4NegTo,
  fp4one,
  fp4Sqr,
  fp4SqrTo,
  fp4SqrV,
  fp4Sub,
  fp4SubTo,
  fp4set,
  fp4TimesV,
  fp4TimesVTo,
  fp4zero,
} from './fp4';

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

// ---------- scratch（To 算子内部工作区） ----------
//
// 非重入约束：fp12 的 To 算子内部只调 fp4 / fp2 的 To 算子（它们各自有独立
// scratch）与 fp 层的 To 算子，不再回调 fp12 的 To 算子，因此这些槽在单次调用
// 期间独占。U* 为 Fp4 级、W* 为 Fp2 级工作区。
const U0: Fp4 = fp4zero();
const U1: Fp4 = fp4zero();
const U2: Fp4 = fp4zero();
const U3: Fp4 = fp4zero();
const U4: Fp4 = fp4zero();
const U5: Fp4 = fp4zero();
const U6: Fp4 = fp4zero();
const U7: Fp4 = fp4zero();
const W0: Fp2 = fp2zero();
const W1: Fp2 = fp2zero();
const W2: Fp2 = fp2zero();
const W3: Fp2 = fp2zero();
const W4: Fp2 = fp2zero();
const W5: Fp2 = fp2zero();
const W6: Fp2 = fp2zero();
const W7: Fp2 = fp2zero();
const W8: Fp2 = fp2zero();
const W9: Fp2 = fp2zero();
const W10: Fp2 = fp2zero();
const W11: Fp2 = fp2zero();
const W12: Fp2 = fp2zero();
const W13: Fp2 = fp2zero();
const W14: Fp2 = fp2zero();
const W15: Fp2 = fp2zero();
const W16: Fp2 = fp2zero();
const W17: Fp2 = fp2zero();
const W18: Fp2 = fp2zero();
const W19: Fp2 = fp2zero();
const W20: Fp2 = fp2zero();
const W21: Fp2 = fp2zero();
const W22: Fp2 = fp2zero();
const W23: Fp2 = fp2zero();

/**
 * out = a · b（对齐 fp12_mul），w³ = v：
 *   r0 = a0 b0 + v·(a1 b2 + a2 b1)
 *   r1 = a0 b1 + a1 b0 + v·(a2 b2)
 *   r2 = a0 b2 + a1 b1 + a2 b0
 *
 * Karatsuba：6 个积 p0/p1/p2 + s01/s02/s12 求出全部交叉项，
 * fp4Mul 9 → 6 次（这是 pairing 最热的路径）。
 * 全部中间量走 scratch；允许 out 与 a / b 别名（写 out 前已读完入参）。
 */
export function fp12MulTo(out: Fp12, a: Fp12, b: Fp12): void {
  fp4MulTo(U0, a[0], b[0]); // p0
  fp4MulTo(U1, a[1], b[1]); // p1
  fp4MulTo(U2, a[2], b[2]); // p2
  fp4AddTo(U3, a[0], a[1]);
  fp4AddTo(U4, b[0], b[1]);
  fp4MulTo(U3, U3, U4); // s01
  fp4AddTo(U4, a[0], a[2]);
  fp4AddTo(U5, b[0], b[2]);
  fp4MulTo(U4, U4, U5); // s02
  fp4AddTo(U5, a[1], a[2]);
  fp4AddTo(U6, b[1], b[2]);
  fp4MulTo(U5, U5, U6); // s12

  fp4SubTo(U6, U3, U0);
  fp4SubTo(U6, U6, U1); // c01 = s01 - p0 - p1
  fp4SubTo(U7, U4, U0);
  fp4SubTo(U7, U7, U2); // c02 = s02 - p0 - p2
  fp4SubTo(U3, U5, U1);
  fp4SubTo(U3, U3, U2); // c12 = s12 - p1 - p2

  fp4TimesVTo(U4, U3); // v·c12
  fp4AddTo(out[0], U0, U4); // r0 = p0 + v·c12
  fp4TimesVTo(U4, U2); // v·p2
  fp4AddTo(out[1], U6, U4); // r1 = c01 + v·p2
  fp4AddTo(out[2], U7, U1); // r2 = c02 + p1
}

/**
 * 乘法（对齐 fp12_mul），w³ = v。
 */
export function fp12Mul(a: Fp12, b: Fp12): Fp12 {
  const r = fp12zero();
  fp12MulTo(r, a, b);
  return r;
}

/**
 * 平方（对齐 fp12_sqr），w³ = v：
 *   r0 = a0² + 2·v·(a1 a2)
 *   r1 = 2 a0 a1 + v·a2²
 *   r2 = 2 a0 a2 + a1²
 *
 * 交叉项 2·a_i·a_j 用 Karatsuba 形式 (a_i+a_j)² − a_i² − a_j² 求出，于是 6 次
 * 运算全是 fp4Sqr（原来 3 次 fp4Sqr + 3 次 fp4Mul）。fp4Sqr 走复平方，比 fp4Mul
 * 少一次 Fp2 乘法。这里系数正好是 2a_i a_j，所以不需要再除以 2。
 * final exponent 里有 200 次这样的平方，是 pairing 里最集中的一处。
 */
/**
 * out = a²（对齐 fp12_sqr），w³ = v：
 *   r0 = a0² + 2·v·(a1 a2)
 *   r1 = 2 a0 a1 + v·a2²
 *   r2 = 2 a0 a2 + a1²
 *
 * 交叉项 2·a_i·a_j 用 Karatsuba 形式 (a_i+a_j)² − a_i² − a_j² 求出，于是 6 次
 * 运算全是 fp4Sqr（原来 3 次 fp4Sqr + 3 次 fp4Mul）。fp4Sqr 走复平方，比 fp4Mul
 * 少一次 Fp2 乘法。这里系数正好是 2a_i a_j，所以不需要再除以 2。
 * final exponent 里有 200 次这样的平方，是 pairing 里最集中的一处。
 * 允许 out 与 a 别名（写 out 前已读完 a）。
 */
export function fp12SqrTo(out: Fp12, a: Fp12): void {
  fp4SqrTo(U0, a[0]); // A
  fp4SqrTo(U1, a[1]); // B
  fp4SqrTo(U2, a[2]); // C
  fp4AddTo(U3, a[0], a[1]);
  fp4SqrTo(U3, U3);
  fp4SubTo(U3, U3, U0);
  fp4SubTo(U3, U3, U1); // D = 2 a0 a1
  fp4AddTo(U4, a[0], a[2]);
  fp4SqrTo(U4, U4);
  fp4SubTo(U4, U4, U0);
  fp4SubTo(U4, U4, U2); // E = 2 a0 a2
  fp4AddTo(U5, a[1], a[2]);
  fp4SqrTo(U5, U5);
  fp4SubTo(U5, U5, U1);
  fp4SubTo(U5, U5, U2); // F = 2 a1 a2

  fp4TimesVTo(U6, U5);
  fp4AddTo(out[0], U0, U6); // r0 = A + v·F
  fp4TimesVTo(U6, U2);
  fp4AddTo(out[1], U3, U6); // r1 = D + v·C
  fp4AddTo(out[2], U4, U1); // r2 = E + B
}

/**
 * 平方（对齐 fp12_sqr），w³ = v。
 */
export function fp12Sqr(a: Fp12): Fp12 {
  const r = fp12zero();
  fp12SqrTo(r, a);
  return r;
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

    const r2 = fp4Mul(fp4Sqr(a[1]), k);
    const r1 = fp4Neg(fp4Mul(fp4Mul(a[0], a[1]), k));
    const r0 = fp4Mul(fp4Sqr(a[0]), k);
    return fp12set(r0, r1, r2);
  }
  // 通用分支
  const t0 = fp4Sub(fp4Sqr(a[1]), fp4Mul(a[0], a[2]));
  const t1 = fp4Sub(fp4Mul(a[0], a[1]), fp4SqrV(a[2]));
  const t2 = fp4Sub(fp4Sqr(a[0]), fp4MulV(a[1], a[2]));

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

/**
 * 稀疏乘：f × line。Miller loop 里 line 的分子只有三个非零 Fp2 分量：
 *   L[0][0] = a0, L[0][1] = a1, L[2][0] = a4（其余为 0）
 *
 * 直接按稀疏展开（Fp4 视角 L0 = a0+a1·v, L1 = 0, L2 = a4）：
 *   r0 = f0·L0 + v·(f1·L2)
 *   r1 = f1·L0 + v·(f2·L2)
 *   r2 = f2·L0 + f0·L2
 *
 * f_i·L0 为稠密×稠密（3 次 fp2Mul），f_i·L2 为稠密×稀疏（2 次 fp2Mul），
 * 共 15 次 fp2Mul，而通用 fp12Mul 是 18 次加一堆 fp4Add/fp4Sub。
 * 省下的还有：调用方不再构造整个 Fp12（12 个 Fp2）只为喂给乘法。
 */
export function fp12MulLine(f: Fp12, a0: Fp2, a1: Fp2, a4: Fp2): Fp12 {
  const r = fp12zero();
  fp12MulLineTo(r, f, a0, a1, a4);
  return r;
}

/**
 * out = f × line（稀疏乘的原地版）。允许 out 与 f 别名：所有对 f 的读取
 * （含 f_i·L0、f_i·L2 的全部乘积）都算进 scratch 之后才写 out。
 */
export function fp12MulLineTo(out: Fp12, f: Fp12, a0: Fp2, a1: Fp2, a4: Fp2): void {
  fp2AddTo(W15, a0, a1); // a0 + a1（六次复用）

  // f0·L0 = [x,y]·[a0,a1]：Karatsuba → p0 = W3, q0 = W4
  fp2MulTo(W0, f[0][0], a0);
  fp2MulTo(W1, f[0][1], a1);
  fp2AddTo(W2, f[0][0], f[0][1]);
  fp2MulTo(W2, W2, W15);
  fp2TimesUTo(W16, W1);
  fp2AddTo(W3, W0, W16);
  fp2SubTo(W4, W2, W0);
  fp2SubTo(W4, W4, W1);

  // f1·L0 → p1 = W8, q1 = W9
  fp2MulTo(W5, f[1][0], a0);
  fp2MulTo(W6, f[1][1], a1);
  fp2AddTo(W7, f[1][0], f[1][1]);
  fp2MulTo(W7, W7, W15);
  fp2TimesUTo(W16, W6);
  fp2AddTo(W8, W5, W16);
  fp2SubTo(W9, W7, W5);
  fp2SubTo(W9, W9, W6);

  // f2·L0 → p2 = W13, q2 = W14
  fp2MulTo(W10, f[2][0], a0);
  fp2MulTo(W11, f[2][1], a1);
  fp2AddTo(W12, f[2][0], f[2][1]);
  fp2MulTo(W12, W12, W15);
  fp2TimesUTo(W16, W11);
  fp2AddTo(W13, W10, W16);
  fp2SubTo(W14, W12, W10);
  fp2SubTo(W14, W14, W11);

  // f_i·L2 = [x,y]·[a4,0] = [x·a4, y·a4] → W17..W22
  fp2MulTo(W17, f[0][0], a4);
  fp2MulTo(W18, f[0][1], a4);
  fp2MulTo(W19, f[1][0], a4);
  fp2MulTo(W20, f[1][1], a4);
  fp2MulTo(W21, f[2][0], a4);
  fp2MulTo(W22, f[2][1], a4);

  // v·(x + y·v) = u·y + x·v → [u·y, x]
  // r0 = f0·L0 + v·(f1·L2)
  fp2TimesUTo(W23, W20);
  fp2AddTo(out[0][0], W3, W23);
  fp2AddTo(out[0][1], W4, W19);
  // r1 = f1·L0 + v·(f2·L2)
  fp2TimesUTo(W23, W22);
  fp2AddTo(out[1][0], W8, W23);
  fp2AddTo(out[1][1], W9, W21);
  // r2 = f2·L0 + f0·L2
  fp2AddTo(out[2][0], W13, W17);
  fp2AddTo(out[2][1], W14, W18);
}

/**
 * 幂 a^k（k 为 256-bit uint，MSB-first）。k 以 U256（8×u32 小端）给出。
 *
 * **NAF（非邻接形式）square-and-multiply**：指数先转 NAF（数字 ∈ {0,±1}，
 * 平均密度 1/3，无连续非零位），非零位为 -1 时乘 `a^{-1}`。配对的随机标量
 * popcount ≈ 128，NAF 平均非零位数 ≈ 85，`fp12Mul` 次数约降 1/3；
 * `fp12Inv`（Fp4 逆 ×1 + 一堆乘）比 ~8 次 `fp12Mul` 便宜，净收益为正。
 * final exponent 的固定指数（a2 popcount 40 → NAF 34）同样受益。
 *
 * 算法在整数域上对 2000 组随机（素模）指数与内置 pow 对拍验证过。
 * k == 0 返回 1；k == 1 走快速路径。
 */
export function fp12Pow(a: Fp12, k: U256): Fp12 {
  // 找最高有效位
  let msb = -1;
  for (let i = 255; i >= 0; i--) {
    if (((k[i >> 5] >>> (i & 31)) & 1) === 1) {
      msb = i;
      break;
    }
  }
  if (msb < 0) return fp12one(); // k == 0
  if (msb === 0) return a; // k == 1

  // 标量 NAF（modn.ts 的 u256naf 同款，Fp12 域内联）：
  //   k 奇：digit = 2 - (k mod 4)，k -= digit；否则 digit = 0；k >>= 1
  // 走 256 bit 位串（k < n < 2^256），digit 存 StaticArray<i8>。
  const kWork = u256clone(k);
  const naf = new StaticArray<i8>(msb + 2);
  for (let i = 0; i <= msb + 1; i++) {
    if (u256isOdd(kWork)) {
      const ki = <i8>(2 - <i32>(kWork[0] & 3));
      // kWork -= ki（ki ∈ {1,-1}）
      if (ki === 1) {
        kWork[0] = (kWork[0] - 1) & 0xffffffff;
      } else {
        // kWork += 1（进位最多传到 msb+1 之外不会：kWork 原奇）
        let c: u64 = 1;
        let idx = 0;
        while (c !== 0 && idx < 8) {
          const s = u64(kWork[idx]) + c;
          kWork[idx] = <u32>(s & 0xffffffff);
          c = s >>> 32;
          idx++;
        }
      }
      naf[i] = ki;
    } else {
      naf[i] = 0;
    }
    u256shr1(kWork);
  }

  // 逐位：从最高非零 NAF 位起步
  const inv = fp12Inv(a); // 每次调用算一次，之后 O(1) 使用
  let top = msb + 1;
  while (top >= 0 && naf[top] === 0) top--;
  let result = naf[top] === 1 ? fp12copy(a) : fp12copy(inv);
  for (let i = top - 1; i >= 0; i--) {
    result = fp12Sqr(result);
    if (naf[i] === 1) result = fp12Mul(result, a);
    else if (naf[i] === -1) result = fp12Mul(result, inv);
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
  const a1 = alphas[0],
    a2 = alphas[1],
    a3 = alphas[2],
    a4 = alphas[3],
    a5 = alphas[4];
  const xa = x[0],
    xb = x[1],
    xc = x[2];

  const ra = fp4set(fp2Conjugate(xa[0]), fp2MulFp(fp2Conjugate(xa[1]), a3));

  const rb = fp4set(fp2MulFp(fp2Conjugate(xb[0]), a1), fp2MulFp(fp2Conjugate(xb[1]), a4));

  const rc = fp4set(fp2MulFp(fp2Conjugate(xc[0]), a2), fp2MulFp(fp2Conjugate(xc[1]), a5));

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
  const xa = x[0],
    xb = x[1],
    xc = x[2];

  const ra = fp4set(fp2Conjugate(xa[0]), fp2Neg(fp2MulFp(fp2Conjugate(xa[1]), beta)));
  const rb = fp4set(fp2MulFp(fp2Conjugate(xb[0]), beta), fp2Conjugate(xb[1]));
  const rc = fp4set(fp2Neg(fp2Conjugate(xc[0])), fp2MulFp(fp2Conjugate(xc[1]), beta));
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

void fp2one;
void fp2set;
void fp2copy;
void fp2eq;
void fp4MulFp;
void fp12MulFp4;
void u256zero;
void fp2FromFp;

// SM9 基础域 Fp（AssemblyScript）—— **Montgomery 域**。
//
// SM9 用 BN 曲线（GM/T 0044-2016）：
//   p = b6400000 02a3a6f1 d603ab4f f58ec745 21f2934b 1a7aeedb e56f9b27 e351457d
//   n = b6400000 02a3a6f1 d603ab4f f58ec744 49f2934b 18ea8bee e56ee19c d69ecf25
//
// 通用 256-bit 模运算在 `src/common/assembly/field256.ts`；本文件固定 SM9 的 p/n。
//
// 为什么用 Montgomery：SM9 的 p 不是伪 Mersenne（不像 SM2 的 p 能做 Solinas 展开），
// 通用 Barrett 归约一次 512→256 要 q1·μ(9×9) + q3·m(9×8) ≈ 153 次 32×32 乘法，
// 加上 64 次部分积，单次模乘实测 ~179ns；CIOS Montgomery 只要 2×64 次乘法，
// 实测 ~98ns（1.8×）。p 是奇数，Montgomery 天然适配。
//
// 约定：**本模块的 Fp 元素一律是 Montgomery 表示**（ă = a·R mod p，R = 2²⁵⁶）。
//   - 线性运算（加/减/取负/除以 2）在两种表示下形式相同，不受影响；
//   - 乘/平方/逆/幂按 Montgomery 语义实现；
//   - 与外部字节、模块常量打交道的地方必须显式 fpToMont / fpFromMont 一次。
//     SM9 内部只在该边界转换（每次导出调用几处），域内全是 Montgomery 乘法。
//
// SM9 base field Fp (AssemblyScript) — a **Montgomery domain**.
//
// SM9 uses the BN curve of GM/T 0044-2016:
//   p = b6400000 02a3a6f1 d603ab4f f58ec745 21f2934b 1a7aeedb e56f9b27 e351457d
//   n = b6400000 02a3a6f1 d603ab4f f58ec744 49f2934b 18ea8bee e56ee19c d69ecf25
//
// The generic 256-bit modular arithmetic lives in
// `src/common/assembly/field256.ts`; this file pins p and n for SM9.
//
// Why Montgomery: SM9's p is not pseudo-Mersenne (unlike SM2's p, which admits a
// Solinas expansion), so the generic Barrett reduction costs
// q1·μ(9×9) + q3·m(9×8) ≈ 153 32×32 multiplies plus 64 partial products per
// 512→256 reduction, measured at ~179ns per modular multiply; CIOS Montgomery
// needs only 2×64 multiplies, measured at ~98ns (1.8×). p is odd, so Montgomery
// fits naturally.
//
// Convention: **every Fp element in this module is kept in Montgomery form**
// (ă = a·R mod p, R = 2²⁵⁶).
//   - Linear operations (add / sub / neg / halve) look the same in both forms;
//   - mul / square / inverse / pow follow Montgomery semantics;
//   - anything touching external bytes or module constants must convert
//     explicitly once via fpToMont / fpFromMont. SM9 only converts at those
//     boundaries (a few places per exported call); inside the field everything
//     is a Montgomery multiply.

import {
  modAdd,
  modAddInto,
  modHalve,
  modHalveInto,
  modInv,
  modMul,
  modSub,
  modSubInto,
  U256,
  u256bit,
  u256clone,
  u256fromHex,
  u256fromLimbs,
  u256fromU32,
  u256isZero,
} from '../../common/assembly/field256';

export { U256 };

// p 的小端 limb。
// p = b6400000 02a3a6f1 d603ab4f f58ec745 21f2934b 1a7aeedb e56f9b27 e351457d
//
// Little-endian limbs of p.
// p = b6400000 02a3a6f1 d603ab4f f58ec745 21f2934b 1a7aeedb e56f9b27 e351457d
export const SM9_P_LIMBS: StaticArray<u32> = [
  0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000,
];

// n 的小端 limb。
// n = b6400000 02a3a6f1 d603ab4f f58ec744 49f2934b 18ea8bee e56ee19c d69ecf25
//
// Little-endian limbs of n.
// n = b6400000 02a3a6f1 d603ab4f f58ec744 49f2934b 18ea8bee e56ee19c d69ecf25
export const SM9_N_LIMBS: StaticArray<u32> = [
  0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000,
];

// p / n 的 U256 形式只构造一次。每次 fpAdd/fpSub 都重建一份 U256 是这里最贵的
// 固定开销（实测 fpAdd ≈ 0.66µs ≈ fpMul 的 1/3，足以吃掉 Karatsuba 省下的那次乘法）。
// field256 的 mod* 系列只读模数（输入自行 clone），不会写这块共享内存。
//
// The U256 forms of p / n are built only once. Rebuilding a U256 on every
// fpAdd/fpSub was the most expensive fixed cost here (measured fpAdd ≈ 0.66µs
// ≈ 1/3 of fpMul, enough to eat the multiply that Karatsuba saves). The mod*
// helpers in field256 only read the modulus (they clone their inputs) and never
// write this shared memory.
const P_CACHE: U256 = u256fromLimbs(SM9_P_LIMBS);
const N_CACHE: U256 = u256fromLimbs(SM9_N_LIMBS);

/**
 * 返回 p（共享常量：只读，勿就地修改）。
 *
 * Returns p (a shared constant: read-only, never mutate it in place).
 */
export function pArr(): U256 {
  return P_CACHE;
}

/**
 * 返回 n（共享常量：只读，勿就地修改）。
 *
 * Returns n (a shared constant: read-only, never mutate it in place).
 */
export function nArr(): U256 {
  return N_CACHE;
}

// ---------- Montgomery 常数（R = 2²⁵⁶） ----------
// ---------- Montgomery constants (R = 2²⁵⁶) ----------
//
// R  = 2²⁵⁶ mod p        = 0x49bfffff…caeba83（即「1」的 Montgomery 表示）
// R² = 2⁵¹² mod p        = 0x2ea795a6…17e2d2（标准域 → Montgomery 的乘数）
// n0' = −p⁻¹ mod 2³²     = 0x2f2ee42b（CIOS 每轮的消去因子，p 奇故必存在）
//
// R  = 2²⁵⁶ mod p        = 0x49bfffff…caeba83 (Montgomery form of "1")
// R² = 2⁵¹² mod p        = 0x2ea795a6…17e2d2 (standard domain → Montgomery multiplier)
// n0' = −p⁻¹ mod 2³²     = 0x2f2ee42b (per-round CIOS cancellation factor; exists
//                         because p is odd)
const FP_R_HEX = '49bffffffd5c590e29fc54b00a7138bade0d6cb4e58511241a9064d81caeba83';
const FP_R2_HEX = '2ea795a656f62fbde479b522d6706e7b88f8105fae1a5d3f27dea312b417e2d2';
const FP_N0INV: u32 = 0x2f2ee42b;

// 1 的 Montgomery 表示（只读）
//
// Montgomery form of 1 (read-only).
const FP_R: U256 = u256fromHex(FP_R_HEX);
// 只读
//
// Read-only.
const FP_R2: U256 = u256fromHex(FP_R2_HEX);
// 标准域的 1（只读）
//
// The value 1 in the standard domain (read-only).
const FP_ONE: U256 = u256fromU32(1);

/**
 * CIOS 累加器 t[0..8] + 溢出位 t[9]（非重入：montMulInto 是叶子）。
 *
 * CIOS accumulator t[0..8] plus the overflow limb t[9] (not re-entrant:
 * montMulInto is a leaf).
 */
const MT: usize = heap.alloc(10 * 4);
/**
 * 条件减 p 的暂存（8 limb）。
 *
 * Scratch for the conditional subtraction of p (8 limbs).
 */
const MH: usize = heap.alloc(8 * 4);

/**
 * out = a · b · R⁻¹ mod p（CIOS，8×u32 limb）。
 *
 * 每轮：t += a·b[i]；m = t[0]·n0' mod 2³²；t = (t + m·p) / 2³²。
 * 8 轮后 t < 2p，做一次条件减 p 即得结果。允许 out 与 a / b 别名
 * （a / b 只在累加阶段被读，out 在最后才写）。
 *
 * out = a · b · R⁻¹ mod p (CIOS over 8 u32 limbs).
 *
 * Each round: t += a·b[i]; m = t[0]·n0' mod 2³²; t = (t + m·p) / 2³². After 8
 * rounds t < 2p, so one conditional subtraction of p yields the result. out may
 * alias a / b (a / b are only read during accumulation and out is written last).
 */
function montMulInto(out: U256, a: U256, b: U256): void {
  const t = MT;
  const p = P_CACHE;
  for (let i = 0; i < 10; i++) store<u32>(t + ((<usize>i) << 2), 0);
  for (let i = 0; i < 8; i++) {
    const bi = u64(load<u32>(b + ((<usize>i) << 2)));
    let c: u64 = 0;
    for (let j = 0; j < 8; j++) {
      const uv =
        u64(load<u32>(t + ((<usize>j) << 2))) + u64(load<u32>(a + ((<usize>j) << 2))) * bi + c;
      store<u32>(t + ((<usize>j) << 2), <u32>(uv & 0xffffffff));
      c = uv >>> 32;
    }
    let uv = u64(load<u32>(t + 32)) + c;
    store<u32>(t + 32, <u32>(uv & 0xffffffff));
    const t9 = <u32>(uv >>> 32);

    // m = t[0] · n0' mod 2³²；t = (t + m·p) >> 32
    const m = <u32>(load<u32>(t) * FP_N0INV);
    uv = u64(load<u32>(t)) + u64(m) * u64(load<u32>(p));
    c = uv >>> 32;
    for (let j = 1; j < 8; j++) {
      uv =
        u64(load<u32>(t + ((<usize>j) << 2))) + u64(m) * u64(load<u32>(p + ((<usize>j) << 2))) + c;
      store<u32>(t + ((<usize>(j - 1)) << 2), <u32>(uv & 0xffffffff));
      c = uv >>> 32;
    }
    uv = u64(load<u32>(t + 32)) + c;
    store<u32>(t + 28, <u32>(uv & 0xffffffff)); // t[7]
    store<u32>(t + 32, <u32>((uv >>> 32) + u64(t9))); // t[8] ∈ {0,1}
  }
  // t < 2p：试减一次 p；借位（且 t[8]==0）时保留原值，t[8]==1 时必可减
  //
  // t < 2p: try subtracting p once. On borrow (with t[8]==0) keep the original
  // value; with t[8]==1 the subtraction is always possible.
  const h = MH;
  let borrow: i64 = 0;
  for (let i = 0; i < 8; i++) {
    const d: i64 =
      i64(load<u32>(t + ((<usize>i) << 2))) - i64(load<u32>(p + ((<usize>i) << 2))) - borrow;
    store<u32>(h + ((<usize>i) << 2), <u32>(d & 0xffffffff));
    borrow = (d >> 63) & 1;
  }
  if (load<u32>(t + 32) === 0 && borrow !== 0) {
    for (let i = 0; i < 8; i++)
      store<u32>(out + ((<usize>i) << 2), load<u32>(t + ((<usize>i) << 2)));
  } else {
    for (let i = 0; i < 8; i++)
      store<u32>(out + ((<usize>i) << 2), load<u32>(h + ((<usize>i) << 2)));
  }
}

/**
 * 标准域 → Montgomery：ă = a·R。
 *
 * Standard domain → Montgomery: ă = a·R.
 */
export function fpToMont(a: U256): U256 {
  const out = u256fromU32(0);
  montMulInto(out, a, FP_R2);
  return out;
}

/**
 * 标准域 → Montgomery（原地写 out）。
 *
 * Standard domain → Montgomery (writes out in place).
 */
export function fpToMontTo(out: U256, a: U256): void {
  montMulInto(out, a, FP_R2);
}

/**
 * Montgomery → 标准域：a = ă·R⁻¹。
 *
 * Montgomery → standard domain: a = ă·R⁻¹.
 */
export function fpFromMont(a: U256): U256 {
  const out = u256fromU32(0);
  montMulInto(out, a, FP_ONE);
  return out;
}

/**
 * Montgomery → 标准域（原地写 out）。
 *
 * Montgomery → standard domain (writes out in place).
 */
export function fpFromMontTo(out: U256, a: U256): void {
  montMulInto(out, a, FP_ONE);
}

/**
 * 「1」的 Montgomery 表示（新分配的副本，可安全就地修改）。
 *
 * Montgomery form of "1" (a freshly allocated copy, safe to mutate in place).
 */
export function fpMontOne(): U256 {
  return u256clone(FP_R);
}

/**
 * SM9 素域加：(a + b) mod p（Montgomery 域下形式不变）。
 *
 * SM9 prime-field addition: (a + b) mod p (same form in the Montgomery domain).
 */
export function fpAdd(a: U256, b: U256): U256 {
  return modAdd(a, b, pArr());
}

/**
 * 原地：(a + b) mod p → out（供扩域层 To 算子用，零分配）。
 *
 * In place: (a + b) mod p → out (used by the extension-field To operators; no
 * allocation).
 */
export function fpAddTo(out: U256, a: U256, b: U256): void {
  modAddInto(out, a, b, pArr());
}

/**
 * 原地：(a - b) mod p → out。
 *
 * In place: (a - b) mod p → out.
 */
export function fpSubTo(out: U256, a: U256, b: U256): void {
  modSubInto(out, a, b, pArr());
}

/**
 * 原地：(a · b) mod p → out（Montgomery 乘）。
 *
 * In place: (a · b) mod p → out (Montgomery multiply).
 */
export function fpMulTo(out: U256, a: U256, b: U256): void {
  montMulInto(out, a, b);
}

/**
 * 原地：a² mod p → out（Montgomery 乘）。
 *
 * In place: a² mod p → out (Montgomery multiply).
 */
export function fpSqrTo(out: U256, a: U256): void {
  montMulInto(out, a, a);
}

/**
 * 原地：(a / 2) mod p → out（Montgomery 域下仍是「表示 / 2」）。
 *
 * In place: (a / 2) mod p → out (in the Montgomery domain this is still
 * "representation / 2").
 */
export function fpDiv2To(out: U256, a: U256): void {
  modHalveInto(out, a, pArr());
}

/**
 * SM9 素域减。
 *
 * SM9 prime-field subtraction.
 */
export function fpSub(a: U256, b: U256): U256 {
  return modSub(a, b, pArr());
}

/**
 * SM9 素域乘（Montgomery：返回 a·b·R⁻¹，即两元素之积的表示）。
 *
 * SM9 prime-field multiply (Montgomery: returns a·b·R⁻¹, i.e. the
 * representation of the product of the two elements).
 */
export function fpMul(a: U256, b: U256): U256 {
  const out = u256fromU32(0);
  montMulInto(out, a, b);
  return out;
}

/**
 * SM9 素域平方。
 *
 * SM9 prime-field squaring.
 */
export function fpSqr(a: U256): U256 {
  const out = u256fromU32(0);
  montMulInto(out, a, a);
  return out;
}

/**
 * SM9 素域逆（Montgomery 域内）。
 *
 * 二进制扩展欧几里得对任意 256 位输入都成立，所以直接对 ă 求逆得 a⁻¹·R⁻¹；
 * 要回到 Montgomery 表示 a⁻¹·R 还差一个 R。注意这一步必须是**标准域乘法**
 * （modMul，·R²·R⁻² = ·1）：用 montMul 的话它自带 ·R⁻¹，正好把要补的 R 又消掉，
 * 结果会退化成标准域的 a⁻¹，后续整条链就都错一个因子。
 *
 * SM9 prime-field inverse (inside the Montgomery domain).
 *
 * The binary extended Euclidean algorithm works for any 256-bit input, so
 * inverting ă directly gives a⁻¹·R⁻¹; returning to the Montgomery form a⁻¹·R
 * still lacks one factor R. That last step must be a **standard-domain
 * multiply** (modMul, ·R²·R⁻² = ·1): montMul carries its own ·R⁻¹ and would
 * cancel exactly the R we need to add back, degrading the result to the
 * standard-domain a⁻¹ — which then skews the whole downstream chain by one
 * factor.
 */
export function fpInv(a: U256): U256 {
  const t = modInv(a, pArr()); // a⁻¹·R⁻¹
  return modMul(t, FP_R2, pArr()); // ·R² → a⁻¹·R
}

/**
 * SM9 素域取负：(-a) mod p（Montgomery 域下形式不变）。
 *
 * SM9 prime-field negation: (-a) mod p (same form in the Montgomery domain).
 */
export function fpNeg(a: U256): U256 {
  const p = pArr();
  if (u256isZero(a)) return u256clone(a);
  return modSub(p, a, p);
}

/**
 * SM9 素域幂（Montgomery 域内平方-乘，MSB-first）。
 *
 * SM9 prime-field exponentiation (square-and-multiply inside the Montgomery
 * domain, MSB-first).
 */
export function fpPow(a: U256, k: U256): U256 {
  // 1 的 Montgomery 表示
  //
  // Montgomery form of 1.
  let result = u256clone(FP_R);
  let base = u256clone(a);
  for (let i = 0; i < 256; i++) {
    if (u256bit(k, i) === 1) {
      const t1 = u256fromU32(0);
      montMulInto(t1, result, base);
      result = t1;
    }
    const t2 = u256fromU32(0);
    montMulInto(t2, base, base);
    base = t2;
  }
  return result;
}

/**
 * SM9 素域除以 2：(a * 2^{-1}) mod p。
 *
 * SM9 prime-field halving: (a * 2^{-1}) mod p.
 */
export function fpDiv2(a: U256): U256 {
  return modHalve(a, pArr());
}

/**
 * 标量模 n 乘（n 域仍是普通整数表示，走 field256 的 Barrett）。
 *
 * Scalar multiply mod n (values mod n stay plain integers and go through
 * field256's Barrett reduction).
 */
export function mulModN(a: U256, b: U256): U256 {
  return modMul(a, b, nArr());
}

/**
 * 标量模 n 加。
 *
 * Scalar addition mod n.
 */
export function addModN(a: U256, b: U256): U256 {
  return modAdd(a, b, nArr());
}

/**
 * 标量模 n 逆。
 *
 * Scalar inverse mod n.
 */
export function invModN(a: U256): U256 {
  return modInv(a, nArr());
}

/**
 * 从 hex 构造 U256（用于常数）。
 *
 * Builds a U256 from hex (used for constants).
 */
export function u256(hex: string): U256 {
  return u256fromHex(hex);
}

/**
 * 拷贝。
 *
 * Copies a U256.
 */
export function clone(a: U256): U256 {
  return u256clone(a);
}

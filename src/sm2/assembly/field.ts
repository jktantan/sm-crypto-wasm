// SM2 素数域 / 子群阶运算（AssemblyScript）。
//
// 本文件是**薄封装**：通用 256-bit 模运算实现于 `src/common/assembly/field256.ts`，
// 这里只固定 SM2 的模数常数并转发，保持 SM2 内部调用签名不变。
//
// SM2 曲线参数（GM/T 0003-2012）：
//   p = 2^256 - 2^224 - 2^96 + 2^64 - 1
//     = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//   n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123

import {
  arenaAlloc,
  modAdd,
  modAddInto,
  modInv,
  modMul,
  modMulInto,
  modSqr,
  modSqrInto,
  modSub,
  modSubInto,
  mul512,
  permU256,
  reduce512,
  U256,
  U512,
  u256addRaw,
  u256bit,
  u256clone,
  u256cmp,
  u256copy,
  u256fromBytes,
  u256fromLimbs,
  u256fromMemBE,
  u256fromU32,
  u256isOdd,
  u256isZero,
  u256shr1,
  u256subRaw,
  u256toBytes,
  u256zero,
  arenaRewind,
} from '../../common/assembly/field256';

// 重新导出通用工具，供 SM2 其它文件沿用。
export {
  U256,
  U512,
  arenaAlloc,
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
  u256toBytes,
  u256zero,
  permU256,
  arenaRewind,
};

// SM2 素域 p（小端 limb）。
// p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
export const P_LIMBS: StaticArray<u32> = [
  0xffffffff, 0xffffffff, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
];

// SM2 子群阶 n（小端 limb）。
// n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
export const N_LIMBS: StaticArray<u32> = [
  0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
];

// p / n 的 U256 形式只构造一次。每次 fpAdd/fpSub/fpMul 都重建一份 U256 是最贵的固定开销
// （SM2 实测 fpAdd ≈ 0.83µs ≈ fpMul 的 1/3）。field256 的 mod* 系列只读模数（输入自行
// clone），不会写这块共享内存；调用方也不要就地修改 pArr()/nArr() 的返回值。
const P_CACHE: U256 = u256fromLimbs(P_LIMBS);
const N_CACHE: U256 = u256fromLimbs(N_LIMBS);

/** 返回 p（共享常量：只读，勿就地修改）。 */
export function pArr(): U256 {
  return P_CACHE;
}

/** 返回 n（共享常量：只读，勿就地修改）。 */
export function nArr(): U256 {
  return N_CACHE;
}

/** 模加：(a + b) mod p。 */
export function fpAdd(a: U256, b: U256): U256 {
  return modAdd(a, b, pArr());
}

/** 模减：(a - b) mod p。 */
export function fpSub(a: U256, b: U256): U256 {
  return modSub(a, b, pArr());
}

/** 模乘：(a * b) mod p。 */
export function fpMul(a: U256, b: U256): U256 {
  return modMul(a, b, pArr());
}

/** 模平方。 */
export function fpSqr(a: U256): U256 {
  return modSqr(a, pArr());
}

// ---------- 原地（To）变体 ----------
//
// 供点运算的 Into 版使用：一次倍点原本要 ~10 次 `new U256`（arena 分配 + 可能的
// memory.copy），改成写调用方的 out 后这部分开销消失。四者都允许 out 与入参别名
// （mod*Into 的读写顺序已经保证：先读完入参、再写 out）。

/** 原地：(a + b) mod p → out。 */
export function fpAddTo(out: U256, a: U256, b: U256): void {
  modAddInto(out, a, b, pArr());
}

/** 原地：(a - b) mod p → out。 */
export function fpSubTo(out: U256, a: U256, b: U256): void {
  modSubInto(out, a, b, pArr());
}

/** 原地：(a · b) mod p → out。 */
export function fpMulTo(out: U256, a: U256, b: U256): void {
  modMulInto(out, a, b, pArr());
}

/** 原地：a² mod p → out。 */
export function fpSqrTo(out: U256, a: U256): void {
  modSqrInto(out, a, pArr());
}

/** 模逆：a^{-1} mod p。 */
export function fpInv(a: U256): U256 {
  return modInv(a, pArr());
}

// ---------- 诊断用（保持既有导出，供 probe 使用） ----------

/** 诊断用：暴露 512-bit 积。 */
export function mul512Debug(a: U256, b: U256): U512 {
  return mul512(a, b);
}

/** 诊断用：暴露归约。 */
export function reduce512Debug(x: U512): U256 {
  return reduce512(x, pArr());
}

// 保持 u256addRaw / u256subRaw 可见（部分内部代码可能引用）。
export { u256addRaw, u256subRaw };

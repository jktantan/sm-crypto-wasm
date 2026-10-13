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
  U256,
  U512,
  u256zero,
  u256fromU32,
  u256fromBytes,
  u256toBytes,
  u256cmp,
  u256isZero,
  u256copy,
  u256bit,
  u256clone,
  u256fromLimbs,
  u256addRaw,
  u256subRaw,
  modAdd,
  modSub,
  mul512,
  reduce512,
  modMul,
  modSqr,
  modInv,
} from '../../common/assembly/field256';

// 重新导出通用工具，供 SM2 其它文件沿用。
export {
  U256,
  U512,
  u256zero,
  u256fromU32,
  u256fromBytes,
  u256toBytes,
  u256cmp,
  u256isZero,
  u256copy,
  u256bit,
  u256clone,
};

// SM2 素域 p（小端 limb）。
// p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
export const P_LIMBS: StaticArray<u32> = [
  0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
];

// SM2 子群阶 n（小端 limb）。
// n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
export const N_LIMBS: StaticArray<u32> = [
  0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
  0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
];

/** 返回 p（新对象）。 */
export function pArr(): U256 {
  return u256fromLimbs(P_LIMBS);
}

/** 返回 n（新对象）。 */
export function nArr(): U256 {
  return u256fromLimbs(N_LIMBS);
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
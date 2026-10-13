// SM9 基础域 Fp（AssemblyScript）。
//
// SM9 用 BN 曲线（GM/T 0044-2016）：
//   p = b6400000 02a3a6f1 d603ab4f f58ec745 21f2934b 1a7aeedb e56f9b27 e351457d
//   n = b6400000 02a3a6f1 d603ab4f f58ec744 49f2934b 18ea8bee e56ee19c d69ecf25
//
// 通用 256-bit 模运算在 `src/common/assembly/field256.ts`；本文件固定 SM9 的 p/n。

import {
  U256,
  modAdd,
  modSub,
  modMul,
  modSqr,
  modInv,
  modPow,
  u256fromLimbs,
  u256clone,
  u256fromHex,
} from '../../common/assembly/field256';

export { U256 };

// p 的小端 limb。
// p = b6400000 02a3a6f1 d603ab4f f58ec745 21f2934b 1a7aeedb e56f9b27 e351457d
export const SM9_P_LIMBS: StaticArray<u32> = [
  0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b,
  0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000,
];

// n 的小端 limb。
// n = b6400000 02a3a6f1 d603ab4f f58ec744 49f2934b 18ea8bee e56ee19c d69ecf25
export const SM9_N_LIMBS: StaticArray<u32> = [
  0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b,
  0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000,
];

/** 返回 p。 */
export function pArr(): U256 {
  return u256fromLimbs(SM9_P_LIMBS);
}

/** 返回 n。 */
export function nArr(): U256 {
  return u256fromLimbs(SM9_N_LIMBS);
}

/** SM9 素域加：(a + b) mod p。 */
export function fpAdd(a: U256, b: U256): U256 {
  return modAdd(a, b, pArr());
}

/** SM9 素域减。 */
export function fpSub(a: U256, b: U256): U256 {
  return modSub(a, b, pArr());
}

/** SM9 素域乘。 */
export function fpMul(a: U256, b: U256): U256 {
  return modMul(a, b, pArr());
}

/** SM9 素域平方。 */
export function fpSqr(a: U256): U256 {
  return modSqr(a, pArr());
}

/** SM9 素域逆。 */
export function fpInv(a: U256): U256 {
  return modInv(a, pArr());
}

/** SM9 素域幂。 */
export function fpPow(a: U256, k: U256): U256 {
  return modPow(a, k, pArr());
}

/** SM9 素域除以 2：(a * 2^{-1}) mod p。 */
export function fpDiv2(a: U256): U256 {
  return modHalve(a, pArr());
}

/** 标量模 n 乘。 */
export function mulModN(a: U256, b: U256): U256 {
  return modMul(a, b, nArr());
}

/** 标量模 n 加。 */
export function addModN(a: U256, b: U256): U256 {
  return modAdd(a, b, nArr());
}

/** 标量模 n 逆。 */
export function invModN(a: U256): U256 {
  return modInv(a, nArr());
}

/** 从 hex 构造 U256（用于常数）。 */
export function u256(hex: string): U256 {
  return u256fromHex(hex);
}

/** 拷贝。 */
export function clone(a: U256): U256 {
  return u256clone(a);
}
// SM2 标量模运算（mod n）—— AssemblyScript。
//
// 薄封装：通用 256-bit 模运算在 `src/common/assembly/field256.ts`；
// 这里固定模数为 SM2 子群阶 n，并转发。
//
// n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123

import {
  U256,
  modAdd,
  modSub,
  modMul,
  modInv,
} from '../../common/assembly/field256';
import { nArr } from './field';

export { U256 };

// 保持 nArr 可从本模块取（部分调用方习惯）。
export { nArr } from './field';

/** (a + b) mod n。 */
export function addModN(a: U256, b: U256): U256 {
  return modAdd(a, b, nArr());
}

/** (a - b) mod n。 */
export function subModN(a: U256, b: U256): U256 {
  return modSub(a, b, nArr());
}

/** (a * b) mod n。 */
export function mulModN(a: U256, b: U256): U256 {
  return modMul(a, b, nArr());
}

/** a^{-1} mod n（费马小定理 a^{n-2}）。 */
export function invModN(a: U256): U256 {
  return modInv(a, nArr());
}
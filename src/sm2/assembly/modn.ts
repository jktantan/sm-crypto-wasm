// SM2 标量模运算（mod n）。
//
// n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
//
// 签名/密钥交换需要：模加、模减、模乘（512-bit 积 mod n）、模逆（费马）。
// 表示：8×u32 小端 limb。
//
// 参考 GM/T 0003-2012。

import { U256 } from './field';

/** 阶 n（小端 limb）。 */
export const N_LIMBS: StaticArray<u32> = [
  0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
  0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
];

export function nArr(): U256 {
  const n = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) n[i] = N_LIMBS[i];
  return n;
}

export function u256zero(): U256 {
  const x = new StaticArray<u32>(8);
  return x;
}

export function u256fromBytes(b: Uint8Array, off: usize): U256 {
  const x = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) {
    const o = off + i * 4;
    x[7 - i] = (((<u32>b[o]) << 24) | ((<u32>b[o + 1]) << 16) | ((<u32>b[o + 2]) << 8) | (<u32>b[o + 3])) & 0xffffffff;
  }
  return x;
}

export function u256toBytes(x: U256, out: usize): void {
  for (let i = 0; i < 8; i++) {
    const v = x[7 - i];
    store<u8>(out + i * 4, <u8>(v >>> 24));
    store<u8>(out + i * 4 + 1, <u8>(v >>> 16));
    store<u8>(out + i * 4 + 2, <u8>(v >>> 8));
    store<u8>(out + i * 4 + 3, <u8>v);
  }
}

export function u256cmp(a: U256, b: U256): i32 {
  for (let i = 7; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

export function u256isZero(a: U256): bool {
  for (let i = 0; i < 8; i++) if (a[i] !== 0) return false;
  return true;
}

function addRaw(a: U256, b: U256): u32 {
  let carry: u64 = 0;
  for (let i = 0; i < 8; i++) {
    const s: u64 = u64(a[i]) + u64(b[i]) + carry;
    a[i] = <u32>(s & 0xffffffff);
    carry = s >>> 32;
  }
  return <u32>carry;
}

function subRaw(a: U256, b: U256): u32 {
  let borrow: i64 = 0;
  for (let i = 0; i < 8; i++) {
    const d: i64 = i64(a[i]) - i64(b[i]) - borrow;
    if (d < 0) {
      a[i] = <u32>(d + 0x100000000);
      borrow = 1;
    } else {
      a[i] = <u32>d;
      borrow = 0;
    }
  }
  return <u32>borrow;
}

/** (a + b) mod n。 */
export function addModN(a: U256, b: U256): U256 {
  const r = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) r[i] = a[i];
  const carry = addRaw(r, b);
  const n = nArr();
  if (carry !== 0 || u256cmp(r, n) >= 0) subRaw(r, n);
  return r;
}

/** (a - b) mod n。 */
export function subModN(a: U256, b: U256): U256 {
  const r = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) r[i] = a[i];
  const borrow = subRaw(r, b);
  if (borrow !== 0) {
    const n = nArr();
    addRaw(r, n);
  }
  return r;
}

type U512 = StaticArray<u32>;

function mul512(a: U256, b: U256): U512 {
  const r = new StaticArray<u32>(16);
  for (let i = 0; i < 16; i++) r[i] = 0;
  for (let i = 0; i < 8; i++) {
    let carry: u64 = 0;
    const ai = u64(a[i]);
    for (let j = 0; j < 8; j++) {
      const cur: u64 = u64(r[i + j]) + ai * u64(b[j]) + carry;
      r[i + j] = <u32>(cur & 0xffffffff);
      carry = cur >>> 32;
    }
    let k = i + 8;
    while (carry !== 0 && k < 16) {
      const cur: u64 = u64(r[k]) + carry;
      r[k] = <u32>(cur & 0xffffffff);
      carry = cur >>> 32;
      k++;
    }
  }
  return r;
}

/** 512-bit mod n（长除法，9-limb 累加寄存器）。 */
function reduce512ModN(x: U512): U256 {
  const n = nArr();
  const r = new StaticArray<u32>(9);
  for (let i = 0; i < 9; i++) r[i] = 0;
  for (let i = 511; i >= 0; i--) {
    let carry: u32 = 0;
    for (let k = 0; k < 9; k++) {
      const hi = (r[k] >>> 31) & 1;
      r[k] = ((r[k] << 1) | carry) & 0xffffffff;
      carry = hi;
    }
    const b = (x[i >> 5] >>> (i & 31)) & 1;
    r[0] = (r[0] | b) & 0xffffffff;
    if (r[8] !== 0 || cmp9(r, n) >= 0) {
      sub9(r, n);
    }
  }
  const out = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) out[i] = r[i];
  return out;
}

function cmp9(a: StaticArray<u32>, b: U256): i32 {
  if (a[8] !== 0) return 1;
  for (let i = 7; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

function sub9(a: StaticArray<u32>, b: U256): void {
  let borrow: i64 = 0;
  for (let i = 0; i < 9; i++) {
    const bi: i64 = i < 8 ? i64(b[i]) : 0;
    const d: i64 = i64(a[i]) - bi - borrow;
    if (d < 0) {
      a[i] = <u32>(d + 0x100000000);
      borrow = 1;
    } else {
      a[i] = <u32>d;
      borrow = 0;
    }
  }
}

/** (a * b) mod n。 */
export function mulModN(a: U256, b: U256): U256 {
  return reduce512ModN(mul512(a, b));
}

/** a^{-1} mod n（费马小定理 a^{n-2}）。 */
export function invModN(a: U256): U256 {
  const e = nArr();
  e[0] = (e[0] - 2) & 0xffffffff;
  let result = new StaticArray<u32>(8);
  result[0] = 1;
  let base = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) base[i] = a[i];
  for (let i = 0; i < 256; i++) {
    if (((e[i >> 5] >>> (i & 31)) & 1) === 1) {
      result = mulModN(result, base);
    }
    base = mulModN(base, base);
  }
  return result;
}
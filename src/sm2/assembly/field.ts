// SM2 素数域 Fp 运算（AssemblyScript）。
//
// p = 2^256 - 2^224 - 2^96 + 2^64 - 1
//   = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
//
// 表示：每个 256-bit 数用 8 个 u32 limb，**小端序**（limb[0] = 最低 32 位）。
//
// 归约策略：先用二进制长除法把 512-bit 积归约到 < p —— 慢但**绝对正确**，
// 优先保证正确性；后续如需要性能再换成伪梅森折回 / 蒙哥马利。
//
// 参考 GM/T 0003-2012 曲线参数。

/** 256-bit 无符号整数，8×u32 小端。 */
export type U256 = StaticArray<u32>;

export function u256zero(): U256 {
  return new StaticArray<u32>(8);
}

export function u256fromU32(v: u32): U256 {
  const x = new StaticArray<u32>(8);
  x[0] = v;
  return x;
}

/** 从字节数组（大端）读 256-bit，起点 off。 */
export function u256fromBytes(b: Uint8Array, off: usize): U256 {
  const x = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) {
    const o = off + i * 4;
    x[7 - i] = (((<u32>b[o]) << 24) | ((<u32>b[o + 1]) << 16) | ((<u32>b[o + 2]) << 8) | (<u32>b[o + 3])) & 0xffffffff;
  }
  return x;
}

/** 写 256-bit 到 out（大端），32 字节。 */
export function u256toBytes(x: U256, out: usize): void {
  for (let i = 0; i < 8; i++) {
    const v = x[7 - i];
    store<u8>(out + i * 4, <u8>(v >>> 24));
    store<u8>(out + i * 4 + 1, <u8>(v >>> 16));
    store<u8>(out + i * 4 + 2, <u8>(v >>> 8));
    store<u8>(out + i * 4 + 3, <u8>v);
  }
}

/** 比较：a > b → 1，a == b → 0，a < b → -1。 */
export function u256cmp(a: U256, b: U256): i32 {
  for (let i = 7; i >= 0; i--) {
    const x = a[i];
    const y = b[i];
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

export function u256isZero(a: U256): bool {
  for (let i = 0; i < 8; i++) if (a[i] !== 0) return false;
  return true;
}

export function u256copy(src: U256, dst: U256): void {
  for (let i = 0; i < 8; i++) dst[i] = src[i];
}

export function u256bit(a: U256, i: i32): u32 {
  return (a[i >> 5] >>> (i & 31)) & 1;
}

/** a += b（mod 2^256），返回进位。 */
function addRaw(a: U256, b: U256): u32 {
  let carry: u64 = 0;
  for (let i = 0; i < 8; i++) {
    const s: u64 = u64(a[i]) + u64(b[i]) + carry;
    a[i] = <u32>(s & 0xffffffff);
    carry = s >>> 32;
  }
  return <u32>carry;
}

/** a -= b（mod 2^256），返回借位。 */
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

// SM2 素数 p（小端 limb）。
// p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
export const P_LIMBS: StaticArray<u32> = [
  0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
];

// SM2 子群阶 n（小端 limb），用于标量模运算。
// n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
export const N_LIMBS: StaticArray<u32> = [
  0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
  0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
];

function limbsToU256(src: StaticArray<u32>): U256 {
  const p = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) p[i] = src[i];
  return p;
}

export function pArr(): U256 {
  return limbsToU256(P_LIMBS);
}

/** 模加：(a + b) mod p。 */
export function fpAdd(a: U256, b: U256): U256 {
  const r = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) r[i] = a[i];
  const carry = addRaw(r, b);
  const p = pArr();
  if (carry !== 0 || u256cmp(r, p) >= 0) {
    subRaw(r, p);
  }
  return r;
}

/** 模减：(a - b) mod p。 */
export function fpSub(a: U256, b: U256): U256 {
  const r = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) r[i] = a[i];
  const borrow = subRaw(r, b);
  if (borrow !== 0) {
    const p = pArr();
    addRaw(r, p);
  }
  return r;
}

// ---------- 乘法与归约 ----------

/** 512-bit 中间积（16×u32 小端）。 */
type U512 = StaticArray<u32>;

/** 学校算法乘法：a(8) × b(8) → 512-bit(16)。 */
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

/**
 * 512-bit mod p（二进制长除法）。绝对正确、无需特殊结构。
 *
 * 从最高位到最低位逐位：r = (r << 1 | bit) mod p。
 */
function reduce512(x: U512): U256 {
  const p = pArr();
  // r 用 9 个 limb：第 9 个（r[8]）保存 r<<1 的溢出位。
  // r < p < 2^256 时 r<<1|bit ≤ 2^257-1，必须用 257 bit 存。
  const r = new StaticArray<u32>(9);
  for (let i = 0; i < 9; i++) r[i] = 0;
  for (let i = 511; i >= 0; i--) {
    // r <<= 1（含第 9 limb）
    let carry: u32 = 0;
    for (let k = 0; k < 9; k++) {
      const hi = (r[k] >>> 31) & 1;
      r[k] = ((r[k] << 1) | carry) & 0xffffffff;
      carry = hi;
    }
    // r |= bit(x, i)
    const b = (x[i >> 5] >>> (i & 31)) & 1;
    r[0] = (r[0] | b) & 0xffffffff;
    // if r >= p: r -= p（含高位 limb 的比较）
    if (r[8] !== 0 || u256cmp9(r, p) >= 0) {
      subRaw9(r, p);
    }
  }
  const out = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) out[i] = r[i];
  return out;
}

/** 9-limb 比较（高位 limb 参与）。 */
function u256cmp9(a: StaticArray<u32>, b: U256): i32 {
  if (a[8] !== 0) return 1;
  for (let i = 7; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

/** 9-limb -= 8-limb p。 */
function subRaw9(a: StaticArray<u32>, b: U256): void {
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

/** 模乘：(a * b) mod p。 */
export function fpMul(a: U256, b: U256): U256 {
  return reduce512(mul512(a, b));
}

/** 诊断用：暴露 512-bit 积。 */
export function mul512Debug(a: U256, b: U256): U512 {
  return mul512(a, b);
}

/** 诊断用：暴露归约。 */
export function reduce512Debug(x: U512): U256 {
  return reduce512(x);
}

/** 模平方。 */
export function fpSqr(a: U256): U256 {
  return fpMul(a, a);
}

/** 模逆：a^{-1} mod p（费马小定理，a^{p-2}）。a == 0 时返回 0。 */
export function fpInv(a: U256): U256 {
  const e = pArr();
  e[0] = (e[0] - 2) & 0xffffffff;

  let result = new StaticArray<u32>(8);
  result[0] = 1;
  let base = new StaticArray<u32>(8);
  u256copy(a, base);

  for (let i = 0; i < 256; i++) {
    const limb = e[i >> 5];
    if (((limb >>> (i & 31)) & 1) === 1) {
      result = fpMul(result, base);
    }
    base = fpSqr(base);
  }
  return result;
}
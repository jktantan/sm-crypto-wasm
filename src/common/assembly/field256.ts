// 通用 256-bit 模运算（AssemblyScript）—— 供 SM2 与 SM9 共用。
//
// 表示：每个 256-bit 无符号整数用 8 个 u32 limb，**小端序**（limb[0] 是最低 32 位）。
//
// 与具体曲线解耦：所有运算把**模数 m 作为参数传入**，因此：
// - SM2 传其素域 p 或子群阶 n；
// - SM9 传其 BN 曲线素域 p 或阶 n。
//
// 归约策略：二进制长除法把 512-bit 积归约到 < m —— 慢但**绝对正确**。
// 性能后续可换伪梅森 / 蒙哥马利，不影响调用方。
//
// 参考：GM/T 0003-2012（SM2）、GM/T 0044-2016（SM9）。

/** 256-bit 无符号整数，8×u32 小端。 */
export type U256 = StaticArray<u32>;

/** 512-bit 中间积，16×u32 小端。 */
export type U512 = StaticArray<u32>;

// ---------- 构造 / 转换 ----------

export function u256zero(): U256 {
  return new StaticArray<u32>(8);
}

export function u256fromU32(v: u32): U256 {
  const x = new StaticArray<u32>(8);
  x[0] = v;
  return x;
}

/** 从 Uint8Array（大端）读 256-bit，起点 off。 */
export function u256fromBytes(b: Uint8Array, off: usize): U256 {
  const x = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) {
    const o = off + i * 4;
    x[7 - i] = (((<u32>b[o]) << 24) | ((<u32>b[o + 1]) << 16) | ((<u32>b[o + 2]) << 8) | (<u32>b[o + 3])) & 0xffffffff;
  }
  return x;
}

/** 写 256-bit 到线性内存 out（大端），32 字节。 */
export function u256toBytes(x: U256, out: usize): void {
  for (let i = 0; i < 8; i++) {
    const v = x[7 - i];
    store<u8>(out + i * 4, <u8>(v >>> 24));
    store<u8>(out + i * 4 + 1, <u8>(v >>> 16));
    store<u8>(out + i * 4 + 2, <u8>(v >>> 8));
    store<u8>(out + i * 4 + 3, <u8>v);
  }
}

/** 判断 256-bit 是否全 0（1=零）。 */
export function u256isZero(a: U256): bool {
  for (let i = 0; i < 8; i++) if (a[i] !== 0) return false;
  return true;
}

/** 判断 256-bit 是否等于给定 32 字节大端。 */
export function u256eqBytes(a: U256, b: Uint8Array, off: usize): bool {
  for (let i = 0; i < 8; i++) {
    const x = a[7 - i];
    const o = off + i * 4;
    const y = ((<u32>b[o]) << 24) | ((<u32>b[o + 1]) << 16) | ((<u32>b[o + 2]) << 8) | (<u32>b[o + 3]);
    if (x !== (y & 0xffffffff)) return false;
  }
  return true;
}

/** 把 U256 拷贝到静态数组（返回新对象）。 */
export function u256clone(a: U256): U256 {
  const r = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) r[i] = a[i];
  return r;
}

/** 原地拷贝：dst = src（保持旧的 `u256copy(src, dst)` 签名）。 */
export function u256copy(src: U256, dst: U256): void {
  for (let i = 0; i < 8; i++) dst[i] = src[i];
}

/** 从 8 个 u32（小端）构造 U256。 */
export function u256fromLimbs(limbs: StaticArray<u32>): U256 {
  const r = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) r[i] = limbs[i];
  return r;
}

// ---------- 比较 / 位 ----------

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

/** 取第 i 位（0..255）。 */
export function u256bit(a: U256, i: i32): u32 {
  return (a[i >> 5] >>> (i & 31)) & 1;
}

export function u256eq(a: U256, b: U256): bool {
  return u256cmp(a, b) === 0;
}

/** 从十六进制字符串构造 U256。 */
export function u256fromHex(hex: string): U256 {
  const x = new StaticArray<u32>(8);
  const n = hex.length;
  for (let i = 0; i < 8; i++) {
    let v: u32 = 0;
    // 从低位读 8 个 hex 字符（4 字节）。
    const end = n - i * 8;
    const start = end - 8;
    for (let j = start; j < end; j++) {
      if (j < 0) { v = (v << 4) & 0xffffffff; continue; }
      v = ((v << 4) | hexNib(hex.charCodeAt(j))) & 0xffffffff;
    }
    x[i] = v;
  }
  return x;
}

function hexNib(c: i32): u32 {
  if (c >= 0x30 && c <= 0x39) return <u32>(c - 0x30);
  if (c >= 0x41 && c <= 0x46) return <u32>(c - 0x41 + 10);
  if (c >= 0x61 && c <= 0x66) return <u32>(c - 0x61 + 10);
  return 0;
}

// ---------- 原始 256-bit 加 / 减（mod 2^256） ----------

/** a += b（mod 2^256），返回进位。 */
export function u256addRaw(a: U256, b: U256): u32 {
  let carry: u64 = 0;
  for (let i = 0; i < 8; i++) {
    const s: u64 = u64(a[i]) + u64(b[i]) + carry;
    a[i] = <u32>(s & 0xffffffff);
    carry = s >>> 32;
  }
  return <u32>carry;
}

/** a -= b（mod 2^256），返回借位。 */
export function u256subRaw(a: U256, b: U256): u32 {
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

// ---------- 模运算（模数 m 作参数） ----------

/** (a + b) mod m。要求 a、b < m 且 m != 0。 */
export function modAdd(a: U256, b: U256, m: U256): U256 {
  const r = u256clone(a);
  const carry = u256addRaw(r, b);
  if (carry !== 0 || u256cmp(r, m) >= 0) {
    u256subRaw(r, m);
  }
  return r;
}

/** (a - b) mod m。要求 a、b < m。 */
export function modSub(a: U256, b: U256, m: U256): U256 {
  const r = u256clone(a);
  const borrow = u256subRaw(r, b);
  if (borrow !== 0) {
    u256addRaw(r, m);
  }
  return r;
}

/** a(8) × b(8) → 512-bit(16)，学校算法。 */
export function mul512(a: U256, b: U256): U512 {
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

/** 512-bit mod m（二进制长除法，9-limb 累加寄存器）。通用、无结构假设。 */
export function reduce512(x: U512, m: U256): U256 {
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
    // if r >= m: r -= m
    if (r[8] !== 0 || cmp9(r, m) >= 0) {
      sub9(r, m);
    }
  }
  const out = new StaticArray<u32>(8);
  for (let i = 0; i < 8; i++) out[i] = r[i];
  return out;
}

/** 大端字节串（任意长度）mod m：Horner 法 acc = acc*256 + b[i]。用于 SM9 的 40 字节哈希取模。 */
export function bytesMod(b: StaticArray<u8>, m: U256): U256 {
  const c256 = new StaticArray<u32>(8);
  c256[0] = 256;
  let acc = new StaticArray<u32>(8); // 0
  for (let i = 0; i < b.length; i++) {
    acc = modMul(acc, c256, m);
    const add = new StaticArray<u32>(8);
    add[0] = <u32>b[i];
    acc = modAdd(acc, add, m);
  }
  return acc;
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

/** (a * b) mod m。 */
export function modMul(a: U256, b: U256, m: U256): U256 {
  return reduce512(mul512(a, b), m);
}

/** a² mod m。 */
export function modSqr(a: U256, m: U256): U256 {
  return modMul(a, a, m);
}

/** a^{-1} mod m（费马小定理 a^{m-2}；要求 m 为素数）。a == 0 时返回 0。 */
export function modInv(a: U256, m: U256): U256 {
  const e = u256clone(m);
  e[0] = (e[0] - 2) & 0xffffffff;
  let result = new StaticArray<u32>(8);
  result[0] = 1;
  let base = u256clone(a);
  for (let i = 0; i < 256; i++) {
    if (((e[i >> 5] >>> (i & 31)) & 1) === 1) {
      result = modMul(result, base, m);
    }
    base = modSqr(base, m);
  }
  return result;
}

/** a 是否为奇数。 */
export function u256isOdd(a: U256): bool {
  return (a[0] & 1) === 1;
}

/** 原地右移一位（a >>= 1）。 */
export function u256shr1(a: U256): void {
  let carry: u32 = 0;
  for (let i = 7; i >= 0; i--) {
    const v = a[i];
    a[i] = ((v >>> 1) | (carry << 31)) & 0xffffffff;
    carry = v & 1;
  }
}

/** (a / 2) mod m（m 为奇数素数的情形）。
 *  注意：m 可能 ≥ 2^255，此时 a + m 会超过 256 位，
 *  因此不能直接 u256addRaw（会丢进位）。改用 (a>>1) + ((a&1) ? (m>>1)+1 : 0)：
 *    a 偶：(a/2)；a 奇：(a-1)/2 + (m+1)/2 = (a+m)/2。
 *  此处 m 恒为奇数，(m>>1)+1 == (m+1)/2。
 */
export function modHalve(a: U256, m: U256): U256 {
  const r = u256clone(a);
  const odd = u256isOdd(r);
  u256shr1(r);
  if (odd) {
    const half = u256clone(m);
    u256shr1(half);
    u256addRaw(half, u256fromU32(1)); // (m>>1) + 1 = (m+1)/2，不会溢出
    u256addRaw(r, half);              // r + (m+1)/2 ≤ (a-1)/2 + (m+1)/2 < m，不会溢出
  }
  return r;
}

/**
 * 模幂 a^k mod m（平方-乘，k 为 256-bit，MSB-first）。
 * k 为 8×u32 小端。
 */
export function modPow(a: U256, k: U256, m: U256): U256 {
  let result = new StaticArray<u32>(8);
  result[0] = 1;
  let base = u256clone(a);
  for (let i = 0; i < 256; i++) {
    if (u256bit(k, i) === 1) {
      result = modMul(result, base, m);
    }
    base = modSqr(base, m);
  }
  return result;
}
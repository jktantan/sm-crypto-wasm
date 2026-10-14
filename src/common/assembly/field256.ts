// 通用 256-bit 模运算（AssemblyScript）—— 供 SM2 与 SM9 共用。
//
// 表示：每个 256-bit 无符号整数用 8 个 u32 limb，**小端序**（limb[0] 是最低 32 位）。
//
// 与具体曲线解耦：所有运算把**模数 m 作为参数传入**，因此：
// - SM2 传其素域 p 或子群阶 n；
// - SM9 传其 BN 曲线素域 p 或阶 n。
//
// 归约策略：基数 2^32 的多 limb 长除法（Knuth D 简化版）把 512-bit 积归约到 < m。
// 假定模数 m 的最高 limb ≥ 2^31（SM2/SM9 的 p、n 均满足）——此时 Knuth 估商高估 ≤ 2，修正很快。
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
    const o = <i32>off + i * 4;
    x[7 - i] =
      (((<u32>b[o]) << 24) | ((<u32>b[o + 1]) << 16) | ((<u32>b[o + 2]) << 8) | <u32>b[o + 3]) &
      0xffffffff;
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
    const y =
      ((<u32>b[o]) << 24) | ((<u32>b[o + 1]) << 16) | ((<u32>b[o + 2]) << 8) | <u32>b[o + 3];
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
      if (j < 0) {
        v = (v << 4) & 0xffffffff;
        continue;
      }
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

/**
 * out = (a + b) mod m（原地变体，允许 out 与 a / b 别名）。
 *
 * 供 fp2 / fp4 层的 `*To` 算子使用：整条扩域运算链不再产生逐次的
 * `new StaticArray<u32>(8)`，这是 pairing 里分配压力的主要来源。
 */
export function modAddInto(out: U256, a: U256, b: U256, m: U256): void {
  let carry: u64 = 0;
  for (let i = 0; i < 8; i++) {
    const s: u64 = u64(a[i]) + u64(b[i]) + carry;
    out[i] = <u32>(s & 0xffffffff);
    carry = s >>> 32;
  }
  if (carry !== 0 || u256cmp(out, m) >= 0) {
    let borrow: i64 = 0;
    for (let i = 0; i < 8; i++) {
      const d: i64 = i64(out[i]) - i64(m[i]) - borrow;
      if (d < 0) {
        out[i] = <u32>(d + 0x100000000);
        borrow = 1;
      } else {
        out[i] = <u32>d;
        borrow = 0;
      }
    }
  }
}

/** out = (a - b) mod m（原地变体，允许 out 与 a / b 别名）。 */
export function modSubInto(out: U256, a: U256, b: U256, m: U256): void {
  let borrow: i64 = 0;
  for (let i = 0; i < 8; i++) {
    const d: i64 = i64(a[i]) - i64(b[i]) - borrow;
    if (d < 0) {
      out[i] = <u32>(d + 0x100000000);
      borrow = 1;
    } else {
      out[i] = <u32>d;
      borrow = 0;
    }
  }
  if (borrow !== 0) {
    let c: u64 = 0;
    for (let i = 0; i < 8; i++) {
      const s: u64 = u64(out[i]) + u64(m[i]) + c;
      out[i] = <u32>(s & 0xffffffff);
      c = s >>> 32;
    }
  }
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

/** a(8) × b(8) → 512-bit(16)，学校算法。 */export function mul512(a: U256, b: U256): U512 {
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
 * 512-bit mod m（基数 2^32 多 limb 长除法，Knuth D 简化版）。
 *
 * 每轮处理 x 的一个 32-bit limb（共 16 轮），而非逐位（512 轮）——快约 30~50×。
 * 假定 m 的最高 limb ≥ 2^31（SM2/SM9 的 p、n 均满足），此时估商高估 ≤ 2。
 */
export function reduce512(x: U512, m: U256): U256 {
  const out = new StaticArray<u32>(8);
  reduce512Into(x, m, out);
  return out;
}

/** reduce512 的 scratch 版（modMul 长除回退路径用，无逐次分配）。 */
function reduce512Into(x: U512, m: U256, out: StaticArray<u32>): void {
  const r = RD_R; // 余数（< m · 2^32，故 9 limb 足够）
  const t = RD_T; // q · m
  for (let k = 0; k < 9; k++) r[k] = 0;
  const mhi = m[7];
  for (let i = 15; i >= 0; i--) {
    // r = r * 2^32 + x[i]
    for (let k = 8; k > 0; k--) r[k] = r[k - 1];
    r[0] = x[i];

    // 估商 q = floor((r[8]·2^32 + r[7]) / m[7])，上限 2^32-1
    const num = (u64(r[8]) << 32) | u64(r[7]);
    const qq = num / u64(mhi);
    let q: u32 = qq > u64(0xffffffff) ? 0xffffffff : <u32>qq;

    // 试减 r - q·m；若借位（q 高估）则恢复 r、q-- 重试（≤2 次）
    let tries = 0;
    while (true) {
      let carry: u64 = 0;
      for (let j = 0; j < 8; j++) {
        const cur = u64(q) * u64(m[j]) + carry;
        t[j] = <u32>(cur & 0xffffffff);
        carry = cur >>> 32;
      }
      t[8] = <u32>carry;

      let borrow: i64 = 0;
      for (let k = 0; k < 9; k++) {
        const d: i64 = i64(r[k]) - i64(t[k]) - borrow;
        if (d < 0) {
          r[k] = <u32>(d + 0x100000000);
          borrow = 1;
        } else {
          r[k] = <u32>d;
          borrow = 0;
        }
      }
      if (borrow === 0) break;

      // 恢复 r（加回 t），q 减 1 重试
      let c: u64 = 0;
      for (let k = 0; k < 9; k++) {
        const s = u64(r[k]) + u64(t[k]) + c;
        r[k] = <u32>(s & 0xffffffff);
        c = s >>> 32;
      }
      q = (q - 1) & 0xffffffff;
      tries++;
      if (tries > 4) break; // 安全阀（不应触发）
    }

    // 兜底：确保 r < m
    while (r[8] !== 0 || cmp9(r, m) >= 0) {
      sub9(r, m);
    }
  }
  for (let i = 0; i < 8; i++) out[i] = r[i];
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

/**
 * (a * b) mod m。已知模数（SM2/SM9 的 p、n）走 Barrett 归约，否则回退多 limb 长除法。
 *
 * 内部工作数组（512-bit 积、Barrett 的 q1/q2/q3/r2/r、长除法的 r/t）全部走模块级
 * scratch，不逐次分配——modMul 是 pairing/点乘的最热路径，一次配对要调几千次，
 * 逐次 new StaticArray 的 GC 压力实测占了相当大比例。
 * scratch 非重入：modMul/modSqr 是叶子函数（不互相嵌套），调用方拿到的返回值是
 * 独立分配的 U256，不受后续调用影响。
 */
const MUL_X = new StaticArray<u32>(16); // 512-bit 积
const BR_Q1 = new StaticArray<u32>(9);
const BR_Q2 = new StaticArray<u32>(18);
const BR_Q3 = new StaticArray<u32>(9);
const BR_R2 = new StaticArray<u32>(17);
const BR_R = new StaticArray<u32>(10);
const RD_R = new StaticArray<u32>(9); // reduce512 的余数
const RD_T = new StaticArray<u32>(9); // reduce512 的 q·m

/** mul512 的原地版：a × b → out（16 limb，需先清零语义由本函数保证）。 */
function mul512Into(a: U256, b: U256, out: StaticArray<u32>): void {
  for (let i = 0; i < 16; i++) out[i] = 0;
  for (let i = 0; i < 8; i++) {
    let carry: u64 = 0;
    const ai = u64(a[i]);
    for (let j = 0; j < 8; j++) {
      const cur: u64 = u64(out[i + j]) + ai * u64(b[j]) + carry;
      out[i + j] = <u32>(cur & 0xffffffff);
      carry = cur >>> 32;
    }
    let k = i + 8;
    while (carry !== 0 && k < 16) {
      const cur: u64 = u64(out[k]) + carry;
      out[k] = <u32>(cur & 0xffffffff);
      carry = cur >>> 32;
      k++;
    }
  }
}

export function modMul(a: U256, b: U256, m: U256): U256 {
  mul512Into(a, b, MUL_X);
  const mu = barrettMu(m);
  const out = new StaticArray<u32>(8);
  if (mu !== null) barrettReduceInto(MUL_X, m, mu, out);
  else reduce512Into(MUL_X, m, out);
  return out;
}

/**
 * out = (a · b) mod m（原地变体，允许 out 与 a / b 别名）。
 *
 * 读 a / b 只发生在 mul512Into 阶段、结果落在 MUL_X；写 out 在归约末尾，
 * 因此 out 与任一入参共享内存都安全。
 */
export function modMulInto(out: U256, a: U256, b: U256, m: U256): void {
  mul512Into(a, b, MUL_X);
  const mu = barrettMu(m);
  if (mu !== null) barrettReduceInto(MUL_X, m, mu, out);
  else reduce512Into(MUL_X, m, out);
}

/** out = a² mod m（原地变体，允许 out 与 a 别名）。 */
export function modSqrInto(out: U256, a: U256, m: U256): void {
  sqr512Into(a, MUL_X);
  const mu = barrettMu(m);
  if (mu !== null) barrettReduceInto(MUL_X, m, mu, out);
  else reduce512Into(MUL_X, m, out);
}

/**
 * a² mod m。平方特化：对角项 a_i·a_i 只算一次，交叉项 a_i·a_j（i<j）只算一次再
 * 翻倍进位——比通用 modMul(a,a) 少 20 个 32×32 部分积（64 → 36+加法）。
 * 归约路径与 modMul 一致（Barrett / 长除法）。
 */
export function modSqr(a: U256, m: U256): U256 {
  sqr512Into(a, MUL_X);
  const mu = barrettMu(m);
  const out = new StaticArray<u32>(8);
  if (mu !== null) barrettReduceInto(MUL_X, m, mu, out);
  else reduce512Into(MUL_X, m, out);
  return out;
}

/** a(8) × a(8) → 512-bit(16) 平方，schoolbook 对角折半。 */
function sqr512Into(a: U256, out: StaticArray<u32>): void {
  for (let i = 0; i < 16; i++) out[i] = 0;
  // 交叉项：每对 (i, j>i) 算一次 p = a_i·a_j，加倍加进位置 i+j。
  for (let i = 0; i < 8; i++) {
    const ai = u64(a[i]);
    for (let j = i + 1; j < 8; j++) {
      const p = ai * u64(a[j]); // < 2^64
      // p 加两次到 out[i+j..i+j+2]
      for (let rep = 0; rep < 2; rep++) {
        let k = i + j;
        let add: u64 = p;
        while (add !== 0 && k < 16) {
          const cur = u64(out[k]) + (add & 0xffffffff);
          out[k] = <u32>(cur & 0xffffffff);
          add = (add >>> 32) + (cur >>> 32);
          k++;
        }
      }
    }
  }
  // 对角项：a_i² 加到位置 2i。
  for (let i = 0; i < 8; i++) {
    const p = ai2(a, i);
    let k = 2 * i;
    let add: u64 = p;
    while (add !== 0 && k < 16) {
      const cur = u64(out[k]) + (add & 0xffffffff);
      out[k] = <u32>(cur & 0xffffffff);
      add = (add >>> 32) + (cur >>> 32);
      k++;
    }
  }
}

@inline
function ai2(a: U256, i: i32): u64 {
  const v = u64(a[i]);
  return v * v;
}

/**
 * a^{-1} mod m：**二进制扩展欧几里得**（加/减/移位，无乘法）。
 *
 * 原实现走费马小定理 a^{m-2}（~380 次 modMul/modSqr），是 fp12Inv / 点归一化
 * 等所有求逆路径的大头。二进制 EE 算法每轮一次加减 + 一次移位，~256 轮即可，
 * 单次求逆从毫秒级降到微秒级。
 *
 * 要求 gcd(a, m) = 1（m 为素数且 a != 0 时恒成立）。a == 0 时返回 0（与原语义一致）。
 */
export function modInv(a: U256, m: U256): U256 {
  if (u256isZero(a)) return u256zero();
  // u, v 为剩余；x1, x2 为 x 系数（u 的 Bezout 系数在 x1，v 的在 x2，均为 mod m 非负）
  const u = u256clone(a);
  const v = u256clone(m);
  const x1 = u256fromU32(1);
  const x2 = u256zero();
  while (!u256isZero(u) && !u256isZero(v)) {
    while (u256isEven(u)) {
      u256shr1(u);
      halveMod(x1, m);
    }
    while (u256isEven(v)) {
      u256shr1(v);
      halveMod(x2, m);
    }
    // u >= v → u -= v, x1 -= x2（mod m）；否则 v -= u, x2 -= x1
    if (u256cmp(u, v) >= 0) {
      u256subRaw(u, v);
      subMod(x1, x2, m);
    } else {
      u256subRaw(v, u);
      subMod(x2, x1, m);
    }
  }
  // 退出时非零者为 gcd；素模数下 gcd == 1，对应 x 系数即逆元
  if (!u256isZero(u)) {
    return x1; // u == 1：a·x1 ≡ u ≡ 1
  }
  return x2; // v == 1：a·x2 ≡ v ≡ 1
}

/**
 * x = x/2 mod m（要求 x < m）。
 *
 * 不能先 x += m 再右移：SM2/SM9 的模数 ≈ 0.7·2^256，x + m 会溢出 256-bit。
 * 用无溢出分解：x、m 均奇时 (x+m)/2 = (x>>1) + (m>>1) + 1，各步 < m。
 */
function halveMod(x: U256, m: U256): void {
  if (u256isOdd(x)) {
    const t = u256clone(x);
    u256shr1(t); // floor(x/2)
    const s = u256clone(m);
    u256shr1(s); // floor(m/2)
    u256copy(t, x);
    const carry = u256addRaw(x, s); // < m，无溢出
    if (carry !== 0) {
      // 不应发生（x>>1 + m>>1 < m），安全兜底
      u256subRaw(x, m);
    }
    u256addRaw(x, u256fromU32(1));
    // x + 1 仍 < m（(x+m)/2 ≤ m-1），无溢出
  } else {
    u256shr1(x);
  }
}

/** x1 = (x1 - x2) mod m（要求 x1, x2 < m）。 */
function subMod(x1: U256, x2: U256, m: U256): void {
  if (u256cmp(x1, x2) >= 0) {
    u256subRaw(x1, x2);
  } else {
    // x1 < x2：x1 - x2 + m
    u256addRaw(x1, m);
    u256subRaw(x1, x2);
  }
}

/** a 是否为偶数。 */
function u256isEven(a: U256): bool {
  return (a[0] & 1) === 0;
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
    u256addRaw(r, half); // r + (m+1)/2 ≤ (a-1)/2 + (m+1)/2 < m，不会溢出
  }
  return r;
}

const HALF_TMP = new StaticArray<u32>(8); // modHalveInto 的 (m>>1) 暂存
const HALF_ONE = new StaticArray<u32>(8);
HALF_ONE[0] = 1;

/** out = a / 2 mod m（原地变体，允许 out 与 a 别名）。 */
export function modHalveInto(out: U256, a: U256, m: U256): void {
  const odd = u256isOdd(a);
  let carry: u32 = 0;
  for (let i = 7; i >= 0; i--) {
    const v = a[i];
    out[i] = ((v >>> 1) | (carry << 31)) & 0xffffffff;
    carry = v & 1;
  }
  if (odd) {
    let hc: u32 = 0;
    for (let i = 7; i >= 0; i--) {
      const v = m[i];
      HALF_TMP[i] = ((v >>> 1) | (hc << 31)) & 0xffffffff;
      hc = v & 1;
    }
    let c: u64 = 1; // (m>>1) + 1
    for (let i = 0; i < 8; i++) {
      const s: u64 = u64(out[i]) + u64(HALF_TMP[i]) + c;
      out[i] = <u32>(s & 0xffffffff);
      c = s >>> 32;
    }
  }
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

// ---------- Barrett 归约（SM2/SM9 的 p、n） ----------
//
// μ = floor(2^512 / m)（257 bit，9 limb，预计算）。归约 = q1=x>>224；
// q2=q1·μ；q3=q2>>288；r=x[0..8]−((q3·m)[0..8])；再减 m 到 < m。
// 纯乘法 + 移位 + 加减，**无除法**——比通用多 limb 长除法快。

const SM2_P_MU: StaticArray<u32> = [
  0x00000003, 0x00000002, 0x00000002, 0x00000002, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
  0x00000001,
];
const SM2_N_MU: StaticArray<u32> = [
  0xf15149a0, 0x12ac6361, 0xfa323c01, 0x8dfc2096, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
  0x00000001,
];
const SM9_P_MU: StaticArray<u32> = [
  0xd5c22146, 0x71188f90, 0x1e36081c, 0xf2665f6d, 0xdcd1312a, 0x55f73aeb, 0xeb5759a6, 0x67980e0b,
  0x00000001,
];
const SM9_N_MU: StaticArray<u32> = [
  0xdfc97c2f, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b,
  0x00000001,
];

/** 按模数取 Barrett 常数 μ；未知模数返回 null（回退长除法）。 */
function barrettMu(m: U256): StaticArray<u32> | null {
  const hi = m[7];
  if (hi === 0xfffffffe) {
    if (m[3] === 0xffffffff) return SM2_P_MU;
    if (m[3] === 0x7203df6b) return SM2_N_MU;
  } else if (hi === 0xb6400000) {
    if (m[3] === 0x21f2934b) return SM9_P_MU;
    if (m[3] === 0x49f2934b) return SM9_N_MU;
  }
  return null;
}

/** out(na+nb) = a(na) · b(nb)（schoolbook）。 */
function mulLimbArrays(
  a: StaticArray<u32>,
  na: i32,
  b: StaticArray<u32>,
  nb: i32,
  out: StaticArray<u32>,
): void {
  for (let i = 0; i < na + nb; i++) out[i] = 0;
  for (let i = 0; i < na; i++) {
    let carry: u64 = 0;
    const ai = u64(a[i]);
    for (let j = 0; j < nb; j++) {
      const cur = u64(out[i + j]) + ai * u64(b[j]) + carry;
      out[i + j] = <u32>(cur & 0xffffffff);
      carry = cur >>> 32;
    }
    let k = i + nb;
    while (carry !== 0) {
      const cur = u64(out[k]) + carry;
      out[k] = <u32>(cur & 0xffffffff);
      carry = cur >>> 32;
      k++;
    }
  }
}

/** Barrett 归约（scratch 版）：x(16 limb) mod m(8 limb) → out(8 limb)，结果 < m。 */
function barrettReduceInto(x: U512, m: U256, mu: StaticArray<u32>, out: StaticArray<u32>): void {
  const q1 = BR_Q1;
  for (let i = 0; i < 9; i++) q1[i] = x[7 + i]; // x >> 224
  const q2 = BR_Q2;
  mulLimbArrays(q1, 9, mu, 9, q2);
  const q3 = BR_Q3;
  for (let i = 0; i < 9; i++) q3[i] = q2[9 + i]; // q2 >> 288
  const r2 = BR_R2;
  mulLimbArrays(q3, 9, m, 8, r2);

  const r = BR_R;
  let borrow: i64 = 0;
  for (let i = 0; i < 9; i++) {
    const d: i64 = i64(x[i]) - i64(r2[i]) - borrow;
    if (d < 0) {
      r[i] = <u32>(d + 0x100000000);
      borrow = 1;
    } else {
      r[i] = <u32>d;
      borrow = 0;
    }
  }
  r[9] = <u32>borrow; // r 为负时 +2^288

  let guard = 0;
  while (guard < 4 && (r[9] !== 0 || r[8] !== 0 || cmp9(r, m) >= 0)) {
    let b: i64 = 0;
    for (let i = 0; i < 10; i++) {
      const mi: i64 = i < 8 ? i64(m[i]) : 0;
      const d: i64 = i64(r[i]) - mi - b;
      if (d < 0) {
        r[i] = <u32>(d + 0x100000000);
        b = 1;
      } else {
        r[i] = <u32>d;
        b = 0;
      }
    }
    guard++;
  }

  for (let i = 0; i < 8; i++) out[i] = r[i];
}

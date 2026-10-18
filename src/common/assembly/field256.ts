// 通用 256-bit 模运算（AssemblyScript）—— 供 SM2 与 SM9 共用。
//
// 表示：每个 256-bit 无符号整数是**线性内存裸指针**：`usize` 指向一段 32 字节的
// limb 区，8×u32 **小端序**（limb[0] 是最低 32 位）。旧实现用 `StaticArray<u32>`
// 表示，索引访问会编译成 `__get`/`__set` runtime 调用（含边界检查），每次分配还要
// 走 TLSF 分配器 + itcms 记账 —— CPU 采样显示这两项合计占 SM2 签名的 ~30%。
//
// 分配：模块级 bump arena。一次性 `heap.alloc` 拿一大块，导出函数入口用
// `arenaMark()` 记水位、出口用 `arenaReset()` 回退，因此单次调用期间的临时量
// 既无 GC 扫描也无回收成本。**不要**把 arena 指针存到跨导出调用的长生命周期结构里。
//
// 与具体曲线解耦：所有运算把**模数 m 作为参数传入**，因此：
// - SM2 传其素域 p 或子群阶 n；
// - SM9 传其 BN 曲线素域 p 或阶 n。
//
// 归约策略：SM2 的素域 p 走 Solinas 展开，其余已知模数（SM2 的 n、SM9 的 p/n）走
// Barrett 归约，未知模数回退多 limb 长除法（Knuth D 简化版）。长除法假定模数 m 的
// 最高 limb ≥ 2^31，此时估商高估 ≤ 2。
//
// 参考：GM/T 0003-2012（SM2）、GM/T 0044-2016（SM9）。
//
// Generic 256-bit modular arithmetic (AssemblyScript), shared by SM2 and SM9.
//
// Representation: every 256-bit unsigned integer is a **raw linear-memory pointer**:
// a `usize` pointing at a 32-byte limb area, 8×u32 **little-endian** (limb[0] is the
// least significant 32 bits). The old implementation used `StaticArray<u32>`, where
// indexed access compiles into `__get`/`__set` runtime calls (with bounds checks) and
// every allocation goes through the TLSF allocator plus itcms bookkeeping — CPU
// sampling showed those two together accounted for ~30% of an SM2 signature.
//
// Allocation: a module-level bump arena. A single `heap.alloc` grabs one large block;
// exported functions record the watermark with `arenaMark()` on entry and roll back
// with `arenaReset()` on exit, so temporaries of one call cost neither GC scanning nor
// reclamation. **Never** store an arena pointer in a long-lived structure that
// outlives an exported call.
//
// Decoupled from any specific curve: every operation takes **the modulus m as a
// parameter**, therefore:
// - SM2 passes its prime field p or its subgroup order n;
// - SM9 passes its BN curve prime field p or its order n.
//
// Reduction strategy: SM2's prime field p uses the Solinas expansion, the other known
// moduli (SM2's n and SM9's p/n) use Barrett reduction, and an unknown modulus falls
// back to multi-limb long division (a simplified Knuth D). Long division assumes the
// modulus's top limb is ≥ 2^31, in which case the quotient estimate overshoots by at
// most 2.
//
// References: GM/T 0003-2012 (SM2), GM/T 0044-2016 (SM9).

/** 256-bit 无符号整数：指向 32 字节小端 limb 区的裸指针。
 *
 * A 256-bit unsigned integer: a raw pointer to a 32-byte little-endian limb area.
 */
export type U256 = usize;

/** 512-bit 中间积：指向 64 字节小端 limb 区的裸指针。
 *
 * A 512-bit intermediate product: a raw pointer to a 64-byte little-endian limb area.
 */
export type U512 = usize;

/** 一个 U256 的字节数。
 *
 * The number of bytes in one U256.
 */
export const U256_BYTES: usize = 32;

// ---------- 模块级 bump arena ----------
//
// ---------- Module-level bump arena ----------

const ARENA_BYTES: usize = 4 << 20; // 4 MiB
// 用 heap.alloc 而不是 `new StaticArray<u8>`：后者会从 TLSF（GC 堆）里吃掉
// 4 MiB，把 GC 的可用空间压低，随后任何一次分配都可能触发 memory.grow —— 而
// JS 门面持有 `new Uint8Array(memory.buffer)` 视图，内存一增长就 detach。
// heap.alloc 在 __heap_base 之上 bump，与自顶向下的 GC 堆互不侵占。
//
// Use heap.alloc rather than `new StaticArray<u8>`: the latter would take 4 MiB out of
// the TLSF (GC) heap, squeezing the space GC has available, after which any allocation
// might trigger memory.grow — and the JS facade holds a `new Uint8Array(memory.buffer)`
// view, which detaches as soon as memory grows. heap.alloc bumps above __heap_base and
// does not compete with the top-down GC heap.
const ARENA_BASE: usize = heap.alloc(ARENA_BYTES);
let ARENA_OFF: usize = 0;
let ARENA_HW: usize = 0;

/** 记录 arena 水位（导出函数入口调用）。
 *
 * Record the arena watermark (called on entry of an exported function).
 */
export function arenaMark(): usize {
  return ARENA_OFF;
}

/** 回退 arena 到 mark（导出函数出口调用）；期间分配的 U256 全部失效。
 *
 * Roll the arena back to `mark` (called on exit of an exported function); every U256
 * allocated in between becomes invalid.
 */
export function arenaReset(mark: usize): void {
  ARENA_OFF = mark;
}

// 模块级常量（SM2/SM9 的 p、n、基点坐标…）在模块初始化时也走 arena。它们在
// 首次导出调用之前就已分配完毕，所以「首次调用时封存水位、之后每次调用回卷到
// 该水位」既保住了常量，又让单次调用内的临时量零成本回收。
//
// Module-level constants (SM2/SM9's p, n, base-point coordinates, …) are also allocated
// from the arena during module initialization. They are all in place before the first
// exported call, so "seal the watermark on the first call, then rewind to it on every
// later call" keeps the constants alive while reclaiming a call's temporaries at zero
// cost.
let BASE_MARK: usize = 0;
let SEALED: bool = false;

/**
 * 回卷到模块初始化后的水位（每个 wasm 导出函数的第一条语句）。
 *
 * 首次调用时封存水位（此时模块级常量已全部就位），之后每次调用都从该水位
 * 重新分配 —— 等价于「每次调用一个全新的 arena」，且不触碰常量。
 *
 * Rewind to the watermark left by module initialization (the first statement of every
 * wasm export).
 *
 * The first call seals the watermark (by then all module-level constants are in place);
 * every later call allocates again from that watermark — equivalent to "a fresh arena
 * per call" without ever touching the constants.
 */
export function arenaRewind(): void {
  if (!SEALED) {
    BASE_MARK = ARENA_OFF;
    SEALED = true;
    return;
  }
  ARENA_OFF = BASE_MARK;
}

/** 诊断：本次进程内 arena 高水位（字节）。
 *
 * Diagnostic: the arena high-water mark (in bytes) for this process lifetime.
 */
export function arenaHighWater(): usize {
  return ARENA_HW;
}

/** 在 arena 里分配 n 字节（U256 分配恒为 32 的倍数）。
 *
 * Allocate `n` bytes from the arena (U256 allocations are always a multiple of 32).
 */
export function arenaAlloc(n: usize): usize {
  const off = ARENA_OFF + n;
  // arena 不够：立即失败，绝不静默越界
  //
  // Arena exhausted: fail immediately, never silently run past the end.
  if (off > ARENA_BYTES) unreachable();
  if (off > ARENA_HW) ARENA_HW = off;
  const p = ARENA_BASE + ARENA_OFF;
  ARENA_OFF = off;
  return p;
}

// ---------- 永久区（跨导出调用的缓存） ----------
//
// arena 会在每次导出调用入口回卷，所以**跨调用存活**的数据（例如 SM9 固定基点
// 的 comb 预计算表）不能落在 arena 里。永久区同样是一次 heap.alloc 的 bump 区，
// 但不受 arenaRewind 影响。
//
// ---------- Permanent area (a cache that outlives exported calls) ----------
//
// The arena rewinds on entry of every exported call, so data that must **survive
// across calls** (for example the comb precomputation table of SM9's fixed base point)
// cannot live in the arena. The permanent area is likewise a bump area carved by one
// heap.alloc, but arenaRewind does not affect it.
const PERM_BYTES: usize = 1 << 20; // 1 MiB
const PERM_BASE: usize = heap.alloc(PERM_BYTES);
let PERM_OFF: usize = 0;

/** 在永久区分配 n 字节。
 *
 * Allocate `n` bytes in the permanent area.
 */
export function permAlloc(n: usize): usize {
  const off = PERM_OFF + n;
  if (off > PERM_BYTES) unreachable();
  const p = PERM_BASE + PERM_OFF;
  PERM_OFF = off;
  return p;
}

/** 把一个 U256 深拷贝到永久区，返回新地址。
 *
 * Deep-copy a U256 into the permanent area and return the new address.
 */
export function permU256(src: U256): U256 {
  const p = permAlloc(U256_BYTES);
  memory.copy(p, src, U256_BYTES);
  return p;
}

// ---------- limb 访问 ----------
//
// ---------- Limb access ----------

/** 读第 i 个 limb（小端）。
 *
 * Read limb i (little-endian).
 */
function limb(a: U256, i: i32): u32 {
  return load<u32>(a + ((<usize>i) << 2));
}

/** 写第 i 个 limb（小端）。
 *
 * Write limb i (little-endian).
 */
function setLimb(a: U256, i: i32, v: u32): void {
  store<u32>(a + ((<usize>i) << 2), v);
}

// ---------- 构造 / 转换 ----------
//
// ---------- Construction / conversion ----------

/** 构造全零的 256-bit。
 *
 * Build an all-zero 256-bit value.
 */
export function u256zero(): U256 {
  const r = arenaAlloc(U256_BYTES);
  memory.fill(r, 0, U256_BYTES);
  return r;
}

/**
 * 从 u32 构造 U256（其余 limb 清零）。
 *
 * Builds a U256 from a u32 with the remaining limbs zeroed.
 */
export function u256fromU32(v: u32): U256 {
  const x = arenaAlloc(U256_BYTES);
  memory.fill(x, 0, U256_BYTES);
  setLimb(x, 0, v);
  return x;
}

/** 从 Uint8Array（大端）读 256-bit，起点 off。
 *
 * Read a 256-bit value from a Uint8Array (big-endian), starting at `off`.
 */
export function u256fromBytes(b: Uint8Array, off: usize): U256 {
  // 注意：Uint8Array 是 TypedArray，数据在 .buffer 里，`changetype<usize>(b)` 拿到的是
  // **对象指针**而不是数据起始 —— 必须走 `.dataStart`（StaticArray<u8> 才可以直接
  // changetype，它的引用本身就指向数据）。
  //
  // Note: a Uint8Array is a TypedArray, so its data lives in `.buffer`, and
  // `changetype<usize>(b)` yields the **object pointer** rather than the start of the
  // data — `.dataStart` must be used (only a StaticArray<u8> can be changetyped
  // directly, because its reference points at the data).
  return u256fromMemBE(b.dataStart + off);
}

/** 从线性内存读 32 字节大端为 U256。
 *
 * Read 32 big-endian bytes of linear memory into a U256.
 */
export function u256fromMemBE(b: usize): U256 {
  const x = arenaAlloc(U256_BYTES);
  for (let i = 0; i < 8; i++) {
    const o = b + i * 4;
    const v =
      ((<u32>load<u8>(o)) << 24) |
      ((<u32>load<u8>(o + 1)) << 16) |
      ((<u32>load<u8>(o + 2)) << 8) |
      <u32>load<u8>(o + 3);
    setLimb(x, 7 - i, v & 0xffffffff);
  }
  return x;
}

/** 写 256-bit 到线性内存 out（大端），32 字节。
 *
 * Write a 256-bit value to linear memory at `out` (big-endian), 32 bytes.
 */
export function u256toBytes(x: U256, out: usize): void {
  for (let i = 0; i < 8; i++) {
    const v = limb(x, 7 - i);
    store<u8>(out + i * 4, <u8>(v >>> 24));
    store<u8>(out + i * 4 + 1, <u8>(v >>> 16));
    store<u8>(out + i * 4 + 2, <u8>(v >>> 8));
    store<u8>(out + i * 4 + 3, <u8>v);
  }
}

/** 判断 256-bit 是否全 0（1=零）。
 *
 * Whether the 256-bit value is all zero (1 = zero).
 */
export function u256isZero(a: U256): bool {
  for (let i = 0; i < 8; i++) if (limb(a, i) !== 0) return false;
  return true;
}

/** 判断 256-bit 是否等于给定 32 字节大端。
 *
 * Whether the 256-bit value equals the given 32 big-endian bytes.
 */
export function u256eqBytes(a: U256, b: Uint8Array, off: usize): bool {
  const base = b.dataStart + off;
  for (let i = 0; i < 8; i++) {
    const x = limb(a, 7 - i);
    const o = base + i * 4;
    const y =
      ((<u32>load<u8>(o)) << 24) |
      ((<u32>load<u8>(o + 1)) << 16) |
      ((<u32>load<u8>(o + 2)) << 8) |
      <u32>load<u8>(o + 3);
    if (x !== (y & 0xffffffff)) return false;
  }
  return true;
}

/** 返回新分配的副本。
 *
 * Return a newly allocated copy.
 */
export function u256clone(a: U256): U256 {
  const r = arenaAlloc(U256_BYTES);
  memory.copy(r, a, U256_BYTES);
  return r;
}

/** 原地拷贝：dst = src（保持旧的 `u256copy(src, dst)` 签名）。
 *
 * In-place copy: dst = src (keeping the old `u256copy(src, dst)` signature).
 */
export function u256copy(src: U256, dst: U256): void {
  memory.copy(dst, src, U256_BYTES);
}

/** 从 8 个 u32（小端）构造 U256。
 *
 * Build a U256 from 8 u32 limbs (little-endian).
 */
export function u256fromLimbs(limbs: StaticArray<u32>): U256 {
  const r = arenaAlloc(U256_BYTES);
  for (let i = 0; i < 8; i++) setLimb(r, i, limbs[i]);
  return r;
}

// ---------- 比较 / 位 ----------
//
// ---------- Comparison / bits ----------

/** 比较：a > b → 1，a == b → 0，a < b → -1。
 *
 * Compare: a > b → 1, a == b → 0, a < b → -1.
 */
export function u256cmp(a: U256, b: U256): i32 {
  for (let i = 7; i >= 0; i--) {
    const x = limb(a, i);
    const y = limb(b, i);
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

/** 取第 i 位（0..255）。
 *
 * Extract bit i (0..255).
 */
export function u256bit(a: U256, i: i32): u32 {
  return (limb(a, i >> 5) >>> (i & 31)) & 1;
}

/** 判断两个 256-bit 是否相等。
 *
 * Whether two 256-bit values are equal.
 */
export function u256eq(a: U256, b: U256): bool {
  return u256cmp(a, b) === 0;
}

/** 从十六进制字符串构造 U256。
 *
 * Build a U256 from a hexadecimal string.
 */
export function u256fromHex(hex: string): U256 {
  const x = arenaAlloc(U256_BYTES);
  const n = hex.length;
  for (let i = 0; i < 8; i++) {
    let v: u32 = 0;
    // 从低位读 8 个 hex 字符（4 字节）。
    //
    // Read 8 hex characters (4 bytes) at a time, starting from the low end.
    const end = n - i * 8;
    const start = end - 8;
    for (let j = start; j < end; j++) {
      if (j < 0) {
        v = (v << 4) & 0xffffffff;
        continue;
      }
      v = ((v << 4) | hexNib(hex.charCodeAt(j))) & 0xffffffff;
    }
    setLimb(x, i, v);
  }
  return x;
}

/** 单个 hex 字符的数值；非法字符返回 0（不报错）。
 *
 * Numeric value of a single hex character; illegal characters return 0 (matching the
 * previous behaviour).
 */
function hexNib(c: i32): u32 {
  if (c >= 0x30 && c <= 0x39) return <u32>(c - 0x30);
  if (c >= 0x41 && c <= 0x46) return <u32>(c - 0x41 + 10);
  if (c >= 0x61 && c <= 0x66) return <u32>(c - 0x61 + 10);
  return 0;
}

// ---------- 原始 256-bit 加 / 减（mod 2^256） ----------
//
// ---------- Raw 256-bit add / sub (mod 2^256) ----------

/** a += b（mod 2^256），返回进位。
 *
 * a += b (mod 2^256); returns the carry.
 */
export function u256addRaw(a: U256, b: U256): u32 {
  let carry: u64 = 0;
  for (let i = 0; i < 8; i++) {
    const s: u64 = u64(limb(a, i)) + u64(limb(b, i)) + carry;
    setLimb(a, i, <u32>(s & 0xffffffff));
    carry = s >>> 32;
  }
  return <u32>carry;
}

/** a -= b（mod 2^256），返回借位。
 *
 * a -= b (mod 2^256); returns the borrow.
 */
export function u256subRaw(a: U256, b: U256): u32 {
  let borrow: i64 = 0;
  for (let i = 0; i < 8; i++) {
    const d: i64 = i64(limb(a, i)) - i64(limb(b, i)) - borrow;
    if (d < 0) {
      setLimb(a, i, <u32>(d + 0x100000000));
      borrow = 1;
    } else {
      setLimb(a, i, <u32>d);
      borrow = 0;
    }
  }
  return <u32>borrow;
}

// ---------- 模运算（模数 m 作参数） ----------
//
// ---------- Modular arithmetic (the modulus m is a parameter) ----------

/** (a + b) mod m。要求 a、b < m 且 m != 0。
 *
 * (a + b) mod m. Requires a, b < m and m != 0.
 */
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
 * 供 fp2 / fp4 层的 `*To` 算子使用：整条扩域运算链不再产生逐次的分配。
 *
 * out = (a + b) mod m (in-place variant; `out` may alias a / b).
 *
 * Used by the `*To` operators of the fp2 / fp4 layers so the whole extension-field
 * computation chain allocates nothing step by step.
 */
export function modAddInto(out: U256, a: U256, b: U256, m: U256): void {
  let carry: u64 = 0;
  for (let i = 0; i < 8; i++) {
    const s: u64 = u64(limb(a, i)) + u64(limb(b, i)) + carry;
    setLimb(out, i, <u32>(s & 0xffffffff));
    carry = s >>> 32;
  }
  if (carry !== 0 || u256cmp(out, m) >= 0) {
    let borrow: i64 = 0;
    for (let i = 0; i < 8; i++) {
      const d: i64 = i64(limb(out, i)) - i64(limb(m, i)) - borrow;
      if (d < 0) {
        setLimb(out, i, <u32>(d + 0x100000000));
        borrow = 1;
      } else {
        setLimb(out, i, <u32>d);
        borrow = 0;
      }
    }
  }
}

/** out = (a - b) mod m（原地变体，允许 out 与 a / b 别名）。
 *
 * out = (a - b) mod m (in-place variant; `out` may alias a / b).
 */
export function modSubInto(out: U256, a: U256, b: U256, m: U256): void {
  let borrow: i64 = 0;
  for (let i = 0; i < 8; i++) {
    const d: i64 = i64(limb(a, i)) - i64(limb(b, i)) - borrow;
    if (d < 0) {
      setLimb(out, i, <u32>(d + 0x100000000));
      borrow = 1;
    } else {
      setLimb(out, i, <u32>d);
      borrow = 0;
    }
  }
  if (borrow !== 0) {
    let c: u64 = 0;
    for (let i = 0; i < 8; i++) {
      const s: u64 = u64(limb(out, i)) + u64(limb(m, i)) + c;
      setLimb(out, i, <u32>(s & 0xffffffff));
      c = s >>> 32;
    }
  }
}

/** (a - b) mod m。要求 a、b < m。
 *
 * (a - b) mod m. Requires a, b < m.
 */
export function modSub(a: U256, b: U256, m: U256): U256 {
  const r = u256clone(a);
  const borrow = u256subRaw(r, b);
  if (borrow !== 0) {
    u256addRaw(r, m);
  }
  return r;
}

/** a(8) × b(8) → 512-bit(16)，学校算法。
 *
 * a(8) × b(8) → 512-bit(16) by the schoolbook algorithm.
 */
export function mul512(a: U256, b: U256): U512 {
  const r = arenaAlloc(64);
  memory.fill(r, 0, 64);
  mul512Into(a, b, r);
  return r;
}

/**
 * 512-bit mod m（基数 2^32 多 limb 长除法，Knuth D 简化版）。
 *
 * 每轮处理 x 的一个 32-bit limb（共 16 轮），而非逐位（512 轮）——快约 30~50×。
 * 假定 m 的最高 limb ≥ 2^31（SM2/SM9 的 p、n 均满足），此时估商高估 ≤ 2。
 *
 * 512-bit value mod m (base 2^32 multi-limb long division, a simplified Knuth D).
 *
 * Each round consumes one 32-bit limb of x (16 rounds) instead of one bit (512 rounds)
 * — roughly 30~50× faster. Assumes the modulus's top limb is ≥ 2^31 (true for SM2/SM9's
 * p and n), in which case the quotient estimate overshoots by at most 2.
 */
export function reduce512(x: U512, m: U256): U256 {
  const out = arenaAlloc(U256_BYTES);
  reduce512Into(x, m, out);
  return out;
}

/** reduce512 的 scratch 版（modMul 长除回退路径用，无逐次分配）。
 *
 * Scratch variant of reduce512 (used by modMul's long-division fallback; no per-step
 * allocation).
 */
function reduce512Into(x: usize, m: U256, out: U256): void {
  // r：余数（< m · 2^32，故 9 limb 足够）；t：q · m。
  //
  // r: the remainder (< m · 2^32, so 9 limbs suffice); t: q · m.
  const r = RD_R;
  const t = RD_T;
  for (let k = 0; k < 9; k++) store<u32>(r + ((<usize>k) << 2), 0);
  const mhi = limb(m, 7);
  for (let i = 15; i >= 0; i--) {
    // r = r * 2^32 + x[i]
    for (let k = 8; k > 0; k--) {
      store<u32>(r + ((<usize>k) << 2), load<u32>(r + ((<usize>(k - 1)) << 2)));
    }
    store<u32>(r, load<u32>(x + ((<usize>i) << 2)));

    // 估商 q = floor((r[8]·2^32 + r[7]) / m[7])，上限 2^32-1
    //
    // Estimate the quotient q = floor((r[8]·2^32 + r[7]) / m[7]), capped at 2^32-1.
    const num = (u64(load<u32>(r + 32)) << 32) | u64(load<u32>(r + 28));
    const qq = num / u64(mhi);
    let q: u32 = qq > u64(0xffffffff) ? 0xffffffff : <u32>qq;

    // 试减 r - q·m；若借位（q 高估）则恢复 r、q-- 重试（≤2 次）
    //
    // Trial subtraction r - q·m; on borrow (q overestimated) restore r, decrement q and
    // retry (≤2 times).
    let tries = 0;
    while (true) {
      let carry: u64 = 0;
      for (let j = 0; j < 8; j++) {
        const cur = u64(q) * u64(limb(m, j)) + carry;
        store<u32>(t + ((<usize>j) << 2), <u32>(cur & 0xffffffff));
        carry = cur >>> 32;
      }
      store<u32>(t + 32, <u32>carry);

      let borrow: i64 = 0;
      for (let k = 0; k < 9; k++) {
        const d: i64 =
          i64(load<u32>(r + ((<usize>k) << 2))) - i64(load<u32>(t + ((<usize>k) << 2))) - borrow;
        if (d < 0) {
          store<u32>(r + ((<usize>k) << 2), <u32>(d + 0x100000000));
          borrow = 1;
        } else {
          store<u32>(r + ((<usize>k) << 2), <u32>d);
          borrow = 0;
        }
      }
      if (borrow === 0) break;

      // 恢复 r（加回 t），q 减 1 重试
      //
      // Restore r (add t back), decrement q and retry.
      let c: u64 = 0;
      for (let k = 0; k < 9; k++) {
        const s = u64(load<u32>(r + ((<usize>k) << 2))) + u64(load<u32>(t + ((<usize>k) << 2))) + c;
        store<u32>(r + ((<usize>k) << 2), <u32>(s & 0xffffffff));
        c = s >>> 32;
      }
      q = (q - 1) & 0xffffffff;
      tries++;
      // 安全阀（不应触发）。
      //
      // Safety valve (should never trigger).
      if (tries > 4) break;
    }

    // 兜底：确保 r < m
    //
    // Backstop: make sure r < m.
    while (load<u32>(r + 32) !== 0 || cmp9(r, m) >= 0) {
      sub9(r, m);
    }
  }
  for (let i = 0; i < 8; i++) setLimb(out, i, load<u32>(r + ((<usize>i) << 2)));
}

/** 大端字节串（任意长度）mod m：Horner 法 acc = acc*256 + b[i]。用于 SM9 的 40 字节哈希取模。
 *
 * Big-endian byte string (of any length) mod m by Horner's rule, acc = acc*256 + b[i].
 * Used for SM9's 40-byte hash reduction.
 */
export function bytesMod(b: StaticArray<u8>, m: U256): U256 {
  const c256 = arenaAlloc(U256_BYTES);
  memory.fill(c256, 0, U256_BYTES);
  setLimb(c256, 0, 256);
  let acc = arenaAlloc(U256_BYTES);
  memory.fill(acc, 0, U256_BYTES);
  const add = arenaAlloc(U256_BYTES);
  for (let i = 0; i < b.length; i++) {
    acc = modMul(acc, c256, m);
    memory.fill(add, 0, U256_BYTES);
    setLimb(add, 0, <u32>b[i]);
    acc = modAdd(acc, add, m);
  }
  return acc;
}

/** 比较 9-limb scratch 值与 U256：a > b → 1，a == b → 0，a < b → -1。
 *
 * Compare a 9-limb scratch value against a U256: a > b → 1, a == b → 0, a < b → -1.
 */
function cmp9(a: usize, b: U256): i32 {
  if (load<u32>(a + 32) !== 0) return 1;
  for (let i = 7; i >= 0; i--) {
    const ai = load<u32>(a + ((<usize>i) << 2));
    const bi = limb(b, i);
    if (ai > bi) return 1;
    if (ai < bi) return -1;
  }
  return 0;
}

/** 9-limb 裸指针减 U256（a -= b），b 的第 9 limb 视为 0。
 *
 * Subtract a U256 from a 9-limb raw pointer (a -= b), treating b's 9th limb as 0.
 */
function sub9(a: usize, b: U256): void {
  let borrow: i64 = 0;
  for (let i = 0; i < 9; i++) {
    const bi: i64 = i < 8 ? i64(limb(b, i)) : 0;
    const d: i64 = i64(load<u32>(a + ((<usize>i) << 2))) - bi - borrow;
    if (d < 0) {
      store<u32>(a + ((<usize>i) << 2), <u32>(d + 0x100000000));
      borrow = 1;
    } else {
      store<u32>(a + ((<usize>i) << 2), <u32>d);
      borrow = 0;
    }
  }
}

/**
 * (a * b) mod m。已知模数（SM2/SM9 的 p、n）走 Barrett 归约，否则回退多 limb 长除法。
 *
 * 内部工作数组（512-bit 积、Barrett 的 q1/q2/q3/r2/r、长除法的 r/t）全部走模块级
 * scratch，不逐次分配——modMul 是 pairing/点乘的最热路径。
 * scratch 非重入：modMul/modSqr 是叶子函数（不互相嵌套），调用方拿到的返回值是
 * 独立分配（arena）的 U256，不受后续调用影响。
 *
 * 下方 scratch 缓冲区的用途：
 * - MUL_X：512-bit 积；
 * - BR_Q1 / BR_Q2 / BR_Q3 / BR_R2 / BR_R：Barrett 归约的中间量 q1/q2/q3/r2/r；
 * - RD_R：reduce512 的余数；RD_T：reduce512 的 q·m。
 *
 * (a * b) mod m. Known moduli (SM2/SM9's p and n) use Barrett reduction; anything else
 * falls back to multi-limb long division.
 *
 * Every internal workspace array (the 512-bit product, Barrett's q1/q2/q3/r2/r, the
 * long division's r/t) lives in module-level scratch instead of being allocated per
 * step — modMul is the hottest path of pairing / point multiplication.
 * The scratch is not reentrant: modMul/modSqr are leaf functions (they never nest), and
 * the value handed to the caller is a separately allocated (arena) U256 that later
 * calls do not disturb.
 *
 * Buffer roles below:
 * - MUL_X: the 512-bit product;
 * - BR_Q1 / BR_Q2 / BR_Q3 / BR_R2 / BR_R: the intermediates q1/q2/q3/r2/r of the
 *   Barrett reduction;
 * - RD_R: the remainder of reduce512; RD_T: the q·m of reduce512.
 */
const MUL_X: usize = heap.alloc(16 * 4);
const BR_Q1: usize = heap.alloc(9 * 4);
const BR_Q2: usize = heap.alloc(18 * 4);
const BR_Q3: usize = heap.alloc(9 * 4);
const BR_R2: usize = heap.alloc(17 * 4);
const BR_R: usize = heap.alloc(10 * 4);
const RD_R: usize = heap.alloc(9 * 4);
const RD_T: usize = heap.alloc(9 * 4);

/** mul512 的原地版：a × b → out（16 limb 裸指针）。
 *
 * In-place variant of mul512: a × b → out (a raw pointer to 16 limbs).
 */
function mul512Into(a: U256, b: U256, out: usize): void {
  for (let i = 0; i < 16; i++) store<u32>(out + ((<usize>i) << 2), 0);
  for (let i = 0; i < 8; i++) {
    let carry: u64 = 0;
    const ai = u64(limb(a, i));
    for (let j = 0; j < 8; j++) {
      const cur: u64 = u64(load<u32>(out + ((<usize>(i + j)) << 2))) + ai * u64(limb(b, j)) + carry;
      store<u32>(out + ((<usize>(i + j)) << 2), <u32>(cur & 0xffffffff));
      carry = cur >>> 32;
    }
    let k = i + 8;
    while (carry !== 0 && k < 16) {
      const cur: u64 = u64(load<u32>(out + ((<usize>k) << 2))) + carry;
      store<u32>(out + ((<usize>k) << 2), <u32>(cur & 0xffffffff));
      carry = cur >>> 32;
      k++;
    }
  }
}

// ---------- SM2 素域 p 的 Solinas 归约 ----------
//
// p = 2^256 − 2^224 − 2^96 + 2^64 − 1 是伪 Mersenne，于是
//   2^256 ≡ 2^224 + 2^96 − 2^64 + 1  (mod p)
// 把 512 位积里位置 ≥ 8 的每个 32-bit 字按
//   2^32i ≡ 2^32(i−1) + 2^32(i−5) − 2^32(i−6) + 2^32(i−8)
// 展开到低位即可 —— 全程只有加减与移位，**没有乘法**。相比通用 Barrett
// （q1·μ 的 9×9 加 q3·m 的 9×8，共 153 次 32×32 乘法）是数量级差别；SM2 的
// 一次标量乘要做几千次模乘，归约正是签名耗时的大头。
//
// 只有 SM2 的 p 是这个形状：n 与 SM9 的 p/n 仍走 Barrett。展开表与收敛性已用
// limb 级原型对 BigInt 跑过 10015 组（含 p±1、(2^256−1)²、p·p 等边界）对拍。
//
// ---------- Solinas reduction for SM2's prime field p ----------
//
// p = 2^256 − 2^224 − 2^96 + 2^64 − 1 is a pseudo-Mersenne prime, hence
//   2^256 ≡ 2^224 + 2^96 − 2^64 + 1  (mod p)
// so every 32-bit word of the 512-bit product at a position ≥ 8 can be expanded
// downwards via
//   2^32i ≡ 2^32(i−1) + 2^32(i−5) − 2^32(i−6) + 2^32(i−8)
// — the whole fold uses only adds, subtracts and shifts, **no multiplication**. Compared
// with generic Barrett (a 9×9 for q1·μ plus a 9×8 for q3·m, 153 32×32 multiplications in
// total) that is a difference of an order of magnitude; one SM2 scalar multiplication
// performs thousands of modular multiplications, and reduction dominates signing time.
//
// Only SM2's p has this shape: n and SM9's p/n still go through Barrett. The expansion
// table and its convergence were cross-checked against BigInt with a limb-level
// prototype over 10015 cases (including the boundaries p±1, (2^256−1)², p·p, …).

/** SM2 素域 p 的识别指纹（与下面实际检查的 limb 一致）：limb7=fffffffe、
 * limb3=limb1=ffffffff、limb2=0；limb0 与 limb4..limb6 不参与判定。
 *
 * Fingerprint used to recognize SM2's prime field p (matching the limbs actually
 * checked below): limb7=fffffffe, limb3=limb1=ffffffff, limb2=0; limb0 and limb4..limb6
 * take no part in the test.
 */
function isSm2Prime(m: U256): bool {
  if (limb(m, 7) !== 0xfffffffe) return false;
  return limb(m, 2) === 0 && limb(m, 1) === 0xffffffff && limb(m, 3) === 0xffffffff;
}

/** SM2 素域 p 的常量副本（模块初始化时分配，供归约的最终减法使用）。
 *
 * A constant copy of SM2's prime field p (allocated during module init, used by the
 * final subtraction of the reduction).
 */
const SM2_P_ARR: U256 = sm2PrimeInit();

/** 构造 SM2 素域 p 的 limb 值（模块初始化时调用一次）。
 *
 * Build the limb value of SM2's prime field p (called once during module init).
 */
function sm2PrimeInit(): U256 {
  const p = arenaAlloc(U256_BYTES);
  setLimb(p, 0, 0xffffffff);
  setLimb(p, 1, 0xffffffff);
  setLimb(p, 2, 0);
  setLimb(p, 3, 0xffffffff);
  setLimb(p, 4, 0xffffffff);
  setLimb(p, 5, 0xffffffff);
  setLimb(p, 6, 0xffffffff);
  setLimb(p, 7, 0xfffffffe);
  return p;
}

/** Solinas 展开的带符号累加器（16 个 i64；非重入：reduceSm2PInto 是叶子）。
 *
 * Signed accumulator for the Solinas expansion (16 i64 slots; non-reentrant:
 * reduceSm2PInto is a leaf).
 */
const SOL_T: usize = heap.alloc(16 * 8);

/** 向 SOL_T 的第 i 槽累加 v（带符号）。
 *
 * Accumulate v (signed) into slot i of SOL_T.
 */
function solAdd(i: i32, v: i64): void {
  store<i64>(SOL_T + ((<usize>i) << 3), load<i64>(SOL_T + ((<usize>i) << 3)) + v);
}

/** 把 SOL_T 的低 8 槽归一化成 8×u32 写入 out，返回溢出的 carry（可为负）。
 *
 * Normalize the low 8 slots of SOL_T into 8×u32 written to `out`; returns the overflow
 * carry (which may be negative).
 */
function solNormalize(out: U256): i64 {
  let carry: i64 = 0;
  for (let i = 0; i < 8; i++) {
    const v = load<i64>(SOL_T + ((<usize>i) << 3)) + carry;
    setLimb(out, i, <u32>(v & <i64>0xffffffff));
    carry = v >> 32;
  }
  return carry;
}

/** x(512 位) mod SM2 的 p → out。
 *
 * x (512 bits) mod SM2's p → out.
 */
function reduceSm2PInto(x: usize, out: U256): void {
  for (let i = 0; i < 16; i++) {
    store<i64>(SOL_T + ((<usize>i) << 3), <i64>load<u32>(x + ((<usize>i) << 2)));
  }
  // 折叠：从高到低处理位置 15..8（轮到 i 时它已收到所有更高位的贡献）
  //
  // Fold: process positions 15..8 from high to low (by the time i is reached it has
  // already received the contribution of every higher position).
  for (let i = 15; i >= 8; i--) {
    const v = load<i64>(SOL_T + ((<usize>i) << 3));
    if (v === 0) continue;
    store<i64>(SOL_T + ((<usize>i) << 3), 0);
    solAdd(i - 1, v);
    solAdd(i - 5, v);
    solAdd(i - 6, -v);
    solAdd(i - 8, v);
  }
  let carry = solNormalize(out);
  // carry·2^256 折回：+ carry·(2^224 + 2^96 − 2^64 + 1)。|carry| 很小，几轮内收敛。
  //
  // Fold carry·2^256 back: + carry·(2^224 + 2^96 − 2^64 + 1). |carry| is tiny, so it
  // converges within a few rounds.
  let guard = 0;
  while (carry !== 0 && guard < 8) {
    for (let i = 0; i < 8; i++) {
      store<i64>(SOL_T + ((<usize>i) << 3), <i64>load<u32>(out + ((<usize>i) << 2)));
    }
    solAdd(7, carry);
    solAdd(3, carry);
    solAdd(2, -carry);
    solAdd(0, carry);
    carry = solNormalize(out);
    guard++;
  }
  while (u256cmp(out, SM2_P_ARR) >= 0) u256subRaw(out, SM2_P_ARR);
}

/** 归约分派：SM2 的 p 走 Solinas，已知模数走 Barrett，其余回退多 limb 长除法。
 *
 * Reduction dispatch: SM2's p takes Solinas, a known modulus takes Barrett, everything
 * else falls back to multi-limb long division.
 */
function reduceInto(x: usize, m: U256, out: U256): void {
  if (isSm2Prime(m)) {
    reduceSm2PInto(x, out);
    return;
  }
  const mu = barrettMu(m);
  if (mu !== null) barrettReduceInto(x, m, mu, out);
  else reduce512Into(x, m, out);
}

/**
 * 返回 (a · b) mod m 的新分配 U256。
 *
 * Returns a newly allocated U256 equal to (a · b) mod m.
 */
export function modMul(a: U256, b: U256, m: U256): U256 {
  mul512Into(a, b, MUL_X);
  const out = arenaAlloc(U256_BYTES);
  reduceInto(MUL_X, m, out);
  return out;
}

/**
 * out = (a · b) mod m（原地变体，允许 out 与 a / b 别名）。
 *
 * 读 a / b 只发生在 mul512Into 阶段、结果落在 MUL_X；写 out 在归约末尾，
 * 因此 out 与任一入参共享内存都安全。
 *
 * out = (a · b) mod m (in-place variant; `out` may alias a / b).
 *
 * a / b are only read during the mul512Into stage and the result lands in MUL_X; `out`
 * is written at the end of the reduction, so it is safe for `out` to share memory with
 * either input.
 */
export function modMulInto(out: U256, a: U256, b: U256, m: U256): void {
  mul512Into(a, b, MUL_X);
  reduceInto(MUL_X, m, out);
}

/** out = a² mod m（原地变体，允许 out 与 a 别名）。
 *
 * out = a² mod m (in-place variant; `out` may alias a).
 */
export function modSqrInto(out: U256, a: U256, m: U256): void {
  sqr512Into(a, MUL_X);
  reduceInto(MUL_X, m, out);
}

/**
 * a² mod m。平方特化：对角项 a_i·a_i 只算一次，交叉项 a_i·a_j（i<j）只算一次再
 * 翻倍进位——比通用 modMul(a,a) 少 20 个 32×32 部分积（64 → 36+加法）。
 * 归约路径与 modMul 一致（Barrett / 长除法）。
 *
 * a² mod m. A squaring specialization: each diagonal term a_i·a_i is computed once and
 * each cross term a_i·a_j (i<j) once, then doubled with propagation — 20 fewer 32×32
 * partial products than the generic modMul(a,a) (64 → 36 plus additions). The reduction
 * path matches modMul's (Barrett / long division).
 */
export function modSqr(a: U256, m: U256): U256 {
  sqr512Into(a, MUL_X);
  const out = arenaAlloc(U256_BYTES);
  reduceInto(MUL_X, m, out);
  return out;
}

/**
 * a(8) × a(8) → 512-bit(16) 平方，**Comba（列扫描）+ 统一进位**。
 *
 * 旧实现每对 (i, j>i) 都要跑两遍完整的进位传播 while 循环（28 对 × 2 = 56 次
 * 内存循环），是 SM2 里最贵的单个函数（CPU 采样 ~37%，比同规模的乘法还高一倍）。
 * 现在改成：所有部分积先拆 lo/hi 累加进 16 个 u64 槽，最后只做一遍进位。
 *
 * 槽容量：位置 k 最多收到 8 个交叉 lo（各 ×2）+ 8 个交叉 hi（各 ×2）+ 1 个对角项，
 * 每项 < 2^32，故槽值 < 2^37，u64 富余。
 *
 * a(8) × a(8) → 512-bit(16) squaring by **Comba (column scan) with one unified carry
 * pass**.
 *
 * The old implementation ran two full carry-propagation while loops for every (i, j>i)
 * pair (28 pairs × 2 = 56 memory loops), making it the single most expensive function in
 * SM2 (CPU sampling ~37%, twice as high as the multiplication of the same size). Now all
 * partial products are first split into lo/hi and accumulated into 16 u64 slots, and only
 * one carry pass runs at the end.
 *
 * Slot capacity: position k receives at most 8 cross lo terms (×2 each) + 8 cross hi terms
 * (×2 each) + 1 diagonal term; every term is < 2^32, so a slot stays < 2^37, well inside
 * u64.
 */
const SQ_T: usize = heap.alloc(16 * 8);

/** 原地平方：a(8) × a(8) → out（16 limb 裸指针）。算法与进位策略见上方的 Comba 说明。
 *
 * In-place squaring: a(8) × a(8) → out (a raw pointer to 16 limbs). See the Comba notes
 * above for the algorithm and the carry strategy.
 */
function sqr512Into(a: U256, out: usize): void {
  for (let k = 0; k < 16; k++) store<u64>(SQ_T + ((<usize>k) << 3), 0);
  // 交叉项 2·a_i·a_j（i < j）
  //
  // Cross terms 2·a_i·a_j (i < j).
  for (let i = 0; i < 8; i++) {
    const ai = u64(limb(a, i));
    for (let j = i + 1; j < 8; j++) {
      const p = ai * u64(limb(a, j));
      const lo = p & <u64>0xffffffff;
      const hi = p >>> 32;
      const klo = SQ_T + ((<usize>(i + j)) << 3);
      const khi = klo + 8;
      store<u64>(klo, load<u64>(klo) + lo + lo);
      store<u64>(khi, load<u64>(khi) + hi + hi);
    }
  }
  // 对角项 a_i²
  //
  // Diagonal terms a_i².
  for (let i = 0; i < 8; i++) {
    const p = u64(limb(a, i)) * u64(limb(a, i));
    const klo = SQ_T + ((<usize>(i + i)) << 3);
    const khi = klo + 8;
    store<u64>(klo, load<u64>(klo) + (p & <u64>0xffffffff));
    store<u64>(khi, load<u64>(khi) + (p >>> 32));
  }
  // 统一进位
  //
  // One unified carry pass.
  let carry: u64 = 0;
  for (let k = 0; k < 16; k++) {
    const s = load<u64>(SQ_T + ((<usize>k) << 3)) + carry;
    store<u32>(out + ((<usize>k) << 2), <u32>(s & <u64>0xffffffff));
    carry = s >>> 32;
  }
}

/**
 * a^{-1} mod m：**二进制扩展欧几里得**，状态全部放在**局部 4×u64（小端）变量**里。
 *
 * 旧实现把 u/v/x1/x2 放在内存（每数 8×u32），每轮、每次 halveMod/subMod 都要跑若干
 * 完整的 8-limb load/store 循环（单次求逆数万次 limb 访问）。256 位恰好 4 个 u64 装得下，
 * 这里改用 wasm 局部变量：循环体内零内存往返，内层消因子 2 时只做 4 次 u64 移位。
 *
 * 每轮：u、v 各消去因子 2（同时对 Bezout 系数 x、y 做 halveMod），再各减一次。
 * x/2 mod m 仍用无溢出分解（x、m 均奇时 (x+m)/2 = (x>>1) + (m>>1) + 1）——SM2/SM9 的
 * 模数 ≈ 0.7·2^256，x + m 会溢出 256 位。
 *
 * 要求 gcd(a, m) = 1（m 为素数且 a != 0 时恒成立）。a == 0 时返回 0（与原语义一致）。
 *
 * a^{-1} mod m by the **binary extended Euclidean algorithm**, with all state kept in
 * **local 4×u64 (little-endian) variables**.
 *
 * The old implementation kept u/v/x1/x2 in memory (8×u32 each), so every round and every
 * halveMod/subMod ran several full 8-limb load/store loops (tens of thousands of limb
 * accesses per inversion). 256 bits fit exactly in 4 u64s, so wasm locals are used here
 * instead: no memory round-trips inside the loop, and factoring out a 2 costs just 4 u64
 * shifts.
 *
 * Each round: strip the factor 2 from u and from v (applying halveMod to the Bezout
 * coefficients x and y at the same time), then subtract once.
 * x/2 mod m still uses the overflow-free decomposition ((x+m)/2 = (x>>1) + (m>>1) + 1 when
 * both x and m are odd) — SM2/SM9 moduli are ≈ 0.7·2^256, so x + m would overflow 256
 * bits.
 *
 * Requires gcd(a, m) = 1 (always true when m is prime and a != 0). Returns 0 for a == 0
 * (matching the previous semantics).
 */
export function modInv(a: U256, m: U256): U256 {
  if (u256isZero(a)) return u256zero();

  let u0 = load<u64>(a);
  let u1 = load<u64>(a + 8);
  let u2 = load<u64>(a + 16);
  let u3 = load<u64>(a + 24);
  let v0 = load<u64>(m);
  let v1 = load<u64>(m + 8);
  let v2 = load<u64>(m + 16);
  let v3 = load<u64>(m + 24);
  // 模数副本与 (m >> 1)：后者是 halveMod 的常数部分
  //
  // A copy of the modulus plus (m >> 1), the latter being the constant part of halveMod.
  const m0 = v0;
  const m1 = v1;
  const m2 = v2;
  const m3 = v3;
  const hm0 = (m0 >> 1) | (m1 << 63);
  const hm1 = (m1 >> 1) | (m2 << 63);
  const hm2 = (m2 >> 1) | (m3 << 63);
  const hm3 = m3 >> 1;

  // x = u 的 Bezout 系数（初值 1），y = v 的（初值 0），均保持 mod m 非负
  //
  // x is the Bezout coefficient of u (initially 1), y that of v (initially 0); both are
  // kept non-negative modulo m.
  let x0: u64 = 1;
  let x1: u64 = 0;
  let x2: u64 = 0;
  let x3: u64 = 0;
  let y0: u64 = 0;
  let y1: u64 = 0;
  let y2: u64 = 0;
  let y3: u64 = 0;

  while ((u0 | u1 | u2 | u3) !== 0 && (v0 | v1 | v2 | v3) !== 0) {
    // ---- 消去 u 的因子 2：u >>= 1，x = x/2 mod m ----
    //
    // ---- Strip the factor 2 from u: u >>= 1, x = x/2 mod m ----
    while ((u0 & 1) === 0) {
      u0 = (u0 >> 1) | (u1 << 63);
      u1 = (u1 >> 1) | (u2 << 63);
      u2 = (u2 >> 1) | (u3 << 63);
      u3 >>= 1;
      if ((x0 & 1) === 1) {
        const p0 = (x0 >> 1) | (x1 << 63);
        const p1 = (x1 >> 1) | (x2 << 63);
        const p2 = (x2 >> 1) | (x3 << 63);
        const p3 = x3 >> 1;
        let t = p0 + hm0;
        let c: u64 = t < p0 ? 1 : 0;
        const r0 = t + 1;
        // p0 + hm0 == 2^64-1 时再加 1 才溢出。
        //
        // Only when p0 + hm0 == 2^64-1 does adding 1 overflow.
        if (r0 === 0) c = 1;
        t = p1 + hm1;
        let c1: u64 = t < p1 ? 1 : 0;
        const r1 = t + c;
        if (r1 < c) c1 = 1;
        t = p2 + hm2;
        let c2: u64 = t < p2 ? 1 : 0;
        const r2 = t + c1;
        if (r2 < c1) c2 = 1;
        t = p3 + hm3;
        x0 = r0;
        x1 = r1;
        x2 = r2;
        x3 = t + c2;
      } else {
        x0 = (x0 >> 1) | (x1 << 63);
        x1 = (x1 >> 1) | (x2 << 63);
        x2 = (x2 >> 1) | (x3 << 63);
        x3 >>= 1;
      }
    }

    // ---- 消去 v 的因子 2：v >>= 1，y = y/2 mod m ----
    //
    // ---- Strip the factor 2 from v: v >>= 1, y = y/2 mod m ----
    while ((v0 & 1) === 0) {
      v0 = (v0 >> 1) | (v1 << 63);
      v1 = (v1 >> 1) | (v2 << 63);
      v2 = (v2 >> 1) | (v3 << 63);
      v3 >>= 1;
      if ((y0 & 1) === 1) {
        const p0 = (y0 >> 1) | (y1 << 63);
        const p1 = (y1 >> 1) | (y2 << 63);
        const p2 = (y2 >> 1) | (y3 << 63);
        const p3 = y3 >> 1;
        let t = p0 + hm0;
        let c: u64 = t < p0 ? 1 : 0;
        const r0 = t + 1;
        if (r0 === 0) c = 1;
        t = p1 + hm1;
        let c1: u64 = t < p1 ? 1 : 0;
        const r1 = t + c;
        if (r1 < c) c1 = 1;
        t = p2 + hm2;
        let c2: u64 = t < p2 ? 1 : 0;
        const r2 = t + c1;
        if (r2 < c1) c2 = 1;
        t = p3 + hm3;
        y0 = r0;
        y1 = r1;
        y2 = r2;
        y3 = t + c2;
      } else {
        y0 = (y0 >> 1) | (y1 << 63);
        y1 = (y1 >> 1) | (y2 << 63);
        y2 = (y2 >> 1) | (y3 << 63);
        y3 >>= 1;
      }
    }

    // ---- 统一成 u >= v：否则交换 (u, v) 与 (x, y) ----
    //
    // ---- Normalize to u >= v: otherwise swap (u, v) and (x, y) ----
    let uge: bool;
    if (u3 !== v3) uge = u3 > v3;
    else if (u2 !== v2) uge = u2 > v2;
    else if (u1 !== v1) uge = u1 > v1;
    else uge = u0 >= v0;
    if (!uge) {
      const s0 = u0;
      const s1 = u1;
      const s2 = u2;
      const s3 = u3;
      u0 = v0;
      u1 = v1;
      u2 = v2;
      u3 = v3;
      v0 = s0;
      v1 = s1;
      v2 = s2;
      v3 = s3;
      const t0 = x0;
      const t1 = x1;
      const t2 = x2;
      const t3 = x3;
      x0 = y0;
      x1 = y1;
      x2 = y2;
      x3 = y3;
      y0 = t0;
      y1 = t1;
      y2 = t2;
      y3 = t3;
    }

    // ---- u -= v ----
    const e1 = u1 - v1;
    const d1 = e1 - (u0 < v0 ? 1 : 0);
    let b1: u64 = u1 < v1 ? 1 : 0;
    if (e1 < (u0 < v0 ? 1 : 0)) b1 = 1;
    const e2 = u2 - v2;
    const d2 = e2 - b1;
    let b2: u64 = u2 < v2 ? 1 : 0;
    if (e2 < b1) b2 = 1;
    u0 = u0 - v0;
    u1 = d1;
    u2 = d2;
    u3 = u3 - v3 - b2;

    // ---- x = (x - y) mod m ----
    const f0 = x0 - y0;
    const g0: u64 = x0 < y0 ? 1 : 0;
    const h1 = x1 - y1;
    const f1 = h1 - g0;
    let g1: u64 = x1 < y1 ? 1 : 0;
    if (h1 < g0) g1 = 1;
    const h2 = x2 - y2;
    const f2 = h2 - g1;
    let g2: u64 = x2 < y2 ? 1 : 0;
    if (h2 < g1) g2 = 1;
    const h3 = x3 - y3;
    const f3 = h3 - g2;
    if (x3 < y3 || h3 < g2) {
      // 借位：结果 + m
      //
      // Borrow: add m to the result.
      const j0 = f0 + m0;
      const k0: u64 = j0 < f0 ? 1 : 0;
      const j1 = f1 + m1;
      const s1 = j1 + k0;
      let k1: u64 = j1 < f1 ? 1 : 0;
      if (s1 < k0) k1 = 1;
      const j2 = f2 + m2;
      const s2 = j2 + k1;
      let k2: u64 = j2 < f2 ? 1 : 0;
      if (s2 < k1) k2 = 1;
      const j3 = f3 + m3;
      x0 = j0;
      x1 = s1;
      x2 = s2;
      x3 = j3 + k2;
    } else {
      x0 = f0;
      x1 = f1;
      x2 = f2;
      x3 = f3;
    }
  }

  // 退出时非零者为 gcd；素模数下 gcd == 1，对应 Bezout 系数即逆元
  //
  // Whichever is non-zero on exit is the gcd; with a prime modulus gcd == 1, so the
  // corresponding Bezout coefficient is the inverse.
  const out = arenaAlloc(U256_BYTES);
  if ((u0 | u1 | u2 | u3) !== 0) {
    // u == 1：a·x ≡ u ≡ 1
    //
    // u == 1: a·x ≡ u ≡ 1
    store<u64>(out, x0);
    store<u64>(out + 8, x1);
    store<u64>(out + 16, x2);
    store<u64>(out + 24, x3);
  } else {
    // v == 1：a·y ≡ v ≡ 1
    //
    // v == 1: a·y ≡ v ≡ 1
    store<u64>(out, y0);
    store<u64>(out + 8, y1);
    store<u64>(out + 16, y2);
    store<u64>(out + 24, y3);
  }
  return out;
}

/** modHalve 用的常量 1（(m>>1) + 1 = (m+1)/2）。
 *
 * The constant 1 used by modHalve ((m>>1) + 1 = (m+1)/2).
 */
const HLV_ONE: usize = heap.alloc(32);
memory.fill(HLV_ONE, 0, 32);
store<u32>(HLV_ONE, 1);

/** a 是否为奇数。
 *
 * Whether a is odd.
 */
export function u256isOdd(a: U256): bool {
  return (limb(a, 0) & 1) === 1;
}

/** 原地右移一位（a >>= 1）。
 *
 * Shift right by one in place (a >>= 1).
 */
export function u256shr1(a: U256): void {
  let carry: u32 = 0;
  for (let i = 7; i >= 0; i--) {
    const v = limb(a, i);
    setLimb(a, i, ((v >>> 1) | (carry << 31)) & 0xffffffff);
    carry = v & 1;
  }
}

/** (a / 2) mod m（m 为奇数素数的情形）。
 *  注意：m 可能 ≥ 2^255，此时 a + m 会超过 256 位，
 *  因此不能直接 u256addRaw（会丢进位）。改用 (a>>1) + ((a&1) ? (m>>1)+1 : 0)：
 *    a 偶：(a/2)；a 奇：(a-1)/2 + (m+1)/2 = (a+m)/2。
 *  此处 m 恒为奇数，(m>>1)+1 == (m+1)/2。
 *
 * (a / 2) mod m (for an odd prime modulus m).
 * Note: m may be ≥ 2^255, in which case a + m exceeds 256 bits, so u256addRaw cannot be
 * used directly (it would lose the carry). Instead (a>>1) + ((a&1) ? (m>>1)+1 : 0) is
 * used:
 *   a even: (a/2); a odd: (a-1)/2 + (m+1)/2 = (a+m)/2.
 * Here m is always odd, so (m>>1)+1 == (m+1)/2.
 */
export function modHalve(a: U256, m: U256): U256 {
  const r = u256clone(a);
  const odd = u256isOdd(r);
  u256shr1(r);
  if (odd) {
    const half = u256clone(m);
    u256shr1(half);
    // (m>>1) + 1 = (m+1)/2，不会溢出。
    //
    // (m>>1) + 1 = (m+1)/2 and cannot overflow.
    u256addRaw(half, HLV_ONE);
    // r + (m+1)/2 ≤ (a-1)/2 + (m+1)/2 < m，不会溢出。
    //
    // r + (m+1)/2 ≤ (a-1)/2 + (m+1)/2 < m and cannot overflow.
    u256addRaw(r, half);
  }
  return r;
}

// modHalveInto 的 (m>>1) 暂存。
//
// Scratch for the (m>>1) of modHalveInto.
const HALF_TMP: usize = heap.alloc(32);

/** out = a / 2 mod m（原地变体，允许 out 与 a 别名）。
 *
 * out = a / 2 mod m (in-place variant; `out` may alias a).
 */
export function modHalveInto(out: U256, a: U256, m: U256): void {
  const odd = u256isOdd(a);
  let carry: u32 = 0;
  for (let i = 7; i >= 0; i--) {
    const v = limb(a, i);
    setLimb(out, i, ((v >>> 1) | (carry << 31)) & 0xffffffff);
    carry = v & 1;
  }
  if (odd) {
    let hc: u32 = 0;
    for (let i = 7; i >= 0; i--) {
      const v = limb(m, i);
      store<u32>(HALF_TMP + ((<usize>i) << 2), ((v >>> 1) | (hc << 31)) & 0xffffffff);
      hc = v & 1;
    }
    let c: u64 = 1; // (m>>1) + 1
    for (let i = 0; i < 8; i++) {
      const s: u64 = u64(limb(out, i)) + u64(load<u32>(HALF_TMP + ((<usize>i) << 2))) + c;
      setLimb(out, i, <u32>(s & 0xffffffff));
      c = s >>> 32;
    }
  }
}

/**
 * 模幂 a^k mod m（平方-乘，k 为 256-bit，从最低位起扫描：该位为 1 时乘、每轮都平方）。
 * k 为 8×u32 小端。
 *
 * Modular exponentiation a^k mod m (square-and-multiply, k is 256-bit, scanning from the
 * least significant bit: multiply when the bit is 1 and square on every round).
 * k is 8×u32 little-endian.
 */
export function modPow(a: U256, k: U256, m: U256): U256 {
  let result = arenaAlloc(U256_BYTES);
  memory.fill(result, 0, U256_BYTES);
  setLimb(result, 0, 1);
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
//
// ---------- Barrett reduction (SM2/SM9's p and n) ----------
//
// μ = floor(2^512 / m) (257 bits, 9 limbs, precomputed). The reduction is: q1=x>>224;
// q2=q1·μ; q3=q2>>288; r=x[0..8]−((q3·m)[0..8]); then subtract m until < m.
// Pure multiplication + shifts + add/subtract, **no division** — faster than generic
// multi-limb long division.

// Barrett 常数表：μ = floor(2^512 / m)，9×u32 小端。每张表的取值由对应的 p / n
// 唯一确定（纯推论，没有单独的标准章节），由 `barrettMu()` 按模数指纹选用。
//
// Barrett constant tables: μ = floor(2^512 / m) as 9 little-endian u32 limbs. Each
// table's value is uniquely determined by its p / n (a pure consequence, not a separate
// standard clause) and `barrettMu()` selects one from the modulus fingerprint.
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

/** 按模数取 Barrett 常数 μ；未知模数返回 null（回退长除法）。
 *
 * Look up the Barrett constant μ by modulus; returns null for an unknown modulus (which
 * falls back to long division).
 */
function barrettMu(m: U256): StaticArray<u32> | null {
  const hi = limb(m, 7);
  if (hi === 0xfffffffe) {
    if (limb(m, 3) === 0xffffffff) return SM2_P_MU;
    if (limb(m, 3) === 0x7203df6b) return SM2_N_MU;
  } else if (hi === 0xb6400000) {
    if (limb(m, 3) === 0x21f2934b) return SM9_P_MU;
    if (limb(m, 3) === 0x49f2934b) return SM9_N_MU;
  }
  return null;
}

/** out(na+nb) = a(na) · b(nb)（schoolbook）。全部为裸指针。
 *
 * out(na+nb) = a(na) · b(nb) (schoolbook). All arguments are raw pointers.
 */
function mulLimbArrays(a: usize, na: i32, b: usize, nb: i32, out: usize): void {
  for (let i = 0; i < na + nb; i++) store<u32>(out + ((<usize>i) << 2), 0);
  for (let i = 0; i < na; i++) {
    let carry: u64 = 0;
    const ai = u64(load<u32>(a + ((<usize>i) << 2)));
    for (let j = 0; j < nb; j++) {
      const cur =
        u64(load<u32>(out + ((<usize>(i + j)) << 2))) +
        ai * u64(load<u32>(b + ((<usize>j) << 2))) +
        carry;
      store<u32>(out + ((<usize>(i + j)) << 2), <u32>(cur & 0xffffffff));
      carry = cur >>> 32;
    }
    let k = i + nb;
    while (carry !== 0) {
      const cur = u64(load<u32>(out + ((<usize>k) << 2))) + carry;
      store<u32>(out + ((<usize>k) << 2), <u32>(cur & 0xffffffff));
      carry = cur >>> 32;
      k++;
    }
  }
}

/** Barrett 归约（scratch 版）：x(16 limb 裸指针) mod m(8 limb) → out(8 limb)，结果 < m。
 *
 * Barrett reduction (scratch variant): x (raw pointer to 16 limbs) mod m (8 limbs) → out
 * (8 limbs), with the result < m.
 */
function barrettReduceInto(x: usize, m: U256, mu: StaticArray<u32>, out: U256): void {
  const q1 = BR_Q1;
  for (let i = 0; i < 9; i++)
    store<u32>(q1 + ((<usize>i) << 2), load<u32>(x + ((<usize>(7 + i)) << 2))); // x >> 224
  const q2 = BR_Q2;
  mulLimbArrays(q1, 9, changetype<usize>(mu), 9, q2);
  const q3 = BR_Q3;
  for (let i = 0; i < 9; i++)
    store<u32>(q3 + ((<usize>i) << 2), load<u32>(q2 + ((<usize>(9 + i)) << 2))); // q2 >> 288
  const r2 = BR_R2;
  mulLimbArrays(q3, 9, m, 8, r2);

  const r = BR_R;
  let borrow: i64 = 0;
  for (let i = 0; i < 9; i++) {
    const d: i64 =
      i64(load<u32>(x + ((<usize>i) << 2))) - i64(load<u32>(r2 + ((<usize>i) << 2))) - borrow;
    if (d < 0) {
      store<u32>(r + ((<usize>i) << 2), <u32>(d + 0x100000000));
      borrow = 1;
    } else {
      store<u32>(r + ((<usize>i) << 2), <u32>d);
      borrow = 0;
    }
  }
  // r 为负时 +2^288。
  //
  // +2^288 when r is negative.
  store<u32>(r + 36, <u32>borrow);

  let guard = 0;
  while (guard < 4 && (load<u32>(r + 36) !== 0 || load<u32>(r + 32) !== 0 || cmp9(r, m) >= 0)) {
    let b: i64 = 0;
    for (let i = 0; i < 10; i++) {
      const mi: i64 = i < 8 ? i64(limb(m, i)) : 0;
      const d: i64 = i64(load<u32>(r + ((<usize>i) << 2))) - mi - b;
      if (d < 0) {
        store<u32>(r + ((<usize>i) << 2), <u32>(d + 0x100000000));
        b = 1;
      } else {
        store<u32>(r + ((<usize>i) << 2), <u32>d);
        b = 0;
      }
    }
    guard++;
  }

  for (let i = 0; i < 8; i++) setLimb(out, i, load<u32>(r + ((<usize>i) << 2)));
}

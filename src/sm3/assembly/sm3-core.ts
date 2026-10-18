// SM3 纯计算核心（AssemblyScript）—— 归属 SM3 模块。
//
// 本文件**不**包含内存分配导出，只提供纯哈希计算，供：
// - `src/sm3/assembly/index.ts`（编译为 sm3.wasm）
// - `src/sm2/assembly/crypto.ts`（编译进 sm2.wasm，用于 Z 值/KDF/C3）
//
// 两个 wasm 在**编译期**各自内联一份（AssemblyScript 是 AOT 编译器），
// 运行期互不依赖 —— 因此 sm2.wasm 与 sm3.wasm 完全解耦。
//
// 性能要点：
// - 压缩函数的 W 用**模块级 scratch 裸指针**：按块分配 68 个 u32 会让 1KB 输入
//   分配 34 次、64KB 输入 2050 次；
// - 消息块与状态用 u32 访存（`load<u32>`/`store<u32>` + `bswap`）替代每字 4 次
//   `load<u8>` 拼装；
// - **不再物化 W'（W[j] ^ W[j+4]）**：原实现单独跑一遍 64 次 store + 128 次 load，
//   现在在轮循环里就地算（顺序访问 wPtr 与 wPtr+16，缓存友好）；
// - 轮循环用**指针递增**（`wPtr += 4`）替代每轮的 `base + (i << 2)` 地址计算；
// - 轮常数 Tj 一次算进 scratch；u32 运算本就模 2^32，故省去多余的 `& 0xffffffff`；
// - 填充缓冲**模块级复用**：原实现每调用一次 `new StaticArray<u8>(totalLen)`，
//   会分配并清零整个 totalLen（1KB 输入即 1088 字节），而真正需要清零的只有
//   padding 区（≤63 字节）；
// - **HMAC 整体在本模块内完成**（`sm3HmacInto`）：ipad/opad 的拼接与两次摘要调用
//   原先都在 JS 层做（4 次跨边界 + 3 个临时数组的分配与拷贝），现在一次调用到底，
//   且 `ipad ‖ msg` 用两段输入接口直接参与填充，省掉整段拼接拷贝。
//
// 参考：GB/T 32905-2016 / GM/T 0004-2014、RFC 2104。
//
// SM3 pure-computation core (AssemblyScript) — owned by the SM3 module.
//
// This file deliberately has **no** memory-allocation exports; it only provides the
// plain hash computation for:
// - `src/sm3/assembly/index.ts` (compiled to sm3.wasm)
// - `src/sm2/assembly/crypto.ts` (compiled into sm2.wasm for the Z value / KDF / C3)
//
// Both wasm modules inline their own copy at **compile time** (AssemblyScript is an AOT
// compiler) and have no runtime dependency on each other, so sm2.wasm and sm3.wasm stay
// fully decoupled.
//
// Performance notes:
// - The compression function keeps W in a **module-level raw scratch pointer**: allocating
//   68 u32 per block would mean 34 allocations for a 1KB input and 2050 for a 64KB input;
// - Message words and state use u32 accesses (`load<u32>`/`store<u32>` + `bswap`) instead of
//   assembling each word from four `load<u8>` calls;
// - **W′ (W[j] ^ W[j+4]) is no longer materialised**: the old version ran a separate pass of
//   64 stores + 128 loads; it is now computed inline in the round loop (sequentially over
//   wPtr and wPtr+16, which is cache friendly);
// - The round loop uses **pointer increments** (`wPtr += 4`) instead of recomputing
//   `base + (i << 2)` every round;
// - The round constant Tj is precomputed once into scratch; u32 arithmetic is already
//   mod 2^32, so redundant `& 0xffffffff` are dropped;
// - The padding buffer is **reused at module level**: the old version allocated a fresh
//   `new StaticArray<u8>(totalLen)` per call, allocating and zeroing the whole totalLen
//   (1088 bytes for a 1KB input) although only the padding area (≤63 bytes) needs zeroing;
// - **HMAC is completed inside this module** (`sm3HmacInto`): ipad/opad assembly and the
//   two digest calls used to happen in the JS layer (4 boundary crossings plus 3 temporary
//   arrays); now it is a single call, and `ipad ‖ msg` is fed straight into padding through
//   the two-segment input interface, removing the concatenation copy.
//
// References: GB/T 32905-2016 / GM/T 0004-2014, RFC 2104.

// 初始值 IV（GB/T 32905-2016），8 个大端 u32 字。
//
// Initial value IV (GB/T 32905-2016), eight big-endian u32 words.
const IV0: u32 = 0x7380166f;
const IV1: u32 = 0x4914b2b9;
const IV2: u32 = 0x172442d7;
const IV3: u32 = 0xda8a0600;
const IV4: u32 = 0xa96f30bc;
const IV5: u32 = 0x163138aa;
const IV6: u32 = 0xe38dee4d;
const IV7: u32 = 0xb0fb0e4e;

// 轮常数 T0（j < 16）/ T1（j ≥ 16），GB/T 32905-2016。
//
// Round constants T0 (j < 16) / T1 (j ≥ 16), GB/T 32905-2016.
const T0: u32 = 0x79cc4519;
const T1: u32 = 0x7a879d8a;

/**
 * 32 位循环左移 n 位。
 *
 * Rotate a 32-bit word left by n bits.
 */
function rotl(x: u32, n: i32): u32 {
  return (x << n) | (x >>> (32 - n));
}
/**
 * 前 16 轮（0 ≤ j ≤ 15）的布尔函数 FF_j(X, Y, Z) = X ⊕ Y ⊕ Z。
 *
 * Boolean function FF_j(X, Y, Z) = X ⊕ Y ⊕ Z used in rounds 0 ≤ j ≤ 15.
 */
function ff0(x: u32, y: u32, z: u32): u32 {
  return x ^ y ^ z;
}
/**
 * 后 48 轮（16 ≤ j ≤ 63）的布尔函数 FF_j(X, Y, Z) = (X&Y) | (Y&Z) | (X&Z)。
 *
 * Boolean function FF_j(X, Y, Z) = (X&Y) | (Y&Z) | (X&Z) used in rounds 16 ≤ j ≤ 63.
 */
function ff1(x: u32, y: u32, z: u32): u32 {
  return (x & y) | (y & z) | (x & z);
}
/**
 * 前 16 轮（0 ≤ j ≤ 15）的布尔函数 GG_j(X, Y, Z) = X ⊕ Y ⊕ Z。
 *
 * Boolean function GG_j(X, Y, Z) = X ⊕ Y ⊕ Z used in rounds 0 ≤ j ≤ 15.
 */
function gg0(x: u32, y: u32, z: u32): u32 {
  return x ^ y ^ z;
}
/**
 * 后 48 轮（16 ≤ j ≤ 63）的布尔函数 GG_j(X, Y, Z) = (X&Y) | (¬X&Z)。
 *
 * Boolean function GG_j(X, Y, Z) = (X&Y) | (¬X&Z) used in rounds 16 ≤ j ≤ 63.
 */
function gg1(x: u32, y: u32, z: u32): u32 {
  return (x & y) | (~x & z);
}
/**
 * 置换函数 P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17)。
 *
 * Permutation P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17).
 */
function p0(x: u32): u32 {
  return x ^ rotl(x, 9) ^ rotl(x, 17);
}
/**
 * 置换函数 P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23)。
 *
 * Permutation P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23).
 */
function p1(x: u32): u32 {
  return x ^ rotl(x, 15) ^ rotl(x, 23);
}

/**
 * 压缩函数工作区：**线性内存裸指针**（heap.alloc 得到，不受 GC 管理）。
 *
 * 为什么不用 `StaticArray<u32>`：AS 会把 `arr[i]` 编译成 runtime 调用
 * `StaticArray<u32>#__get/__set`（含边界检查 + GC 写屏障），且要调整 GC 栈帧。
 * SM3 每块要做 400+ 次工作区访问，编译产物里每个 `W[i] = x` 都是一次 `call`，
 * 于是每块 2µs 里绝大部分是这些调用开销（这也是纯 JS + TypedArray 反而更快的原因：
 * V8 把 TypedArray 访问 JIT 成直接内存指令）。
 *
 * 改成裸指针 + `load<u32>`/`store<u32>` 后编译为直接的 i32.load/i32.store：
 * 无函数调用、无边界检查、无 GC 介入。
 *
 * `compress` 是叶子函数（不递归、不重入），这些区域单次调用独占，跨块复用安全。
 *
 * Compression-function workspace: **raw pointers into linear memory** (obtained from
 * heap.alloc, so not managed by the GC).
 *
 * Why not `StaticArray<u32>`: AS compiles `arr[i]` into calls to the runtime
 * `StaticArray<u32>#__get/__set` (with bounds checks and GC write barriers) and has to
 * adjust the GC frame. SM3 touches this workspace 400+ times per block, so in the
 * compiled output every `W[i] = x` is a `call`; those calls are most of the ~2µs per
 * block (this is also why plain JS + TypedArray can be faster: V8 JITs TypedArray
 * accesses into direct memory instructions).
 *
 * With raw pointers plus `load<u32>`/`store<u32>` the code compiles to plain
 * i32.load/i32.store: no calls, no bounds checks, no GC involvement.
 *
 * `compress` is a leaf function (no recursion, no reentrancy), so it exclusively owns
 * these regions for the duration of a call and reusing them across blocks is safe.
 */
const W_PTR: usize = heap.alloc(68 * 4);
const TJ_PTR: usize = heap.alloc(64 * 4);
/**
 * 8 个 u32 状态。sm3Core 顺序调用（HMAC 亦为顺序），不重入。
 *
 * Eight u32 state words. sm3Core is always called sequentially (HMAC too), never reentrant.
 */
const STATE_PTR: usize = heap.alloc(8 * 4);

/** 轮常数 Tj = rotl(T0, j)（j < 16）/ rotl(T1, j mod 32)（j ≥ 16）。一次算好复用。
 *
 * Round constant Tj = rotl(T0, j) for j < 16 and rotl(T1, j mod 32) for j ≥ 16; computed
 * once and reused.
 */
for (let j = 0; j < 64; j++) {
  store<u32>(TJ_PTR + ((<usize>j) << 2), rotl(j < 16 ? T0 : T1, j < 16 ? j : j & 31));
}

/**
 * 读大端 u32。wasm 内存是小端，故需 bswap。
 *
 * Read a big-endian u32; wasm memory is little-endian, hence the bswap.
 */
function loadU32BE(p: usize): u32 {
  return bswap<u32>(load<u32>(p));
}

/**
 * 单次压缩：处理 64 字节块，`statePtr`（8 个 u32）原地更新。
 *
 * @param statePtr 8 个 u32 状态指针。
 * @param blockPtr 64 字节块指针（4 字节对齐 —— 块偏移恒为 64 的倍数）。
 *
 * Single compression: process a 64-byte block and update `statePtr` (8 u32) in place.
 *
 * @param statePtr Pointer to the eight u32 state words.
 * @param blockPtr Pointer to the 64-byte block (4-byte aligned — the block offset is always
 *   a multiple of 64).
 */
function compress(statePtr: usize, blockPtr: usize): void {
  // 载入 16 个字（大端）。展开成一串常量偏移，省掉循环控制与地址计算。
  //
  // Load the 16 words (big-endian). Unrolled into constant offsets to save loop control
  // and address computation.
  const bp = blockPtr;
  store<u32>(W_PTR, loadU32BE(bp));
  store<u32>(W_PTR + 4, loadU32BE(bp + 4));
  store<u32>(W_PTR + 8, loadU32BE(bp + 8));
  store<u32>(W_PTR + 12, loadU32BE(bp + 12));
  store<u32>(W_PTR + 16, loadU32BE(bp + 16));
  store<u32>(W_PTR + 20, loadU32BE(bp + 20));
  store<u32>(W_PTR + 24, loadU32BE(bp + 24));
  store<u32>(W_PTR + 28, loadU32BE(bp + 28));
  store<u32>(W_PTR + 32, loadU32BE(bp + 32));
  store<u32>(W_PTR + 36, loadU32BE(bp + 36));
  store<u32>(W_PTR + 40, loadU32BE(bp + 40));
  store<u32>(W_PTR + 44, loadU32BE(bp + 44));
  store<u32>(W_PTR + 48, loadU32BE(bp + 48));
  store<u32>(W_PTR + 52, loadU32BE(bp + 52));
  store<u32>(W_PTR + 56, loadU32BE(bp + 56));
  store<u32>(W_PTR + 60, loadU32BE(bp + 60));

  // 消息扩展：W[16..68)。
  //
  // Message expansion: W[16..68).
  for (let i = 16; i < 68; i++) {
    const v =
      load<u32>(W_PTR + ((<usize>(i - 16)) << 2)) ^
      load<u32>(W_PTR + ((<usize>(i - 9)) << 2)) ^
      rotl(load<u32>(W_PTR + ((<usize>(i - 3)) << 2)), 15);
    store<u32>(
      W_PTR + ((<usize>i) << 2),
      p1(v) ^
        rotl(load<u32>(W_PTR + ((<usize>(i - 13)) << 2)), 7) ^
        load<u32>(W_PTR + ((<usize>(i - 6)) << 2)),
    );
  }

  let A = load<u32>(statePtr);
  let B = load<u32>(statePtr + 4);
  let C = load<u32>(statePtr + 8);
  let D = load<u32>(statePtr + 12);
  let E = load<u32>(statePtr + 16);
  let F = load<u32>(statePtr + 20);
  let G = load<u32>(statePtr + 24);
  let H = load<u32>(statePtr + 28);

  // j = 0..15：T0 + ff0/gg0。W' 就地算，不再单独物化到 WP_PTR。
  //
  // j = 0..15: T0 with ff0/gg0. W' is computed inline instead of being materialised in
  // WP_PTR.
  let wPtr = W_PTR;
  let tjPtr = TJ_PTR;
  for (let j = 0; j < 16; j++) {
    const w = load<u32>(wPtr);
    const wp = w ^ load<u32>(wPtr + 16);
    const A12 = rotl(A, 12);
    const SS1 = rotl(A12 + E + load<u32>(tjPtr), 7);
    const SS2 = SS1 ^ A12;
    const TT1 = ff0(A, B, C) + D + SS2 + wp;
    const TT2 = gg0(E, F, G) + H + SS1 + w;
    D = C;
    C = rotl(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotl(F, 19);
    F = E;
    E = p0(TT2);
    wPtr += 4;
    tjPtr += 4;
  }
  // j = 16..63：T1 + ff1/gg1
  //
  // j = 16..63: T1 with ff1/gg1
  for (let j = 16; j < 64; j++) {
    const w = load<u32>(wPtr);
    const wp = w ^ load<u32>(wPtr + 16);
    const A12 = rotl(A, 12);
    const SS1 = rotl(A12 + E + load<u32>(tjPtr), 7);
    const SS2 = SS1 ^ A12;
    const TT1 = ff1(A, B, C) + D + SS2 + wp;
    const TT2 = gg1(E, F, G) + H + SS1 + w;
    D = C;
    C = rotl(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotl(F, 19);
    F = E;
    E = p0(TT2);
    wPtr += 4;
    tjPtr += 4;
  }

  store<u32>(statePtr, load<u32>(statePtr) ^ A);
  store<u32>(statePtr + 4, load<u32>(statePtr + 4) ^ B);
  store<u32>(statePtr + 8, load<u32>(statePtr + 8) ^ C);
  store<u32>(statePtr + 12, load<u32>(statePtr + 12) ^ D);
  store<u32>(statePtr + 16, load<u32>(statePtr + 16) ^ E);
  store<u32>(statePtr + 20, load<u32>(statePtr + 20) ^ F);
  store<u32>(statePtr + 24, load<u32>(statePtr + 24) ^ G);
  store<u32>(statePtr + 28, load<u32>(statePtr + 28) ^ H);
}

/**
 * 填充缓冲：模块级复用，避免每次 hash 都 `new StaticArray<u8>(totalLen)`。
 *
 * `heap.alloc` 返回**未清零**内存，正合需要 —— 只有 padding 区必须为零，
 * 前缀与输入区紧接着被 `memory.copy` 覆盖，长度区被显式写入。
 *
 * Padding buffer: reused at module level so that a `new StaticArray<u8>(totalLen)`
 * allocation is not needed on every hash call.
 *
 * `heap.alloc` returns **unzeroed** memory, which is exactly what is wanted here —
 * only the padding area must be zero; the prefix and input areas are overwritten by
 * `memory.copy` right after, and the length field is written explicitly.
 */
let PAD_CAP: usize = 0;
let PAD_PTR: usize = 0;

/**
 * 取/扩容填充缓冲，返回总长至少 totalLen 的缓冲区首地址。
 *
 * 返回值即模块级 `PAD_PTR`，未清零：调用方只会写入自己需要的那些字节。
 *
 * Return a padding buffer of at least totalLen bytes, growing it on demand.
 *
 * The address returned is the module-level `PAD_PTR` and the memory is not zeroed:
 * callers only write the bytes they actually need.
 */
function padBuf(totalLen: usize): usize {
  if (totalLen > PAD_CAP) {
    // 按需翻倍增长，避免每次加长都重分配。
    //
    // Grow by doubling on demand so that a longer input does not reallocate every time.
    PAD_CAP = totalLen < 4096 ? 4096 : totalLen << 1;
    PAD_PTR = heap.alloc(PAD_CAP);
  }
  return PAD_PTR;
}

/**
 * SM3 核心：对 `prefix ‖ input` 求摘要，写入 outPtr（32 字节，big-endian）。
 *
 * 两段输入是为了让 HMAC 的 `ipad ‖ msg` 直接参与填充，省掉一次整段拼接拷贝
 * （1KB 消息下每次 HMAC 能省约 1KB 的搬移）。普通调用把 prefix 传 0 即可。
 *
 * SM3 core: digest `prefix ‖ input` into outPtr (32 bytes, big-endian).
 *
 * The two-segment input lets HMAC padding cover `ipad ‖ msg` directly and skip one
 * full-length concatenation copy (about 1KB of copying saved per HMAC on a 1KB
 * message). Plain callers simply pass 0 for the prefix.
 */
function sm3Core(
  prefixPtr: usize,
  prefixLen: usize,
  inputPtr: usize,
  inputLen: usize,
  outPtr: usize,
): void {
  store<u32>(STATE_PTR, IV0);
  store<u32>(STATE_PTR + 4, IV1);
  store<u32>(STATE_PTR + 8, IV2);
  store<u32>(STATE_PTR + 12, IV3);
  store<u32>(STATE_PTR + 16, IV4);
  store<u32>(STATE_PTR + 20, IV5);
  store<u32>(STATE_PTR + 24, IV6);
  store<u32>(STATE_PTR + 28, IV7);

  // 填充：prefix ‖ input ‖ 0x80 ‖ 0…0 ‖ 64 位比特长度（大端），总长为 64 的倍数。
  //
  // Padding: prefix ‖ input ‖ 0x80 ‖ 0…0 ‖ 64-bit bit length (big-endian), with the total
  // length a multiple of 64.
  const msgLen: usize = prefixLen + inputLen;
  const lenWithPad: usize = msgLen + 9;
  const padding: usize = (64 - (lenWithPad & 63)) & 63;
  const totalLen: usize = msgLen + 1 + padding + 8;
  const buf = padBuf(totalLen);

  if (prefixLen > 0) memory.copy(buf, prefixPtr, prefixLen);
  if (inputLen > 0) memory.copy(buf + prefixLen, inputPtr, inputLen);
  store<u8>(buf + msgLen, 0x80);
  const zeroFrom: usize = msgLen + 1;
  const zeroTo: usize = totalLen - 8;
  if (zeroTo > zeroFrom) memory.fill(buf + zeroFrom, 0, zeroTo - zeroFrom);

  const bitLen: u64 = (<u64>msgLen) << 3;
  for (let i = 0; i < 8; i++) {
    store<u8>(buf + totalLen - 8 + <usize>i, <u8>((bitLen >> ((7 - i) * 8)) & 0xff));
  }

  for (let off: usize = 0; off < totalLen; off += 64) {
    compress(STATE_PTR, buf + off);
  }

  // 输出大端
  //
  // Write the output in big-endian order.
  store<u32>(outPtr, bswap<u32>(load<u32>(STATE_PTR)));
  store<u32>(outPtr + 4, bswap<u32>(load<u32>(STATE_PTR + 4)));
  store<u32>(outPtr + 8, bswap<u32>(load<u32>(STATE_PTR + 8)));
  store<u32>(outPtr + 12, bswap<u32>(load<u32>(STATE_PTR + 12)));
  store<u32>(outPtr + 16, bswap<u32>(load<u32>(STATE_PTR + 16)));
  store<u32>(outPtr + 20, bswap<u32>(load<u32>(STATE_PTR + 20)));
  store<u32>(outPtr + 24, bswap<u32>(load<u32>(STATE_PTR + 24)));
  store<u32>(outPtr + 28, bswap<u32>(load<u32>(STATE_PTR + 28)));
}

/**
 * 计算 SM3 摘要，写入 outPtr（32 字节，big-endian）。
 *
 * @param inputPtr 输入起始地址。
 * @param inputLen 输入字节数。
 * @param outPtr 输出 32 字节（4 字节对齐）。
 *
 * Compute the SM3 digest and write it to outPtr (32 bytes, big-endian).
 *
 * @param inputPtr Start address of the input.
 * @param inputLen Number of input bytes.
 * @param outPtr The 32-byte output (4-byte aligned).
 */
export function sm3HashInto(inputPtr: usize, inputLen: usize, outPtr: usize): void {
  sm3Core(0, 0, inputPtr, inputLen, outPtr);
}

/**
 * 两段输入（`prefix ‖ input`）的 SM3 摘要 —— 供 HMAC 内部使用。
 *
 * @param p1 前缀起始地址。
 * @param n1 前缀字节数。
 * @param p2 输入起始地址。
 * @param n2 输入字节数。
 * @param outPtr 输出 32 字节。
 *
 * SM3 digest over two segments (`prefix ‖ input`) — used internally by HMAC.
 *
 * @param p1 Start address of the prefix.
 * @param n1 Number of prefix bytes.
 * @param p2 Start address of the input.
 * @param n2 Number of input bytes.
 * @param outPtr The 32-byte output.
 */
export function sm3Hash2Into(p1: usize, n1: usize, p2: usize, n2: usize, outPtr: usize): void {
  sm3Core(p1, n1, p2, n2, outPtr);
}

// ---------------------------------------------------------------- HMAC-SM3

/**
 * K′（归一化后的密钥，≤64 字节、右侧补零）与 pad 工作块、内层摘要。HMAC 不重入。
 *
 * K′ (the normalised key, ≤64 bytes, right zero-padded), the pad work block and the
 * inner digest. HMAC is never reentrant.
 */
const HMAC_KEY_PTR: usize = heap.alloc(64);
const HMAC_PAD_PTR: usize = heap.alloc(64);
const HMAC_INNER_PTR: usize = heap.alloc(32);

/**
 * ipad / opad 的 4 字节批量常量（0x36 / 0x5c 各重复 4 次）。
 *
 * Four-byte batched ipad / opad constants (0x36 / 0x5c repeated four times).
 */
const IPAD32: u32 = 0x36363636;
const OPAD32: u32 = 0x5c5c5c5c;

/**
 * HMAC-SM3（RFC 2104），写入 outPtr（32 字节）。
 *
 * `K′ = key`（超过 64 字节则先取 SM3），右侧补零到 64 字节；
 * `HMAC = SM3((K′ ⊕ opad) ‖ SM3((K′ ⊕ ipad) ‖ msg))`。
 *
 * 原实现在 JS 层做拼接并调用两次 `hash()` —— 4 次跨边界、3 个临时 Uint8Array
 * 的分配与拷贝。这里一次调用到底，且 `ipad ‖ msg` 走两段输入接口直接参与填充。
 *
 * @param keyPtr 密钥起始地址。
 * @param keyLen 密钥字节数。
 * @param msgPtr 消息起始地址。
 * @param msgLen 消息字节数。
 * @param outPtr 输出 32 字节。
 *
 * HMAC-SM3 (RFC 2104), written to outPtr (32 bytes).
 *
 * `K′ = key` (hashed first when longer than 64 bytes), right zero-padded to 64 bytes;
 * `HMAC = SM3((K′ ⊕ opad) ‖ SM3((K′ ⊕ ipad) ‖ msg))`.
 *
 * The old implementation concatenated in JS and called `hash()` twice — 4 boundary
 * crossings plus the allocation and copy of 3 temporary Uint8Arrays. Here it is a
 * single call, and `ipad ‖ msg` goes straight into padding through the two-segment
 * input interface.
 *
 * @param keyPtr Start address of the key.
 * @param keyLen Number of key bytes.
 * @param msgPtr Start address of the message.
 * @param msgLen Number of message bytes.
 * @param outPtr The 32-byte output.
 */
export function sm3HmacInto(
  keyPtr: usize,
  keyLen: usize,
  msgPtr: usize,
  msgLen: usize,
  outPtr: usize,
): void {
  if (keyLen > 64) {
    sm3HashInto(keyPtr, keyLen, HMAC_KEY_PTR);
    memory.fill(HMAC_KEY_PTR + 32, 0, 32);
  } else {
    if (keyLen > 0) memory.copy(HMAC_KEY_PTR, keyPtr, keyLen);
    if (keyLen < 64) memory.fill(HMAC_KEY_PTR + keyLen, 0, 64 - keyLen);
  }

  // 内层：SM3((K′ ⊕ ipad) ‖ msg)
  //
  // Inner layer: SM3((K′ ⊕ ipad) ‖ msg)
  for (let i = 0; i < 64; i += 4) {
    store<u32>(HMAC_PAD_PTR + <usize>i, load<u32>(HMAC_KEY_PTR + <usize>i) ^ IPAD32);
  }
  sm3Hash2Into(HMAC_PAD_PTR, 64, msgPtr, msgLen, HMAC_INNER_PTR);

  // 外层：SM3((K′ ⊕ opad) ‖ inner)
  //
  // Outer layer: SM3((K′ ⊕ opad) ‖ inner)
  for (let i = 0; i < 64; i += 4) {
    store<u32>(HMAC_PAD_PTR + <usize>i, load<u32>(HMAC_KEY_PTR + <usize>i) ^ OPAD32);
  }
  sm3Hash2Into(HMAC_PAD_PTR, 64, HMAC_INNER_PTR, 32, outPtr);
}

/**
 * 计算 SM3 摘要并返回新的 32 字节 StaticArray。
 *
 * Hash with SM3 and return a fresh 32-byte StaticArray.
 */
export function sm3HashBytes(inputPtr: usize, inputLen: usize): StaticArray<u8> {
  const out = new StaticArray<u8>(32);
  sm3HashInto(inputPtr, inputLen, changetype<usize>(out));
  return out;
}

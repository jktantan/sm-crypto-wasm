// AssemblyScript SM4 分组密码核心（GB/T 32907-2016 = GM/T 0002-2014）。
//
// 由 `asc` 编译为 `dist/sm4/sm4.wasm`。
//
// 导出（供 TS 侧调用）：
//     alloc(n): usize
//     freeAll(): void
//     sm4EncryptECB / sm4DecryptECB
//     sm4Block(keyPtr, inPtr, outPtr, decrypt)
//     sm4CbcEncrypt / sm4CbcDecrypt
//     sm4CtrCrypt
//     sm4CfbEncrypt / sm4CfbDecrypt
//     sm4OfbCrypt
//     sm4GcmEncrypt / sm4GcmDecrypt（返回 0 表示 tag 校验通过）
//   其中 inLen 必须是 16 的倍数（块长 16 字节）。
//
// 加密/解密共用轮函数，解密使用逆序轮密钥（SM4 自反结构）。
//
// 参考：GB/T 32907-2016 §6（密钥扩展）、§7（加解密）。
//
// 内存约定：
// - keyPtr..keyPtr+16：128-bit 密钥（大端分组）。
// - inPtr..inPtr+inLen：明文/密文。
// - outPtr..outPtr+inLen：输出。
// - 输入输出可重叠（逐块就地）。
//
// AssemblyScript SM4 block-cipher core (GB/T 32907-2016 = GM/T 0002-2014).
//
// Compiled by `asc` to `dist/sm4/sm4.wasm`.
//
// Exports used by the TypeScript layer:
//     alloc(n): usize
//     freeAll(): void
//     sm4EncryptECB / sm4DecryptECB
//     sm4Block(keyPtr, inPtr, outPtr, decrypt)
//     sm4CbcEncrypt / sm4CbcDecrypt
//     sm4CtrCrypt
//     sm4CfbEncrypt / sm4CfbDecrypt
//     sm4OfbCrypt
//     sm4GcmEncrypt / sm4GcmDecrypt (returns 0 on tag success)
//   inLen must be a multiple of 16 (the block size).
//
// Encryption/decryption share the round function; decryption uses reversed
// round keys (SM4's structure makes this possible).
//
// Reference: GB/T 32907-2016 §6 (key schedule), §7 (encryption/decryption).
//
// Memory layout:
// - keyPtr..keyPtr+16: 128-bit key (big-endian block).
// - inPtr..inPtr+inLen: plaintext/ciphertext.
// - outPtr..outPtr+inLen: output.
// - Input and output may overlap (in-place per block).

// S 盒（GB/T 32907-2016 §6.2 表 1）。
// 用内存数据段裸指针：每块要做 128 次查表，`StaticArray` 索引会退化成
// `__get` runtime 调用（含边界检查），实测是每块成本的主要来源。
//
// SM4 S-box (GB/T 32907-2016 §6.2 table 1).
// Raw memory.data pointer: each block performs 128 lookups, and StaticArray
// indexing lowers to a __get runtime call with bounds checks, which dominates
// the per-block cost.
const SBOX: usize = memory.data<u8>([
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]);

// 系统参数 FK（GB/T 32907-2016 §6.3）。
//
// System parameter FK (GB/T 32907-2016 §6.3).
const FK: usize = memory.data<u32>([0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]);

// 固定参数 CK（GB/T 32907-2016 §6.4）。
//
// Fixed parameter CK (GB/T 32907-2016 §6.4).
const CK: usize = memory.data<u32>([
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
]);

// 用 Array 持住分配的缓冲，防止 GC 回收。
//
// Hold the allocated buffers in an Array so the GC keeps them alive.
const pinned: Array<StaticArray<u8>> = [];

/**
 * 从 AS 堆分配 n 字节，并把缓冲登记到 `pinned`，由 `freeAll` 统一释放。
 *
 * Allocate n bytes on the AS heap, register the buffer in `pinned`, and hand
 * it back to the collector through `freeAll`.
 */
export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

/**
 * 释放全部缓冲。
 *
 * Release every buffer handed out by `alloc`.
 */
export function freeAll(): void {
  pinned.length = 0;
}

/**
 * 轮密钥工作区（32 个 u32）——线性内存裸指针。
 * 密钥扩展与块加密都不重入（叶子），跨调用复用安全。
 *
 * Round-key workspace (32 × u32) addressed through a raw linear-memory
 * pointer. Key expansion and block encryption are both non-reentrant leaves,
 * so reusing it across calls is safe.
 */
const RK_PTR: usize = heap.alloc(32 * 4);

/**
 * 32 位循环左移。
 *
 * 32-bit circular left shift (rotate left).
 */
function rotl(x: u32, n: i32): u32 {
  return ((x << n) | (x >>> (32 - n))) & 0xffffffff;
}

/**
 * big-endian 读 4 字节（一次 load<u32> + bswap，替代 4 次字节 load 拼装）。
 *
 * Read 4 bytes big-endian: one load<u32> plus bswap instead of assembling
 * four byte loads.
 */
function readU32BE(p: usize): u32 {
  return bswap<u32>(load<u32>(p));
}

/**
 * big-endian 写 4 字节（一次 store<u32> + bswap）。
 *
 * Write 4 bytes big-endian: one store<u32> plus bswap.
 */
function writeU32BE(p: usize, v: u32): void {
  store<u32>(p, bswap<u32>(v));
}

/**
 * 非线性变换 tau：对 4 字节逐字节查 S 盒（裸指针 + load<u8>）。
 *
 * Non-linear transform tau: look each of the four bytes up in the S-box via
 * the raw pointer and load<u8>.
 */
function tau(x: u32): u32 {
  const b0 = <u32>load<u8>(SBOX + ((x >>> 24) & 0xff));
  const b1 = <u32>load<u8>(SBOX + ((x >>> 16) & 0xff));
  const b2 = <u32>load<u8>(SBOX + ((x >>> 8) & 0xff));
  const b3 = <u32>load<u8>(SBOX + (x & 0xff));
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff;
}

/**
 * 线性变换 L（加密轮用）。
 *
 * Linear transform L, used by the encryption rounds.
 */
function lLinear(b: u32): u32 {
  return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) & 0xffffffff;
}

/**
 * 线性变换 L'（密钥扩展用）。
 *
 * Linear transform L' used by the key schedule.
 */
function lLinearKey(b: u32): u32 {
  return (b ^ rotl(b, 13) ^ rotl(b, 23)) & 0xffffffff;
}

// ---------- T-table（S 盒 + L 变换合并） ----------
//
// 一轮是 X_{i+4} = X_i ^ L(τ(X_{i+1}^X_{i+2}^X_{i+3}^rk_i))。L 在 GF(2) 上是线性的，
// 而 τ 只是逐字节查盒，于是可以把它拆开预计算：
//   L(τ(t)) = T0[t>>>24] ^ T1[(t>>>16)&0xff] ^ T2[(t>>>8)&0xff] ^ T3[t&0xff]
//   Ti[j] = L(S[j] << (24-8i))
// 轮函数因此从"4 次逐字节查表 + 重组 + 4 次 rotl + 4 次 xor"降到 4 次 32-bit
// 查表 + 3 次 xor。表共 4 KB，仍在 L1 内；从 SBOX 在模块初始化时生成，不手写常量。
//
// 密钥扩展用另一套线性变换 L'，量级只有加密轮的 ~1/65（每次调用 32 轮 vs 每块 32 轮），
// 故保持原样，不额外占 4 KB 表。
//
// ---------- T-table (S-box combined with the L transform) ----------
//
// One round is X_{i+4} = X_i ^ L(tau(X_{i+1}^X_{i+2}^X_{i+3}^rk_i)). L is linear
// over GF(2) and tau is a byte-wise table lookup, so the pair splits into
// precomputed pieces:
//   L(tau(t)) = T0[t>>>24] ^ T1[(t>>>16)&0xff] ^ T2[(t>>>8)&0xff] ^ T3[t&0xff]
//   Ti[j] = L(S[j] << (24-8i))
// The round therefore drops from "4 byte lookups + repack + 4 rotl + 4 xor" to
// "4 32-bit table lookups + 3 xor". The tables total 4 KB and stay in L1; they
// are generated from SBOX at module init instead of being written out by hand.
//
// The key schedule uses the other linear transform L', whose volume is only
// ~1/65 of the encryption rounds (32 rounds per call vs 32 rounds per block), so
// it keeps the plain formulation and does not take another 4 KB of tables.
const T0: usize = heap.alloc(256 * 4);
const T1: usize = heap.alloc(256 * 4);
const T2: usize = heap.alloc(256 * 4);
const T3: usize = heap.alloc(256 * 4);
for (let i = 0; i < 256; i++) {
  const s = <u32>load<u8>(SBOX + i);
  const o = (<usize>i) << 2;
  store<u32>(T0 + o, lLinear(s << 24));
  store<u32>(T1 + o, lLinear(s << 16));
  store<u32>(T2 + o, lLinear(s << 8));
  store<u32>(T3 + o, lLinear(s));
}

/**
 * 合成变换 T = L∘τ：4 次 32-bit 查表 + 3 次 xor。
 *
 * Composite transform T = L∘tau: four 32-bit table lookups plus three xors.
 */
function tableT(t: u32): u32 {
  return (
    load<u32>(T0 + ((<usize>((t >>> 24) & 0xff)) << 2)) ^
    load<u32>(T1 + ((<usize>((t >>> 16) & 0xff)) << 2)) ^
    load<u32>(T2 + ((<usize>((t >>> 8) & 0xff)) << 2)) ^
    load<u32>(T3 + ((<usize>(t & 0xff)) << 2))
  );
}

/**
 * 合成变换 T'（密钥扩展）。
 *
 * Composite transform T' used by the key schedule.
 */
function tTransformKey(x: u32): u32 {
  return lLinearKey(tau(x));
}

/**
 * 密钥扩展：把 16 字节密钥展开成 32 个轮密钥。
 *
 * @param keyPtr 密钥首地址。
 * @param rk 输出轮密钥数组（32 个）。
 *
 * Key schedule: expand the 16-byte key into 32 round keys.
 *
 * @param keyPtr Address of the key.
 * @param rk Output array of 32 round keys.
 */
function keyExpansion(keyPtr: usize, rk: usize): void {
  // 4 个滚动状态量（寄存器），替代 K[36] 数组 —— 后者每轮都要分配并走
  // `__get`/`__set` runtime 调用。
  //
  // Four rolling register values instead of a K[36] array, which would need an
  // allocation and go through `__get`/`__set` runtime calls every round.
  let k0 = readU32BE(keyPtr) ^ load<u32>(FK);
  let k1 = readU32BE(keyPtr + 4) ^ load<u32>(FK + 4);
  let k2 = readU32BE(keyPtr + 8) ^ load<u32>(FK + 8);
  let k3 = readU32BE(keyPtr + 12) ^ load<u32>(FK + 12);
  for (let i = 0; i < 32; i++) {
    const t = (k0 ^ tTransformKey(k1 ^ k2 ^ k3 ^ load<u32>(CK + ((<usize>i) << 2)))) & 0xffffffff;
    k0 = k1;
    k1 = k2;
    k2 = k3;
    k3 = t;
    store<u32>(rk + ((<usize>i) << 2), t);
  }
}

/**
 * 单块加/解密（rk 决定方向：正序=加密，逆序=解密）。
 *
 * @param rk 32 个轮密钥。
 * @param inPtr 16 字节输入。
 * @param outPtr 16 字节输出。
 *
 * Encrypt or decrypt a single block; `rk` picks the direction (forward order
 * encrypts, reversed order decrypts).
 *
 * @param rk The 32 round keys.
 * @param inPtr 16-byte input.
 * @param outPtr 16-byte output.
 */
function cipherBlock(rk: usize, inPtr: usize, outPtr: usize): void {
  // 4 个滚动状态量（寄存器）：SM4 的标准写法，替代 X[36] 数组的分配与访问。
  //
  // Four rolling register values, the standard SM4 formulation, instead of
  // allocating and indexing an X[36] array.
  let x0 = readU32BE(inPtr);
  let x1 = readU32BE(inPtr + 4);
  let x2 = readU32BE(inPtr + 8);
  let x3 = readU32BE(inPtr + 12);
  for (let i = 0; i < 32; i++) {
    const t = (x1 ^ x2 ^ x3 ^ load<u32>(rk + ((<usize>i) << 2))) & 0xffffffff;
    // L(τ(t)) 由 4 张预计算表合成，省掉逐字节查盒后的重组与单独的 L 变换。
    //
    // L(tau(t)) comes from the four precomputed tables, skipping the repack and
    // the separate L transform after the byte-wise S-box lookups.
    const tt = tableT(t);
    const n = (x0 ^ tt) & 0xffffffff;
    x0 = x1;
    x1 = x2;
    x2 = x3;
    x3 = n;
  }
  // 输出反序：X35..X32 即最后的 x3..x0。
  //
  // Output in reverse word order: X35..X32 are the final x3..x0.
  writeU32BE(outPtr, x3);
  writeU32BE(outPtr + 4, x2);
  writeU32BE(outPtr + 8, x1);
  writeU32BE(outPtr + 12, x0);
}

/**
 * 4 块标量交错：不依赖 SIMD，用 T-table 交错 4 个独立块，靠乱序执行隐藏
 * L1 查表延迟。每块的查表次数与 `cipherBlock` 相同，但省掉了 `cipher4` 的
 * 4x4 transpose 与 extract/replace 开销，实测比 `cipher4` 快。
 *
 * 服务 ECB 与 CTR 的 64~127 字节尾段；主路径是 `cipher8s`。
 *
 * Four-block scalar interleave: no SIMD, but four independent blocks are
 * interleaved over the T-tables so out-of-order execution hides the L1 lookup
 * latency. Each block performs the same number of lookups as `cipherBlock`,
 * while the 4x4 transpose and extract/replace overhead of `cipher4` is gone;
 * measured faster than `cipher4`.
 *
 * Serves the 64..127-byte tails of ECB and CTR; the main path is `cipher8s`.
 */
function cipher4s(rk: usize, inPtr: usize, outPtr: usize): void {
  let a0 = readU32BE(inPtr);
  let a1 = readU32BE(inPtr + 4);
  let a2 = readU32BE(inPtr + 8);
  let a3 = readU32BE(inPtr + 12);
  let b0 = readU32BE(inPtr + 16);
  let b1 = readU32BE(inPtr + 20);
  let b2 = readU32BE(inPtr + 24);
  let b3 = readU32BE(inPtr + 28);
  let c0 = readU32BE(inPtr + 32);
  let c1 = readU32BE(inPtr + 36);
  let c2 = readU32BE(inPtr + 40);
  let c3 = readU32BE(inPtr + 44);
  let d0 = readU32BE(inPtr + 48);
  let d1 = readU32BE(inPtr + 52);
  let d2 = readU32BE(inPtr + 56);
  let d3 = readU32BE(inPtr + 60);
  for (let i = 0; i < 32; i++) {
    const rkv = load<u32>(rk + ((<usize>i) << 2));
    const na = (a0 ^ tableT(a1 ^ a2 ^ a3 ^ rkv)) & 0xffffffff;
    const nb = (b0 ^ tableT(b1 ^ b2 ^ b3 ^ rkv)) & 0xffffffff;
    const nc = (c0 ^ tableT(c1 ^ c2 ^ c3 ^ rkv)) & 0xffffffff;
    const nd = (d0 ^ tableT(d1 ^ d2 ^ d3 ^ rkv)) & 0xffffffff;
    a0 = a1;
    a1 = a2;
    a2 = a3;
    a3 = na;
    b0 = b1;
    b1 = b2;
    b2 = b3;
    b3 = nb;
    c0 = c1;
    c1 = c2;
    c2 = c3;
    c3 = nc;
    d0 = d1;
    d1 = d2;
    d2 = d3;
    d3 = nd;
  }
  writeU32BE(outPtr, a3);
  writeU32BE(outPtr + 4, a2);
  writeU32BE(outPtr + 8, a1);
  writeU32BE(outPtr + 12, a0);
  writeU32BE(outPtr + 16, b3);
  writeU32BE(outPtr + 20, b2);
  writeU32BE(outPtr + 24, b1);
  writeU32BE(outPtr + 28, b0);
  writeU32BE(outPtr + 32, c3);
  writeU32BE(outPtr + 36, c2);
  writeU32BE(outPtr + 40, c1);
  writeU32BE(outPtr + 44, c0);
  writeU32BE(outPtr + 48, d3);
  writeU32BE(outPtr + 52, d2);
  writeU32BE(outPtr + 56, d1);
  writeU32BE(outPtr + 60, d0);
}

/**
 * 8 块标量交错：把 `cipher4s` 的交错度再翻倍，用更多独立依赖链填满
 * 流水线。每块每轮的查表次数与标量路径相同（4 次）。
 *
 * Eight-block scalar interleave: doubles the interleave depth of `cipher4s` so
 * more independent dependency chains keep the pipeline busy. Each block still
 * performs the same four lookups per round as the scalar path.
 */
function cipher8s(rk: usize, inPtr: usize, outPtr: usize): void {
  let a0 = readU32BE(inPtr + 0);
  let a1 = readU32BE(inPtr + 4);
  let a2 = readU32BE(inPtr + 8);
  let a3 = readU32BE(inPtr + 12);
  let b0 = readU32BE(inPtr + 16);
  let b1 = readU32BE(inPtr + 20);
  let b2 = readU32BE(inPtr + 24);
  let b3 = readU32BE(inPtr + 28);
  let c0 = readU32BE(inPtr + 32);
  let c1 = readU32BE(inPtr + 36);
  let c2 = readU32BE(inPtr + 40);
  let c3 = readU32BE(inPtr + 44);
  let d0 = readU32BE(inPtr + 48);
  let d1 = readU32BE(inPtr + 52);
  let d2 = readU32BE(inPtr + 56);
  let d3 = readU32BE(inPtr + 60);
  let e0 = readU32BE(inPtr + 64);
  let e1 = readU32BE(inPtr + 68);
  let e2 = readU32BE(inPtr + 72);
  let e3 = readU32BE(inPtr + 76);
  let f0 = readU32BE(inPtr + 80);
  let f1 = readU32BE(inPtr + 84);
  let f2 = readU32BE(inPtr + 88);
  let f3 = readU32BE(inPtr + 92);
  let g0 = readU32BE(inPtr + 96);
  let g1 = readU32BE(inPtr + 100);
  let g2 = readU32BE(inPtr + 104);
  let g3 = readU32BE(inPtr + 108);
  let h0 = readU32BE(inPtr + 112);
  let h1 = readU32BE(inPtr + 116);
  let h2 = readU32BE(inPtr + 120);
  let h3 = readU32BE(inPtr + 124);
  for (let i = 0; i < 32; i++) {
    const rkv = load<u32>(rk + ((<usize>i) << 2));
    const na = (a0 ^ tableT(a1 ^ a2 ^ a3 ^ rkv)) & 0xffffffff;
    const nb = (b0 ^ tableT(b1 ^ b2 ^ b3 ^ rkv)) & 0xffffffff;
    const nc = (c0 ^ tableT(c1 ^ c2 ^ c3 ^ rkv)) & 0xffffffff;
    const nd = (d0 ^ tableT(d1 ^ d2 ^ d3 ^ rkv)) & 0xffffffff;
    const ne = (e0 ^ tableT(e1 ^ e2 ^ e3 ^ rkv)) & 0xffffffff;
    const nf = (f0 ^ tableT(f1 ^ f2 ^ f3 ^ rkv)) & 0xffffffff;
    const ng = (g0 ^ tableT(g1 ^ g2 ^ g3 ^ rkv)) & 0xffffffff;
    const nh = (h0 ^ tableT(h1 ^ h2 ^ h3 ^ rkv)) & 0xffffffff;
    a0 = a1;
    a1 = a2;
    a2 = a3;
    a3 = na;
    b0 = b1;
    b1 = b2;
    b2 = b3;
    b3 = nb;
    c0 = c1;
    c1 = c2;
    c2 = c3;
    c3 = nc;
    d0 = d1;
    d1 = d2;
    d2 = d3;
    d3 = nd;
    e0 = e1;
    e1 = e2;
    e2 = e3;
    e3 = ne;
    f0 = f1;
    f1 = f2;
    f2 = f3;
    f3 = nf;
    g0 = g1;
    g1 = g2;
    g2 = g3;
    g3 = ng;
    h0 = h1;
    h1 = h2;
    h2 = h3;
    h3 = nh;
  }
  writeU32BE(outPtr + 0, a3);
  writeU32BE(outPtr + 4, a2);
  writeU32BE(outPtr + 8, a1);
  writeU32BE(outPtr + 12, a0);
  writeU32BE(outPtr + 16, b3);
  writeU32BE(outPtr + 20, b2);
  writeU32BE(outPtr + 24, b1);
  writeU32BE(outPtr + 28, b0);
  writeU32BE(outPtr + 32, c3);
  writeU32BE(outPtr + 36, c2);
  writeU32BE(outPtr + 40, c1);
  writeU32BE(outPtr + 44, c0);
  writeU32BE(outPtr + 48, d3);
  writeU32BE(outPtr + 52, d2);
  writeU32BE(outPtr + 56, d1);
  writeU32BE(outPtr + 60, d0);
  writeU32BE(outPtr + 64, e3);
  writeU32BE(outPtr + 68, e2);
  writeU32BE(outPtr + 72, e1);
  writeU32BE(outPtr + 76, e0);
  writeU32BE(outPtr + 80, f3);
  writeU32BE(outPtr + 84, f2);
  writeU32BE(outPtr + 88, f1);
  writeU32BE(outPtr + 92, f0);
  writeU32BE(outPtr + 96, g3);
  writeU32BE(outPtr + 100, g2);
  writeU32BE(outPtr + 104, g1);
  writeU32BE(outPtr + 108, g0);
  writeU32BE(outPtr + 112, h3);
  writeU32BE(outPtr + 116, h2);
  writeU32BE(outPtr + 120, h1);
  writeU32BE(outPtr + 124, h0);
}

/**
 * 反转轮密钥（用于解密）。
 *
 * Reverse the round keys in place; used for decryption.
 */
function reverseRk(rk: usize): void {
  for (let i = 0; i < 16; i++) {
    const j = 31 - i;
    const a = load<u32>(rk + ((<usize>i) << 2));
    const b = load<u32>(rk + ((<usize>j) << 2));
    store<u32>(rk + ((<usize>i) << 2), b);
    store<u32>(rk + ((<usize>j) << 2), a);
  }
}

/**
 * SM4 ECB 加密（inLen 必须是 16 的倍数）。
 *
 * 主路径每轮处理 4 块（`cipher4s`），不足 64 字节的尾部逐块走 `cipherBlock`。
 *
 * SM4-ECB encryption; inLen must be a multiple of 16.
 *
 * The main path processes 4 blocks at a time (`cipher4s`); any tail shorter
 * than 64 bytes is done block by block with `cipherBlock`.
 */
export function sm4EncryptECB(keyPtr: usize, inPtr: usize, inLen: usize, outPtr: usize): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  let off: usize = 0;
  while (off + 64 <= inLen) {
    cipher4s(rk, inPtr + off, outPtr + off);
    off += 64;
  }
  while (off < inLen) {
    cipherBlock(rk, inPtr + off, outPtr + off);
    off += 16;
  }
}

/**
 * SM4 ECB 解密（inLen 必须是 16 的倍数）。
 *
 * 与加密同一套 T-table 轮函数，仅把轮密钥逆序后再逐块调用。
 *
 * SM4-ECB decryption; inLen must be a multiple of 16.
 *
 * Uses the same T-table round function as encryption; only the round keys are
 * reversed before the per-block calls.
 */
export function sm4DecryptECB(keyPtr: usize, inPtr: usize, inLen: usize, outPtr: usize): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  reverseRk(rk);
  let off: usize = 0;
  while (off + 64 <= inLen) {
    cipher4s(rk, inPtr + off, outPtr + off);
    off += 64;
  }
  while (off < inLen) {
    cipherBlock(rk, inPtr + off, outPtr + off);
    off += 16;
  }
}

/**
 * 单块加密 / 解密，暴露给 TS 层做 CBC/CTR 等模式的块级调用。
 *
 * @param keyPtr 16 字节密钥。
 * @param inPtr 16 字节输入。
 * @param outPtr 16 字节输出。
 * @param decrypt 0=加密，1=解密。
 *
 * Single-block encrypt/decrypt, exposed so the TypeScript layer can drive
 * block-level modes such as CBC/CTR.
 *
 * @param keyPtr 16-byte key.
 * @param inPtr 16-byte input.
 * @param outPtr 16-byte output.
 * @param decrypt 0 = encrypt, non-zero = decrypt.
 */
export function sm4Block(keyPtr: usize, inPtr: usize, outPtr: usize, decrypt: i32): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  if (decrypt !== 0) reverseRk(rk);
  cipherBlock(rk, inPtr, outPtr);
}

// ---------- 批量模式（CBC / CTR） ----------
//
// 把整段循环放进 wasm。原先 TS 侧逐块调 `sm4Block`，每块要付一次 JS↔WASM
// 边界 + `withBuffers` 的 alloc / mem.set / slice（实测 ~0.5µs/块，1KB 即
// 浪费 ~33µs）。这里一次调用处理整段，模式循环全在 wasm 内完成。
//
// ---------- Batch modes (CBC / CTR) ----------
//
// The whole-buffer loop lives inside wasm. The TypeScript side used to call
// `sm4Block` per block, paying one JS↔WASM boundary plus the alloc / mem.set /
// slice of `withBuffers` for every block (~0.5µs per block, i.e. ~33µs wasted
// on 1 KB). Here a single call handles the whole buffer and the mode loop runs
// entirely inside wasm.

/**
 * 模式工作区（各 16 字节）：CBC 链值 / 异或暂存 / CTR 计数器 / CTR 密钥流。
 *
 * Per-mode workspaces, 16 bytes each: CBC chaining value, XOR scratch, CTR
 * counter block, CTR keystream.
 */
const CBC_PREV: usize = heap.alloc(16);
const CBC_TMP: usize = heap.alloc(16);
const CTR_CB: usize = heap.alloc(16);
const CTR_KS: usize = heap.alloc(16);

/**
 * 16 字节按 u32 异或：dst = a ^ b（三者均 4 字节对齐）。
 *
 * XOR 16 bytes word-wise: dst = a ^ b (all three pointers 4-byte aligned).
 */
function xor16u32(dst: usize, a: usize, b: usize): void {
  for (let i = 0; i < 16; i += 4) {
    store<u32>(dst + i, load<u32>(a + i) ^ load<u32>(b + i));
  }
}

/**
 * SM4-CBC 加密（inLen 必须是 16 的倍数；padding 由调用方处理）。
 *
 * C_i = E(P_i ^ C_{i-1})，C_{-1} = IV；链值存 CBC_PREV，异或暂存存 CBC_TMP。
 *
 * SM4-CBC encryption; inLen must be a multiple of 16 and padding is the
 * caller's job.
 *
 * C_i = E(P_i ^ C_{i-1}) with C_{-1} = IV; the chaining value lives in
 * CBC_PREV and the XOR scratch in CBC_TMP.
 */
export function sm4CbcEncrypt(
  keyPtr: usize,
  ivPtr: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  memory.copy(CBC_PREV, ivPtr, 16);
  for (let off: usize = 0; off < inLen; off += 16) {
    xor16u32(CBC_TMP, inPtr + off, CBC_PREV);
    cipherBlock(rk, CBC_TMP, outPtr + off);
    memory.copy(CBC_PREV, outPtr + off, 16);
  }
}

/**
 * SM4-CBC 解密（inLen 必须是 16 的倍数）。
 *
 * P_i = D(C_i) ^ C_{i-1}；因为输入输出可重叠，必须先把密文块拷到 CBC_TMP 再就地解密。
 *
 * SM4-CBC decryption; inLen must be a multiple of 16.
 *
 * P_i = D(C_i) ^ C_{i-1}. Since input and output may overlap, the ciphertext
 * block is copied to CBC_TMP before it is decrypted in place.
 */
export function sm4CbcDecrypt(
  keyPtr: usize,
  ivPtr: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  reverseRk(rk);
  memory.copy(CBC_PREV, ivPtr, 16);
  for (let off: usize = 0; off < inLen; off += 16) {
    memory.copy(CBC_TMP, inPtr + off, 16); // 保留本块密文，作为下一块的链值
    // Keep this ciphertext block: it is the chaining value for the next one.
    cipherBlock(rk, inPtr + off, outPtr + off);
    xor16u32(outPtr + off, outPtr + off, CBC_PREV);
    memory.copy(CBC_PREV, CBC_TMP, 16);
  }
}

/**
 * SM4-CTR 加解密（自反；inLen 任意长度）。
 *
 * 每 16 字节用计数器块加密得到密钥流后异或；按 8 块 / 4 块 / 1 块三档降级，
 * 尾块不足 16 字节时只取前 `rest` 字节密钥流。
 *
 * SM4-CTR encryption/decryption (self-inverse; inLen may be any length).
 *
 * Every 16 bytes are XORed with a keystream block obtained by encrypting the
 * counter block, stepping down through 8-block / 4-block / 1-block paths; a
 * short tail uses only the first `rest` keystream bytes.
 */
export function sm4CtrCrypt(
  keyPtr: usize,
  ivPtr: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  memory.copy(CTR_CB, ivPtr, 16);
  let off: usize = 0;
  while (off < inLen) {
    const rest = inLen - off;
    if (rest >= 128) {
      // 一次 8 块：生成 8 个连续计数器块 → 8-way 加密成密钥流 → 与数据异或。
      //
      // Eight blocks at once: build 8 consecutive counter blocks, encrypt them
      // 8-way into the keystream, then XOR with the data.
      keystream8(rk, CTR_CB);
      for (let i: usize = 0; i < 128; i++) {
        store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(BLK8_KS + i));
      }
      off += 128;
    } else if (rest >= 64) {
      // 一次 4 块：生成 4 个连续计数器块 → 4 块交错加密成密钥流 → 与数据异或。
      //
      // Four blocks at once: build 4 consecutive counter blocks, encrypt them
      // with the 4-way interleaved path into the keystream, then XOR with the
      // data.
      keystream4(rk, CTR_CB);
      for (let i: usize = 0; i < 64; i++) {
        store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(BLK4_KS + i));
      }
      off += 64;
    } else {
      cipherBlock(rk, CTR_CB, CTR_KS);
      const take: usize = rest < 16 ? rest : 16;
      for (let i: usize = 0; i < take; i++) {
        store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(CTR_KS + i));
      }
      inc32(CTR_CB);
      off += 16;
    }
  }
}

// ---------- CFB / OFB 批量导出 ----------
//
// 这两个模式原先只在 TS 侧逐块调用 `sm4Block`，每 16 字节一次 wasm 跨界
// （alloc + 写入 + 调用 + slice），1 KB 要 64 次 —— 实测比纯 JS 参考实现还慢
// 1.4~1.5×。这里照 CBC/CTR 的做法把整缓冲交给 wasm，跨界降到 1 次。
//
// ---------- Batch exports for CFB / OFB ----------
//
// Both modes used to be driven from the TypeScript side by calling `sm4Block`
// once per 16 bytes, paying a wasm crossing (alloc + write + call + slice) 64
// times per KB, which measured 1.4~1.5× slower than a plain JS reference
// implementation. As with CBC/CTR, the whole buffer is handed to wasm here and
// the crossing count drops to one.

/**
 * CFB128 的反馈寄存器与密钥流暂存。
 *
 * CFB128 feedback register and keystream scratch.
 */
const CFB_FB: usize = heap.alloc(16);
const CFB_KS: usize = heap.alloc(16);

/**
 * OFB 的状态与密钥流暂存。
 *
 * OFB state and keystream scratch.
 */
const OFB_FB: usize = heap.alloc(16);
const OFB_KS: usize = heap.alloc(16);

/**
 * SM4-CFB128 加密（inLen 任意长度）。
 *
 * 反馈取**密文**段：不足 16 字节的尾块按既有实现语义补 0 再作反馈，
 * 保证与 TS 侧原逐块实现逐字节一致。
 *
 * SM4-CFB128 encryption; inLen may be any length.
 *
 * The feedback is the **ciphertext** segment: a short tail block is zero-padded
 * before being fed back, matching the semantics of the previous implementation
 * so the output stays byte-for-byte identical to the old per-block TypeScript
 * path.
 */
export function sm4CfbEncrypt(
  keyPtr: usize,
  ivPtr: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  memory.copy(CFB_FB, ivPtr, 16);
  let off: usize = 0;
  while (off < inLen) {
    cipherBlock(rk, CFB_FB, CFB_KS);
    const rest = inLen - off;
    const take: usize = rest < 16 ? rest : 16;
    for (let i: usize = 0; i < take; i++) {
      const c: u8 = load<u8>(inPtr + off + i) ^ load<u8>(CFB_KS + i);
      store<u8>(outPtr + off + i, c);
      store<u8>(CFB_FB + i, c); // 反馈 = 密文段
      // Feedback = the ciphertext segment.
    }
    for (let i: usize = take; i < 16; i++) store<u8>(CFB_FB + i, 0);
    off += 16;
  }
}

/**
 * SM4-CFB128 解密（反馈同样取密文，故先读入再异或）。
 *
 * SM4-CFB128 decryption; the feedback is the ciphertext again, so the byte is
 * read before the XOR writes the output buffer.
 */
export function sm4CfbDecrypt(
  keyPtr: usize,
  ivPtr: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  memory.copy(CFB_FB, ivPtr, 16);
  let off: usize = 0;
  while (off < inLen) {
    cipherBlock(rk, CFB_FB, CFB_KS);
    const rest = inLen - off;
    const take: usize = rest < 16 ? rest : 16;
    for (let i: usize = 0; i < take; i++) {
      const c: u8 = load<u8>(inPtr + off + i);
      store<u8>(outPtr + off + i, c ^ load<u8>(CFB_KS + i));
      store<u8>(CFB_FB + i, c); // 反馈 = 密文段
      // Feedback = the ciphertext segment.
    }
    for (let i: usize = take; i < 16; i++) store<u8>(CFB_FB + i, 0);
    off += 16;
  }
}

/**
 * SM4-OFB 加解密（自反）：状态 = E(状态)，密钥流与数据异或。
 *
 * SM4-OFB encryption/decryption (self-inverse): the state becomes E(state) and
 * the resulting keystream is XORed with the data.
 */
export function sm4OfbCrypt(
  keyPtr: usize,
  ivPtr: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  memory.copy(OFB_FB, ivPtr, 16);
  let off: usize = 0;
  while (off < inLen) {
    cipherBlock(rk, OFB_FB, OFB_KS);
    memory.copy(OFB_FB, OFB_KS, 16); // 新状态 = E(旧状态)
    // New state = E(old state).
    const rest = inLen - off;
    const take: usize = rest < 16 ? rest : 16;
    for (let i: usize = 0; i < take; i++) {
      store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(OFB_KS + i));
    }
    off += 16;
  }
}

// ---------- GCM（NIST SP 800-38D 的 AEAD，套在 SM4 上） ----------
//
// GCM = CTR（计数器只递增最后 32 位）+ GHASH（GF(2^128) 上的多项式哈希）。
// 参考 NIST SP 800-38D §6.3（GF 乘法 Algorithm 1）、§6.4（GHASH）、§6.5（GCTR）、
// §7.1（GCM 加解密）。GmSSL/OpenSSL 的 SM4-GCM 遵循同一规范，产物可互操作。
//
// ---------- GCM (the AEAD from NIST SP 800-38D, instantiated on SM4) ----------
//
// GCM = CTR (only the last 32 bits of the counter are incremented) + GHASH
// (a polynomial hash over GF(2^128)).
// Following NIST SP 800-38D §6.3 (GF multiplication, Algorithm 1), §6.4
// (GHASH), §6.5 (GCTR) and §7.1 (GCM encryption/decryption). SM4-GCM in
// GmSSL/OpenSSL follows the same spec, so the outputs interoperate.

/**
 * GF(2^128) 乘法结果暂存（hi=高 64 位，lo=低 64 位）。
 *
 * Scratch for the GF(2^128) multiplication result (hi = high 64 bits,
 * lo = low 64 bits).
 */
const gmulOut = new StaticArray<u64>(2);

/**
 * GHASH 累积状态（128-bit，hi/lo）。
 *
 * Accumulated GHASH state (128-bit, hi/lo).
 */
let ghashHi: u64 = 0;
let ghashLo: u64 = 0;

/**
 * big-endian 读 8 字节到 u64（不用 load<u64> 以规避对齐要求）。
 *
 * Read 8 bytes big-endian into a u64 (load<u64> is avoided so that no
 * alignment requirement applies).
 */
function readU64BE(p: usize): u64 {
  let v: u64 = 0;
  for (let i = 0; i < 8; i++) {
    v = (v << 8) | <u64>load<u8>(p + i);
  }
  return v;
}

/**
 * big-endian 写 u64 到 8 字节。
 *
 * Write a u64 big-endian into 8 bytes.
 */
function writeU64BE(p: usize, v: u64): void {
  for (let i = 0; i < 8; i++) {
    store<u8>(p + i, <u8>(v >>> ((7 - i) * 8)));
  }
}

/**
 * GF(2^128) 乘法，GCM 的 bit-reversed 约定（NIST SP 800-38D Algorithm 1）。
 *
 * 结果写入 `gmulOut`。
 *
 * GF(2^128) multiplication with GCM's bit-reversed convention (NIST SP 800-38D
 * Algorithm 1).
 *
 * The result is written to `gmulOut`.
 */
function gfMul(xhi: u64, xlo: u64, yhi: u64, ylo: u64): void {
  // R = 11100001 || 0^120。
  const R: u64 = (<u64>0xe1) << 56;
  let zhi: u64 = 0;
  let zlo: u64 = 0;
  let vhi: u64 = yhi;
  let vlo: u64 = ylo;
  for (let i = 0; i < 128; i++) {
    // x_i：X 的第 i 位（x_0 是最高位）。
    //
    // x_i: bit i of X (x_0 is the most significant bit).
    const bit: u64 = i < 64 ? (xhi >>> (63 - i)) & 1 : (xlo >>> (127 - i)) & 1;
    if (bit !== 0) {
      zhi ^= vhi;
      zlo ^= vlo;
    }
    const lsb: u64 = vlo & 1;
    vlo = (vlo >>> 1) | (vhi << 63);
    vhi = vhi >>> 1;
    if (lsb !== 0) vhi ^= R;
  }
  gmulOut[0] = zhi;
  gmulOut[1] = zlo;
}

/**
 * 把一段数据（不足 16 字节在尾部补零）异或进 GHASH 状态，再乘 H。
 *
 * XOR a chunk of data into the GHASH state (a short chunk is zero-padded at the
 * tail) and multiply by H.
 */
function ghashBlock(hhi: u64, hlo: u64, p: usize, len: usize): void {
  let bhi: u64 = 0;
  let blo: u64 = 0;
  for (let i: usize = 0; i < len; i++) {
    const b = <u64>load<u8>(p + i);
    // 块是大端：数据在**高位**，逐字节左移到对应位置（不足 16 字节时尾部留零）。
    //
    // The block is big-endian, so the data sits in the high bits and each byte is
    // shifted into place (a short chunk leaves zeros at the tail).
    if (i < 8) {
      bhi |= b << ((7 - i) * 8);
    } else {
      blo |= b << ((15 - i) * 8);
    }
  }
  ghashHi ^= bhi;
  ghashLo ^= blo;
  gfMul(ghashHi, ghashLo, hhi, hlo);
  ghashHi = gmulOut[0];
  ghashLo = gmulOut[1];
}

/**
 * 吸收任意长度数据到 GHASH 状态，逐 16 字节补零分块。
 *
 * Absorb arbitrary-length data into the GHASH state in zero-padded 16-byte
 * blocks.
 */
function ghashData(hhi: u64, hlo: u64, p: usize, len: usize): void {
  let off: usize = 0;
  while (off < len) {
    const rest = len - off;
    ghashBlock(hhi, hlo, p + off, rest < 16 ? rest : 16);
    off += 16;
  }
}

/**
 * 计算 S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)，
 * 128-bit 结果写到 outPtr（NIST SP 800-38D §6.4）。
 *
 * Compute S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64) and
 * write the 128-bit result to outPtr (NIST SP 800-38D §6.4).
 */
function ghashAadCt(
  hhi: u64,
  hlo: u64,
  aadPtr: usize,
  aadLen: usize,
  ctPtr: usize,
  ctLen: usize,
  outPtr: usize,
): void {
  ghashHi = 0;
  ghashLo = 0;
  ghashData(hhi, hlo, aadPtr, aadLen);
  ghashData(hhi, hlo, ctPtr, ctLen);
  ghashHi ^= (<u64>aadLen) << 3;
  ghashLo ^= (<u64>ctLen) << 3;
  gfMul(ghashHi, ghashLo, hhi, hlo);
  writeU64BE(outPtr, gmulOut[0]);
  writeU64BE(outPtr + 8, gmulOut[1]);
}

/**
 * 计算初始计数器块 J0（NIST SP 800-38D §7.1 Step 2），写到 outPtr 的 16 字节。
 *
 * - IV 为 96 位：J0 = IV || 0^31 || 1；
 * - 其它长度：J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)。
 *
 * Compute the initial counter block J0 (NIST SP 800-38D §7.1 Step 2) into the
 * 16 bytes at outPtr.
 *
 * - 96-bit IV: J0 = IV || 0^31 || 1;
 * - any other length: J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64).
 */
function computeJ0(hhi: u64, hlo: u64, ivPtr: usize, ivLen: usize, outPtr: usize): void {
  if (ivLen === 12) {
    for (let i = 0; i < 12; i++) store<u8>(outPtr + i, load<u8>(ivPtr + i));
    store<u8>(outPtr + 12, 0);
    store<u8>(outPtr + 13, 0);
    store<u8>(outPtr + 14, 0);
    store<u8>(outPtr + 15, 1);
    return;
  }
  ghashHi = 0;
  ghashLo = 0;
  ghashData(hhi, hlo, ivPtr, ivLen);
  // 追加长度块：高 64 位为零，低 64 位是 len(IV) 的比特数。
  //
  // Append the length block: the high 64 bits are zero and the low 64 bits hold
  // the bit length of the IV.
  ghashLo ^= (<u64>ivLen) << 3;
  gfMul(ghashHi, ghashLo, hhi, hlo);
  writeU64BE(outPtr, gmulOut[0]);
  writeU64BE(outPtr + 8, gmulOut[1]);
}

/**
 * inc32：只把 16 字节块的最后 4 字节按大端加一（GCM 计数器规则）。
 *
 * inc32: increment only the last 4 bytes of the 16-byte block, read and written
 * big-endian, as the GCM counter rule requires.
 */
function inc32(p: usize): void {
  let c: u32 = 0;
  for (let i = 12; i < 16; i++) {
    c = (c << 8) | <u32>load<u8>(p + i);
  }
  c = (c + 1) & 0xffffffff;
  store<u8>(p + 12, <u8>(c >>> 24));
  store<u8>(p + 13, <u8>(c >>> 16));
  store<u8>(p + 14, <u8>(c >>> 8));
  store<u8>(p + 15, <u8>c);
}

/**
 * 复制 16 字节并 inc32，用于得到 GCTR 的初始计数器块 inc32(J0)。
 *
 * Copy 16 bytes and apply inc32, yielding GCTR's initial counter block
 * inc32(J0).
 */
function inc32Copy(srcPtr: usize, dstPtr: usize): void {
  for (let i = 0; i < 16; i++) store<u8>(dstPtr + i, load<u8>(srcPtr + i));
  inc32(dstPtr);
}

/**
 * GCTR：以 icb 为初始计数器块对数据做流式加/解密（NIST SP 800-38D §6.5）。
 * 输入输出可重叠。
 *
 * GCTR: run the data through the stream in/out transform starting from the
 * initial counter block icb (NIST SP 800-38D §6.5). Input and output may
 * overlap.
 */
function gctr(rk: usize, icbPtr: usize, inPtr: usize, inLen: usize, outPtr: usize): void {
  if (inLen === 0) return;
  const cbPtr = GCTR_CB;
  memory.copy(cbPtr, icbPtr, 16);
  let off: usize = 0;
  while (off < inLen) {
    const rest = inLen - off;
    if (rest >= 128) {
      // 一次 8 块：8 个连续计数器块 → 8-way 加密成密钥流 → 与数据异或
      // （密钥流先落 BLK8_KS，故 outPtr 与 inPtr 重叠也安全）。
      //
      // Eight blocks at once: 8 consecutive counter blocks are encrypted 8-way
      // into the keystream and XORed with the data (the keystream is materialised
      // in BLK8_KS first, so overlapping outPtr and inPtr is safe).
      keystream8(rk, cbPtr);
      for (let i: usize = 0; i < 128; i++) {
        store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(BLK8_KS + i));
      }
      off += 128;
    } else if (rest >= 64) {
      // 一次 4 块：4 个连续计数器块 → 4 块交错加密成密钥流 → 与数据异或
      // （密钥流先落 BLK4_KS，故 outPtr 与 inPtr 重叠也安全）。
      //
      // Four blocks at once: 4 consecutive counter blocks are encrypted with the
      // interleaved path into the keystream and XORed with the data (the
      // keystream is materialised in BLK4_KS first, so overlapping outPtr and
      // inPtr is safe).
      keystream4(rk, cbPtr);
      for (let i: usize = 0; i < 64; i++) {
        store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(BLK4_KS + i));
      }
      off += 64;
    } else {
      cipherBlock(rk, cbPtr, BLK4_KS);
      const take: usize = rest < 16 ? rest : 16;
      for (let i: usize = 0; i < take; i++) {
        store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(BLK4_KS + i));
      }
      inc32(cbPtr);
      off += 16;
    }
  }
}

/**
 * SM4-GCM 加密（NIST SP 800-38D §7.1）。
 *
 * @param keyPtr 16 字节密钥。
 * @param ivPtr / ivLen 任意长度 IV（常用 12 字节）。
 * @param aadPtr / aadLen 附加认证数据（可为 0 长度）。
 * @param inPtr / inLen 明文（可为 0 长度）。
 * @param outPtr 密文输出（inLen 字节）。
 * @param tagPtr 认证标签输出（16 字节）。
 *
 * SM4-GCM encryption (NIST SP 800-38D §7.1).
 *
 * @param keyPtr 16-byte key.
 * @param ivPtr / ivLen IV of any length (12 bytes is the common case).
 * @param aadPtr / aadLen Additional authenticated data (may be 0 length).
 * @param inPtr / inLen Plaintext (may be 0 length).
 * @param outPtr Ciphertext output (inLen bytes).
 * @param tagPtr Authentication tag output (16 bytes).
 */
export function sm4GcmEncrypt(
  keyPtr: usize,
  ivPtr: usize,
  ivLen: usize,
  aadPtr: usize,
  aadLen: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
  tagPtr: usize,
): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);

  const h = new StaticArray<u8>(16);
  const hPtr = changetype<usize>(h);
  const zero = new StaticArray<u8>(16);
  cipherBlock(rk, changetype<usize>(zero), hPtr);
  const hhi = readU64BE(hPtr);
  const hlo = readU64BE(hPtr + 8);

  const j0 = new StaticArray<u8>(16);
  const j0Ptr = changetype<usize>(j0);
  computeJ0(hhi, hlo, ivPtr, ivLen, j0Ptr);

  // C = GCTR_K(inc32(J0), P)
  const icb = new StaticArray<u8>(16);
  const icbPtr = changetype<usize>(icb);
  inc32Copy(j0Ptr, icbPtr);
  gctr(rk, icbPtr, inPtr, inLen, outPtr);

  // S = GHASH_H(A, C)，再 T = GCTR_K(J0, S)
  // S = GHASH_H(A, C), then T = GCTR_K(J0, S).
  const s = new StaticArray<u8>(16);
  const sPtr = changetype<usize>(s);
  ghashAadCt(hhi, hlo, aadPtr, aadLen, outPtr, inLen, sPtr);
  gctr(rk, j0Ptr, sPtr, 16, tagPtr);
}

/**
 * SM4-GCM 解密 + 认证（NIST SP 800-38D §7.2）。
 *
 * @returns 0 表示标签校验通过；非 0 表示校验失败（调用方不得使用 outPtr 内容）。
 *
 * SM4-GCM decryption and authentication (NIST SP 800-38D §7.2).
 *
 * @returns 0 on tag success; non-zero on failure, in which case the caller must
 * not use the contents of outPtr.
 */
export function sm4GcmDecrypt(
  keyPtr: usize,
  ivPtr: usize,
  ivLen: usize,
  aadPtr: usize,
  aadLen: usize,
  inPtr: usize,
  inLen: usize,
  outPtr: usize,
  tagPtr: usize,
): i32 {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);

  const h = new StaticArray<u8>(16);
  const hPtr = changetype<usize>(h);
  const zero = new StaticArray<u8>(16);
  cipherBlock(rk, changetype<usize>(zero), hPtr);
  const hhi = readU64BE(hPtr);
  const hlo = readU64BE(hPtr + 8);

  const j0 = new StaticArray<u8>(16);
  const j0Ptr = changetype<usize>(j0);
  computeJ0(hhi, hlo, ivPtr, ivLen, j0Ptr);

  // S 用密文算（inPtr 在 gctr 里未被改写），T' = GCTR_K(J0, S)。
  // S is computed over the ciphertext (gctr never rewrites inPtr);
  // T' = GCTR_K(J0, S).
  const s = new StaticArray<u8>(16);
  const sPtr = changetype<usize>(s);
  ghashAadCt(hhi, hlo, aadPtr, aadLen, inPtr, inLen, sPtr);
  const t = new StaticArray<u8>(16);
  const tPtr = changetype<usize>(t);
  gctr(rk, j0Ptr, sPtr, 16, tPtr);

  // 常量时间比较 16 字节标签。
  //
  // Constant-time comparison of the 16-byte tag: no early exit, so timing does
  // not reveal how many leading bytes matched.
  let bad: i32 = 0;
  for (let i = 0; i < 16; i++) {
    bad |= <i32>(load<u8>(tPtr + i) ^ load<u8>(tagPtr + i));
  }
  if (bad !== 0) return 1;

  // 校验通过后才把明文写出：P = GCTR_K(inc32(J0), C)。
  //
  // Only write the plaintext out after the tag checks out:
  // P = GCTR_K(inc32(J0), C).
  const icb = new StaticArray<u8>(16);
  const icbPtr = changetype<usize>(icb);
  inc32Copy(j0Ptr, icbPtr);
  gctr(rk, icbPtr, inPtr, inLen, outPtr);
  return 0;
}

/**
 * 计数器块 / 密钥流的 scratch（非重入：CTR 与 GCTR 各自独占一次调用）。
 * BLK4_CB 收 4 个连续的计数器块，BLK4_KS 收它们 4 块交错加密后的密钥流；
 * BLK8_* 是同结构的 8 路版本。
 *
 * Scratch for counter blocks and keystream (non-reentrant: CTR and GCTR each
 * own one call at a time). BLK4_CB holds 4 consecutive counter blocks and
 * BLK4_KS the keystream after interleaved 4-block encryption; BLK8_* is the
 * 8-way version of the same layout.
 */
const BLK4_CB: usize = heap.alloc(64);
const BLK4_KS: usize = heap.alloc(64);
const BLK8_CB: usize = heap.alloc(128);
const BLK8_KS: usize = heap.alloc(128);

/**
 * GCTR 的计数器块工作区（16 字节），替代原先每次 `new StaticArray<u8>(16)`。
 *
 * GCTR's 16-byte counter-block workspace, replacing the previous
 * `new StaticArray<u8>(16)` per call.
 */
const GCTR_CB: usize = heap.alloc(16);

/**
 * 以 base（16 字节计数器块）为起点连续生成 4 个块到 BLK4_CB 并把 base 推进 4 次，
 * 再用 cipher4s 加密到 BLK4_KS。
 *
 * Starting from base (a 16-byte counter block), generate 4 consecutive blocks
 * into BLK4_CB while advancing base 4 times, then encrypt them with cipher4s
 * into BLK4_KS.
 */
function keystream4(rk: usize, base: usize): void {
  for (let k = 0; k < 4; k++) {
    memory.copy(BLK4_CB + ((<usize>k) << 4), base, 16);
    inc32(base);
  }
  cipher4s(rk, BLK4_CB, BLK4_KS);
}

/**
 * `keystream4` 的 8 路版本：8 个连续计数器块 → `cipher8s` → BLK8_KS。
 *
 * The 8-way version of `keystream4`: 8 consecutive counter blocks, then
 * `cipher8s`, into BLK8_KS.
 */
function keystream8(rk: usize, base: usize): void {
  for (let k = 0; k < 8; k++) {
    memory.copy(BLK8_CB + ((<usize>k) << 4), base, 16);
    inc32(base);
  }
  cipher8s(rk, BLK8_CB, BLK8_KS);
}

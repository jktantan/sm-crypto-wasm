// AssemblyScript SM4 分组密码核心（GB/T 32907-2016 = GM/T 0002-2014）。
//
// 文件说明：
// - 由 `asc` 编译为 `dist/sm4/sm4.wasm`。
// - 导出（供 TS 侧调用）：
//     alloc(n): usize           —— 从 AS 堆分配缓冲区
//     freeAll(): void           —— 释放全部缓冲
//     sm4EncryptECB(keyPtr, inPtr, inLen, outPtr): void
//     sm4DecryptECB(keyPtr, inPtr, inLen, outPtr): void
//     sm4Block(keyPtr, inPtr, outPtr, decrypt): void
//     sm4GcmEncrypt(keyPtr, ivPtr, ivLen, aadPtr, aadLen, inPtr, inLen, outPtr, tagPtr): void
//     sm4GcmDecrypt(同上): i32  —— 返回 0 表示认证标签校验通过
//   其中 inLen 必须是 16 的倍数（块长 16 字节）。
// - 加密/解密用同一套轮函数，解密使用逆序轮密钥（SM4 本身自反结构，
//   解密只需把 rk 逆序）。
//
// 参考：GB/T 32907-2016 §6（密钥扩展）、§7（加解密）。
//
// 内存约定：
// - keyPtr..keyPtr+16：128-bit 密钥（big-endian 分组）。
// - inPtr..inPtr+inLen：明文/密文。
// - outPtr..outPtr+inLen：输出。
// - 输入输出可重叠（逐块就地）。

// S 盒（GB/T 32907-2016 §6.2 表 1）。
// 用内存数据段裸指针：每块要做 128 次查表，`StaticArray` 索引会退化成
// `__get` runtime 调用（含边界检查），实测是每块成本的主要来源。
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
const FK: usize = memory.data<u32>([0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]);

// 固定参数 CK（GB/T 32907-2016 §6.4）。
const CK: usize = memory.data<u32>([
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
]);

// 用 Array 持住分配的缓冲，防止 GC 回收。
const pinned: Array<StaticArray<u8>> = [];

/** 从 AS 堆分配 n 字节。 */
export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

/** 释放全部缓冲。 */
export function freeAll(): void {
  pinned.length = 0;
}

/**
 * 轮密钥工作区（32 个 u32）——线性内存裸指针。
 * 密钥扩展与块加密都不重入（叶子），跨调用复用安全。
 */
const RK_PTR: usize = heap.alloc(32 * 4);

function rotl(x: u32, n: i32): u32 {
  return ((x << n) | (x >>> (32 - n))) & 0xffffffff;
}

/** big-endian 读 4 字节（一次 load<u32> + bswap，替代 4 次字节 load 拼装）。 */
function readU32BE(p: usize): u32 {
  return bswap<u32>(load<u32>(p));
}

/** big-endian 写 4 字节（一次 store<u32> + bswap）。 */
function writeU32BE(p: usize, v: u32): void {
  store<u32>(p, bswap<u32>(v));
}

/** 非线性变换 tau：对 4 字节逐字节查 S 盒（裸指针 + load<u8>）。 */
function tau(x: u32): u32 {
  const b0 = <u32>load<u8>(SBOX + ((x >>> 24) & 0xff));
  const b1 = <u32>load<u8>(SBOX + ((x >>> 16) & 0xff));
  const b2 = <u32>load<u8>(SBOX + ((x >>> 8) & 0xff));
  const b3 = <u32>load<u8>(SBOX + (x & 0xff));
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff;
}

/** 线性变换 L（加密轮用）。 */
function lLinear(b: u32): u32 {
  return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) & 0xffffffff;
}

/** 线性变换 L'（密钥扩展用）。 */
function lLinearKey(b: u32): u32 {
  return (b ^ rotl(b, 13) ^ rotl(b, 23)) & 0xffffffff;
}

/** 合成变换 T（加密轮）。 */
function tTransform(x: u32): u32 {
  return lLinear(tau(x));
}

/** 合成变换 T'（密钥扩展）。 */
function tTransformKey(x: u32): u32 {
  return lLinearKey(tau(x));
}

/**
 * 密钥扩展：把 16 字节密钥展开成 32 个轮密钥。
 *
 * @param keyPtr 密钥首地址。
 * @param rk 输出轮密钥数组（32 个）。
 */
function keyExpansion(keyPtr: usize, rk: usize): void {
  // 4 个滚动状态量（寄存器），替代 K[36] 数组 —— 后者每轮都要分配并走
  // `__get`/`__set` runtime 调用。
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
 */
function cipherBlock(rk: usize, inPtr: usize, outPtr: usize): void {
  // 4 个滚动状态量（寄存器）：SM4 的标准写法，替代 X[36] 数组的分配与访问。
  let x0 = readU32BE(inPtr);
  let x1 = readU32BE(inPtr + 4);
  let x2 = readU32BE(inPtr + 8);
  let x3 = readU32BE(inPtr + 12);
  for (let i = 0; i < 32; i++) {
    const t = (x0 ^ tTransform(x1 ^ x2 ^ x3 ^ load<u32>(rk + ((<usize>i) << 2)))) & 0xffffffff;
    x0 = x1;
    x1 = x2;
    x2 = x3;
    x3 = t;
  }
  // 输出反序：X35..X32 即最后的 x3..x0。
  writeU32BE(outPtr, x3);
  writeU32BE(outPtr + 4, x2);
  writeU32BE(outPtr + 8, x1);
  writeU32BE(outPtr + 12, x0);
}

/** 反转轮密钥（用于解密）。 */
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
 */
export function sm4EncryptECB(keyPtr: usize, inPtr: usize, inLen: usize, outPtr: usize): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  for (let off: usize = 0; off < inLen; off += 16) {
    cipherBlock(rk, inPtr + off, outPtr + off);
  }
}

/**
 * SM4 ECB 解密（inLen 必须是 16 的倍数）。
 */
export function sm4DecryptECB(keyPtr: usize, inPtr: usize, inLen: usize, outPtr: usize): void {
  const rk = RK_PTR;
  keyExpansion(keyPtr, rk);
  reverseRk(rk);
  for (let off: usize = 0; off < inLen; off += 16) {
    cipherBlock(rk, inPtr + off, outPtr + off);
  }
}

/**
 * 单块加密 / 解密，暴露给 TS 层做 CBC/CTR 等模式的块级调用。
 *
 * @param keyPtr 16 字节密钥。
 * @param inPtr 16 字节输入。
 * @param outPtr 16 字节输出。
 * @param decrypt 0=加密，1=解密。
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

/** 模式工作区（各 16 字节）：CBC 链值 / 异或暂存 / CTR 计数器 / CTR 密钥流。 */
const CBC_PREV: usize = heap.alloc(16);
const CBC_TMP: usize = heap.alloc(16);
const CTR_CB: usize = heap.alloc(16);
const CTR_KS: usize = heap.alloc(16);

/** 16 字节按 u32 异或：dst = a ^ b（三者均 4 字节对齐）。 */
function xor16u32(dst: usize, a: usize, b: usize): void {
  for (let i = 0; i < 16; i += 4) {
    store<u32>(dst + i, load<u32>(a + i) ^ load<u32>(b + i));
  }
}

/**
 * SM4-CBC 加密（inLen 必须是 16 的倍数；padding 由调用方处理）。
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
    cipherBlock(rk, inPtr + off, outPtr + off);
    xor16u32(outPtr + off, outPtr + off, CBC_PREV);
    memory.copy(CBC_PREV, CBC_TMP, 16);
  }
}

/**
 * SM4-CTR 加解密（自反；inLen 任意长度）。
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
    cipherBlock(rk, CTR_CB, CTR_KS);
    const rest = inLen - off;
    const take: usize = rest < 16 ? rest : 16;
    for (let i: usize = 0; i < take; i++) {
      store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(CTR_KS + i));
    }
    inc32(CTR_CB);
    off += 16;
  }
}

// ---------- GCM（NIST SP 800-38D 的 AEAD，套在 SM4 上） ----------
//
// GCM = CTR（计数器只递增最后 32 位）+ GHASH（GF(2^128) 上的多项式哈希）。
// 参考 NIST SP 800-38D §6.3（GF 乘法 Algorithm 1）、§6.4（GHASH）、§6.5（GCTR）、
// §7.1（GCM 加解密）。GmSSL/OpenSSL 的 SM4-GCM 遵循同一规范，产物可互操作。

/** GF(2^128) 乘法结果暂存（hi=高 64 位，lo=低 64 位）。 */
const gmulOut = new StaticArray<u64>(2);

/** GHASH 累积状态（128-bit，hi/lo）。 */
let ghashHi: u64 = 0;
let ghashLo: u64 = 0;

/** big-endian 读 8 字节到 u64（不用 load<u64> 以规避对齐要求）。 */
function readU64BE(p: usize): u64 {
  let v: u64 = 0;
  for (let i = 0; i < 8; i++) {
    v = (v << 8) | <u64>load<u8>(p + i);
  }
  return v;
}

/** big-endian 写 u64 到 8 字节。 */
function writeU64BE(p: usize, v: u64): void {
  for (let i = 0; i < 8; i++) {
    store<u8>(p + i, <u8>(v >>> ((7 - i) * 8)));
  }
}

/**
 * GF(2^128) 乘法，GCM 的 bit-reversed 约定（NIST SP 800-38D Algorithm 1）。
 *
 * 结果写入 `gmulOut`。
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

/** 把一段数据（不足 16 字节在尾部补零）异或进 GHASH 状态，再乘 H。 */
function ghashBlock(hhi: u64, hlo: u64, p: usize, len: usize): void {
  let bhi: u64 = 0;
  let blo: u64 = 0;
  for (let i: usize = 0; i < len; i++) {
    const b = <u64>load<u8>(p + i);
    // 块是大端：数据在**高位**，逐字节左移到对应位置（不足 16 字节时尾部留零）。
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

/** 吸收任意长度数据到 GHASH 状态，逐 16 字节补零分块。 */
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
  ghashLo ^= (<u64>ivLen) << 3;
  gfMul(ghashHi, ghashLo, hhi, hlo);
  writeU64BE(outPtr, gmulOut[0]);
  writeU64BE(outPtr + 8, gmulOut[1]);
}

/** inc32：只把 16 字节块的最后 4 字节按大端加一（GCM 计数器规则）。 */
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

/** 复制 16 字节并 inc32，用于得到 GCTR 的初始计数器块 inc32(J0)。 */
function inc32Copy(srcPtr: usize, dstPtr: usize): void {
  for (let i = 0; i < 16; i++) store<u8>(dstPtr + i, load<u8>(srcPtr + i));
  inc32(dstPtr);
}

/**
 * GCTR：以 icb 为初始计数器块对数据做流式加/解密（NIST SP 800-38D §6.5）。
 * 输入输出可重叠。
 */
function gctr(rk: usize, icbPtr: usize, inPtr: usize, inLen: usize, outPtr: usize): void {
  if (inLen === 0) return;
  const cb = new StaticArray<u8>(16);
  const cbPtr = changetype<usize>(cb);
  for (let i = 0; i < 16; i++) store<u8>(cbPtr + i, load<u8>(icbPtr + i));
  const ks = new StaticArray<u8>(16);
  const ksPtr = changetype<usize>(ks);
  let off: usize = 0;
  while (off < inLen) {
    cipherBlock(rk, cbPtr, ksPtr);
    const rest = inLen - off;
    const take: usize = rest < 16 ? rest : 16;
    for (let i: usize = 0; i < take; i++) {
      store<u8>(outPtr + off + i, load<u8>(inPtr + off + i) ^ load<u8>(ksPtr + i));
    }
    inc32(cbPtr);
    off += 16;
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
  const s = new StaticArray<u8>(16);
  const sPtr = changetype<usize>(s);
  ghashAadCt(hhi, hlo, aadPtr, aadLen, outPtr, inLen, sPtr);
  gctr(rk, j0Ptr, sPtr, 16, tagPtr);
}

/**
 * SM4-GCM 解密 + 认证（NIST SP 800-38D §7.2）。
 *
 * @returns 0 表示标签校验通过；非 0 表示校验失败（调用方不得使用 outPtr 内容）。
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
  const s = new StaticArray<u8>(16);
  const sPtr = changetype<usize>(s);
  ghashAadCt(hhi, hlo, aadPtr, aadLen, inPtr, inLen, sPtr);
  const t = new StaticArray<u8>(16);
  const tPtr = changetype<usize>(t);
  gctr(rk, j0Ptr, sPtr, 16, tPtr);

  // 常量时间比较 16 字节标签。
  let bad: i32 = 0;
  for (let i = 0; i < 16; i++) {
    bad |= <i32>(load<u8>(tPtr + i) ^ load<u8>(tagPtr + i));
  }
  if (bad !== 0) return 1;

  // 校验通过后才把明文写出：P = GCTR_K(inc32(J0), C)。
  const icb = new StaticArray<u8>(16);
  const icbPtr = changetype<usize>(icb);
  inc32Copy(j0Ptr, icbPtr);
  gctr(rk, icbPtr, inPtr, inLen, outPtr);
  return 0;
}

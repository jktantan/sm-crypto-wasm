// SM3 纯计算核心（AssemblyScript）—— 归属 SM3 模块。
//
// 本文件**不**包含内存分配导出，只提供纯哈希计算，供：
// - `src/sm3/assembly/index.ts`（编译为 sm3.wasm）
// - `src/sm2/assembly/crypto.ts`（编译进 sm2.wasm，用于 Z 值/KDF/C3）
//
// 两个 wasm 在**编译期**各自内联一份（AssemblyScript 是 AOT 编译器），
// 运行期互不依赖 —— 因此 sm2.wasm 与 sm3.wasm 完全解耦。
//
// 参考：GB/T 32905-2016 / GM/T 0004-2014。

const IV: StaticArray<u32> = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

const T0: u32 = 0x79cc4519;
const T1: u32 = 0x7a879d8a;

function rotl(x: u32, n: i32): u32 {
  return ((x << n) | (x >>> (32 - n))) & 0xffffffff;
}
function ff0(x: u32, y: u32, z: u32): u32 {
  return x ^ y ^ z;
}
function ff1(x: u32, y: u32, z: u32): u32 {
  return (x & y) | (y & z) | (x & z);
}
function gg0(x: u32, y: u32, z: u32): u32 {
  return x ^ y ^ z;
}
function gg1(x: u32, y: u32, z: u32): u32 {
  return (x & y) | (~x & z);
}
function p0(x: u32): u32 {
  return x ^ rotl(x, 9) ^ rotl(x, 17);
}
function p1(x: u32): u32 {
  return x ^ rotl(x, 15) ^ rotl(x, 23);
}

/**
 * 单次压缩：处理 64 字节块，state 原地更新。
 *
 * @param statePtr 8 个 u32（共 32 字节）状态指针，big-endian 字节布局。
 * @param blockPtr 64 字节块指针。
 */
function compress(statePtr: usize, blockPtr: usize): void {
  const W = new StaticArray<u32>(68);
  const Wp = new StaticArray<u32>(64);

  for (let i = 0; i < 16; i++) {
    const o = blockPtr + i * 4;
    const b0 = <u32>load<u8>(o);
    const b1 = <u32>load<u8>(o + 1);
    const b2 = <u32>load<u8>(o + 2);
    const b3 = <u32>load<u8>(o + 3);
    W[i] = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff;
  }
  for (let i = 16; i < 68; i++) {
    const v = W[i - 16] ^ W[i - 9] ^ rotl(W[i - 3], 15);
    W[i] = (p1(v) ^ rotl(W[i - 13], 7) ^ W[i - 6]) & 0xffffffff;
  }
  for (let i = 0; i < 64; i++) Wp[i] = (W[i] ^ W[i + 4]) & 0xffffffff;

  const readU32BE = (p: usize): u32 => {
    const b0 = <u32>load<u8>(p);
    const b1 = <u32>load<u8>(p + 1);
    const b2 = <u32>load<u8>(p + 2);
    const b3 = <u32>load<u8>(p + 3);
    return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff;
  };
  let A = readU32BE(statePtr + 0);
  let B = readU32BE(statePtr + 4);
  let C = readU32BE(statePtr + 8);
  let D = readU32BE(statePtr + 12);
  let E = readU32BE(statePtr + 16);
  let F = readU32BE(statePtr + 20);
  let G = readU32BE(statePtr + 24);
  let H = readU32BE(statePtr + 28);

  for (let j: usize = 0; j < 64; j++) {
    let TjVal: u32;
    let TjShift: u32;
    if (j < 16) {
      TjVal = T0;
      TjShift = <u32>j;
    } else {
      TjVal = T1;
      TjShift = <u32>(j % 32);
    }
    const Tj = rotl(TjVal, <i32>TjShift);
    const A12 = rotl(A, 12);
    const SS1 = rotl((A12 + E + Tj) & 0xffffffff, 7);
    const SS2 = SS1 ^ A12;
    const TT1 = ((j < 16 ? ff0(A, B, C) : ff1(A, B, C)) + D + SS2 + Wp[j]) & 0xffffffff;
    const TT2 = ((j < 16 ? gg0(E, F, G) : gg1(E, F, G)) + H + SS1 + W[j]) & 0xffffffff;
    D = C;
    C = rotl(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotl(F, 19);
    F = E;
    E = p0(TT2);
  }

  const writeU32BE = (p: usize, v: u32): void => {
    store<u8>(p, <u8>(v >>> 24));
    store<u8>(p + 1, <u8>(v >>> 16));
    store<u8>(p + 2, <u8>(v >>> 8));
    store<u8>(p + 3, <u8>v);
  };
  writeU32BE(statePtr + 0, (readU32BE(statePtr + 0) ^ A) & 0xffffffff);
  writeU32BE(statePtr + 4, (readU32BE(statePtr + 4) ^ B) & 0xffffffff);
  writeU32BE(statePtr + 8, (readU32BE(statePtr + 8) ^ C) & 0xffffffff);
  writeU32BE(statePtr + 12, (readU32BE(statePtr + 12) ^ D) & 0xffffffff);
  writeU32BE(statePtr + 16, (readU32BE(statePtr + 16) ^ E) & 0xffffffff);
  writeU32BE(statePtr + 20, (readU32BE(statePtr + 20) ^ F) & 0xffffffff);
  writeU32BE(statePtr + 24, (readU32BE(statePtr + 24) ^ G) & 0xffffffff);
  writeU32BE(statePtr + 28, (readU32BE(statePtr + 28) ^ H) & 0xffffffff);
}

/**
 * 计算 SM3 摘要，写入 outPtr（32 字节，big-endian）。
 *
 * @param inputPtr 输入起始地址。
 * @param inputLen 输入字节数。
 * @param outPtr 输出 32 字节。
 */
export function sm3HashInto(inputPtr: usize, inputLen: usize, outPtr: usize): void {
  const state = new StaticArray<u8>(32);
  for (let i: usize = 0; i < 8; i++) {
    const v: u32 = IV[i];
    state[i * 4] = <u8>(v >>> 24);
    state[i * 4 + 1] = <u8>(v >>> 16);
    state[i * 4 + 2] = <u8>(v >>> 8);
    state[i * 4 + 3] = <u8>v;
  }
  const lenWithPad: usize = inputLen + 9;
  const padding: usize = (64 - (lenWithPad % 64)) % 64;
  const totalLen: usize = inputLen + 1 + padding + 8;
  const buf = new StaticArray<u8>(totalLen);
  for (let i: usize = 0; i < inputLen; i++) buf[i] = load<u8>(inputPtr + i);
  buf[inputLen] = 0x80;
  const bitLen: u64 = <u64>inputLen * 8;
  for (let i: usize = 0; i < 8; i++) {
    buf[totalLen - 8 + i] = <u8>((bitLen >> ((7 - i) * 8)) & 0xff);
  }
  for (let off: usize = 0; off < totalLen; off += 64) {
    compress(changetype<usize>(state), changetype<usize>(buf) + off);
  }
  for (let i: usize = 0; i < 32; i++) store<u8>(outPtr + i, state[i]);
}

/** 计算 SM3 摘要并返回新的 32 字节 StaticArray。 */
export function sm3HashBytes(inputPtr: usize, inputLen: usize): StaticArray<u8> {
  const out = new StaticArray<u8>(32);
  sm3HashInto(inputPtr, inputLen, changetype<usize>(out));
  return out;
}

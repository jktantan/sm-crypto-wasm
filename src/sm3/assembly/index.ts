// AssemblyScript SM3 哈希实现（GB/T 32905-2016 = GM/T 0004-2014）。
//
// 文件说明：
// - 本文件由 `asc` 编译器编译为 `dist/sm3/sm3.wasm`。
// - 编译命令见 package.json scripts.build:wasm。
// - 暴露给 JS/TS 侧的导出函数（用 @external 标注）：
//     sm3(inputPtr: usize, inputLen: usize, outPtr: usize): void
//     sm3Final(ctxPtr: usize, outPtr: usize): void       （多块增量接口，暂未启用）
// - 内存布局：调用方负责传入一块 wasm 线性内存空间。
//   - input bytes：inputPtr..inputPtr+inputLen
//   - output 32 bytes：outPtr..outPtr+32
//
// 公开算法参考：GM/T 0004-2016 标准的 SM3 算法描述。
// 与 GM/T 0004-2014 同义。

// 初始值 IV（spec §4.1）。
const IV: StaticArray<u32> = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

// 用 Array 持住已分配缓冲，防止被 AS GC 回收（否则返回的指针指向已释放内存）。
const pinned: Array<StaticArray<u8>> = [];

/**
 * 从 AS 堆分配 n 字节，返回首地址。
 *
 * 暴露给 TS 胶水层用于分配 input / output 缓冲区 —— **绝不能**用固定的
 * 小地址（如 0），因为 wasm 线性内存的 0 段被 AS runtime 占用，写它会
 * 破坏 runtime 状态（历史 bug：算法改对了但输出恒错）。
 *
 * @param n 字节数。
 * @returns 分配到的线性内存首地址。
 */
export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

/**
 * 释放全部 `alloc` 分配的缓冲（简单做法：整批清空）。
 */
export function freeAll(): void {
  pinned.length = 0;
}

// 常量 Tj（spec §4.2）。
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
 * @param statePtr 8 个 u32（共 32 字节）的状态指针。
 * @param blockPtr 64 字节块指针。
 */
function compress(statePtr: usize, blockPtr: usize): void {
  const W = new StaticArray<u32>(68);
  const Wp = new StaticArray<u32>(64);

  // 读取 W[0..16]。WebAssembly 内存是 little-endian；SM3 需要 big-endian。
  for (let i = 0; i < 16; i++) {
    const o = blockPtr + (i * 4);
    const b0 = <u32>load<u8>(o);
    const b1 = <u32>load<u8>(o + 1);
    const b2 = <u32>load<u8>(o + 2);
    const b3 = <u32>load<u8>(o + 3);
    W[i] = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff;
  }
  // 扩展 W[16..68]。spec: W[i] = P1(W[i-16] ^ W[i-9] ^ rotl(W[i-3],15)) ^ rotl(W[i-13],7) ^ W[i-6]
  for (let i = 16; i < 68; i++) {
    const v = (W[i - 16] ^ W[i - 9] ^ rotl(W[i - 3], 15));
    W[i] = (p1(v) ^ rotl(W[i - 13], 7) ^ W[i - 6]) & 0xffffffff;
  }
  // 计算 W'。
  for (let i = 0; i < 64; i++) {
    Wp[i] = (W[i] ^ W[i + 4]) & 0xffffffff;
  }

  // 读取 state（big-endian，因为 SM3 状态按 big-endian 字面拼接）。
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

  // 64 轮压缩。
  for (let j: usize = 0; j < 64; j++) {
    // spec §4.2：
    //   j ∈ [0,15]:   Tj = T0 <<< j
    //   j ∈ [16,63]:  Tj = T1 <<< (j % 32)
    let TjShift: u32;
    let TjVal: u32;
    if (j < 16) {
      TjVal = T0;
      TjShift = <u32>j;
    } else {
      TjVal = T1;
      TjShift = <u32>(j % 32);
    }
    const Tj: u32 = rotl(TjVal, <i32>TjShift);
    const A12 = rotl(A, 12);
    const SS1 = rotl((A12 + E + Tj) & 0xffffffff, 7);
    const SS2 = SS1 ^ A12;
    const TT1 = (
      ((j < 16) ? ff0(A, B, C) : ff1(A, B, C)) +
      D + SS2 + Wp[j]
    ) & 0xffffffff;
    const TT2 = (
      ((j < 16) ? gg0(E, F, G) : gg1(E, F, G)) +
      H + SS1 + W[j]
    ) & 0xffffffff;
    D = C;
    C = rotl(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotl(F, 19);
    F = E;
    E = p0(TT2);
  }

  // state ^= (A..H)，按 big-endian 写回。
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
 * SM3 单块调用入口：输入任意字节长度，输出 32 字节摘要。
 *
 * 内存约定：
 * - inputPtr..inputPtr+inputLen：输入字节。
 * - outPtr..outPtr+32：输出摘要（32 字节）。
 *
 * 实现：
 * - `state` 用 `StaticArray<u8>(32)` —— 把 SM3 的 8 个 u32 状态字按
 *   big-endian 字节序列放进线性内存，方便 `compress()` 直接字节级读写。
 * - 输入先拷贝到 `buf` 上做 padding（0x80 + 0..n 个 0 + 64-bit 长度）。
 *
 * @param inputPtr 输入字节起始地址。
 * @param inputLen 输入字节长度。
 * @param outPtr 输出 32 字节起始地址。
 */
export function sm3(inputPtr: usize, inputLen: usize, outPtr: usize): void {
  // 状态：32 字节（8 个 u32 大端）放在栈上。
  const state = new StaticArray<u8>(32);
  // 初始化 IV（GM/T 0004-2014 §4.1），按 big-endian 写入。
  for (let i: usize = 0; i < 8; i++) {
    const v: u32 = IV[i];
    state[i * 4]     = <u8>(v >>> 24);
    state[i * 4 + 1] = <u8>(v >>> 16);
    state[i * 4 + 2] = <u8>(v >>> 8);
    state[i * 4 + 3] = <u8>v;
  }

  // 计算 padding：inputLen + 1 + padding + 8 = 64 的倍数。
  const lenWithPad: usize = inputLen + 9;
  const padding: usize = (64 - (lenWithPad % 64)) % 64;
  const totalLen: usize = inputLen + 1 + padding + 8;

  // 拷贝输入到栈上缓冲。
  const buf = new StaticArray<u8>(totalLen);
  for (let i: usize = 0; i < inputLen; i++) buf[i] = load<u8>(inputPtr + i);
  // 追加 0x80。
  buf[inputLen] = 0x80;
  // 末尾 8 字节是 bit length，大端：buf[totalLen-8] 存 MSB，buf[totalLen-1] 存 LSB。
  const bitLen: u64 = <u64>inputLen * 8;
  for (let i: usize = 0; i < 8; i++) {
    // i=0 → buf[totalLen-8] = MSB；i=7 → buf[totalLen-1] = LSB。
    buf[totalLen - 8 + i] = <u8>((bitLen >> ((7 - i) * 8)) & 0xff);
  }

  // 逐块压缩。
  for (let off: usize = 0; off < totalLen; off += 64) {
    compress(changetype<usize>(state), changetype<usize>(buf) + off);
  }

  // 写 32 字节摘要到 outPtr（big-endian）。
  for (let i: usize = 0; i < 32; i++) {
    store<u8>(outPtr + i, state[i]);
  }
}

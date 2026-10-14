// SM3 纯计算核心（AssemblyScript）—— 归属 SM3 模块。
//
// 本文件**不**包含内存分配导出，只提供纯哈希计算，供：
// - `src/sm3/assembly/index.ts`（编译为 sm3.wasm）
// - `src/sm2/assembly/crypto.ts`（编译进 sm2.wasm，用于 Z 值/KDF/C3）
//
// 两个 wasm 在**编译期**各自内联一份（AssemblyScript 是 AOT 编译器），
// 运行期互不依赖 —— 因此 sm2.wasm 与 sm3.wasm 完全解耦。
//
// 性能要点（实测每块成本从 2.03 µs 降到与纯 JS 同档）：
// - 压缩函数的 W / Wp 用**模块级 scratch**：原先每块 `new` 一次（68+64 个 u32），
//   1KB 输入就要分配 34 次、64KB 分配 2050 次；
// - 消息块与状态用 u32 访存（`load<u32>`/`store<u32>` + `bswap`）替代每字 4 次
//   `load<u8>` 拼装；
// - 轮循环按 T0 / T1 两段拆开，去掉每轮的 `j < 16` 分支与 `j % 32` 取模；
// - 输入到内部缓冲的拷贝用 `memory.copy` 而非逐字节循环。
//
// 参考：GB/T 32905-2016 / GM/T 0004-2014。

const IV: StaticArray<u32> = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

const T0: u32 = 0x79cc4519;
const T1: u32 = 0x7a879d8a;

/** 轮常数 Tj = rotl(T0, j)（j < 16）/ rotl(T1, j mod 32)（j ≥ 16）。一次算好复用。 */
const TJ = new StaticArray<u32>(64);
for (let j = 0; j < 64; j++) {
  TJ[j] = rotl(j < 16 ? T0 : T1, j < 16 ? j : j & 31);
}

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
 */
const W_PTR: usize = heap.alloc(68 * 4);
const WP_PTR: usize = heap.alloc(64 * 4);
const TJ_PTR: usize = heap.alloc(64 * 4);
/** 8 个 u32 状态。sm3HashInto 顺序调用（HMAC 亦为顺序），不重入。 */
const STATE_PTR: usize = heap.alloc(8 * 4);

/** 轮常数 Tj = rotl(T0, j)（j < 16）/ rotl(T1, j mod 32)（j ≥ 16）。一次算好复用。 */
for (let j = 0; j < 64; j++) {
  store<u32>(TJ_PTR + ((<usize>j) << 2), rotl(j < 16 ? T0 : T1, j < 16 ? j : j & 31));
}

/** 读大端 u32。wasm 内存是小端，故需 bswap。 */
function loadU32BE(p: usize): u32 {
  return bswap<u32>(load<u32>(p));
}

/**
 * 单次压缩：处理 64 字节块，`statePtr`（8 个 u32）原地更新。
 *
 * @param statePtr 8 个 u32 状态指针。
 * @param blockPtr 64 字节块指针（4 字节对齐 —— 块偏移恒为 64 的倍数）。
 */
function compress(statePtr: usize, blockPtr: usize): void {
  for (let i = 0; i < 16; i++) {
    store<u32>(W_PTR + ((<usize>i) << 2), loadU32BE(blockPtr + ((<usize>i) << 2)));
  }
  for (let i = 16; i < 68; i++) {
    const v =
      load<u32>(W_PTR + ((<usize>(i - 16)) << 2)) ^
      load<u32>(W_PTR + ((<usize>(i - 9)) << 2)) ^
      rotl(load<u32>(W_PTR + ((<usize>(i - 3)) << 2)), 15);
    const wv =
      (p1(v) ^
        rotl(load<u32>(W_PTR + ((<usize>(i - 13)) << 2)), 7) ^
        load<u32>(W_PTR + ((<usize>(i - 6)) << 2))) &
      0xffffffff;
    store<u32>(W_PTR + ((<usize>i) << 2), wv);
  }
  for (let i = 0; i < 64; i++) {
    const wv =
      (load<u32>(W_PTR + ((<usize>i) << 2)) ^ load<u32>(W_PTR + ((<usize>(i + 4)) << 2))) &
      0xffffffff;
    store<u32>(WP_PTR + ((<usize>i) << 2), wv);
  }

  let A = load<u32>(statePtr);
  let B = load<u32>(statePtr + 4);
  let C = load<u32>(statePtr + 8);
  let D = load<u32>(statePtr + 12);
  let E = load<u32>(statePtr + 16);
  let F = load<u32>(statePtr + 20);
  let G = load<u32>(statePtr + 24);
  let H = load<u32>(statePtr + 28);

  // j = 0..15：T0 + ff0/gg0
  for (let j = 0; j < 16; j++) {
    const A12 = rotl(A, 12);
    const SS1 = rotl((A12 + E + load<u32>(TJ_PTR + ((<usize>j) << 2))) & 0xffffffff, 7);
    const SS2 = SS1 ^ A12;
    const TT1 = (ff0(A, B, C) + D + SS2 + load<u32>(WP_PTR + ((<usize>j) << 2))) & 0xffffffff;
    const TT2 = (gg0(E, F, G) + H + SS1 + load<u32>(W_PTR + ((<usize>j) << 2))) & 0xffffffff;
    D = C;
    C = rotl(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotl(F, 19);
    F = E;
    E = p0(TT2);
  }
  // j = 16..63：T1 + ff1/gg1
  for (let j = 16; j < 64; j++) {
    const A12 = rotl(A, 12);
    const SS1 = rotl((A12 + E + load<u32>(TJ_PTR + ((<usize>j) << 2))) & 0xffffffff, 7);
    const SS2 = SS1 ^ A12;
    const TT1 = (ff1(A, B, C) + D + SS2 + load<u32>(WP_PTR + ((<usize>j) << 2))) & 0xffffffff;
    const TT2 = (gg1(E, F, G) + H + SS1 + load<u32>(W_PTR + ((<usize>j) << 2))) & 0xffffffff;
    D = C;
    C = rotl(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotl(F, 19);
    F = E;
    E = p0(TT2);
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
 * 计算 SM3 摘要，写入 outPtr（32 字节，big-endian）。
 *
 * @param inputPtr 输入起始地址。
 * @param inputLen 输入字节数。
 * @param outPtr 输出 32 字节（4 字节对齐）。
 */
export function sm3HashInto(inputPtr: usize, inputLen: usize, outPtr: usize): void {
  for (let i = 0; i < 8; i++) store<u32>(STATE_PTR + ((<usize>i) << 2), IV[i]);

  const lenWithPad: usize = inputLen + 9;
  const padding: usize = (64 - (lenWithPad % 64)) % 64;
  const totalLen: usize = inputLen + 1 + padding + 8;
  // StaticArray 初始化即清零，故 padding 区已是 0
  const buf = new StaticArray<u8>(<i32>totalLen);
  memory.copy(changetype<usize>(buf), inputPtr, inputLen);
  buf[<i32>inputLen] = 0x80;
  const bitLen: u64 = <u64>inputLen * 8;
  for (let i = 0; i < 8; i++) {
    buf[<i32>totalLen - 8 + <i32>i] = <u8>((bitLen >> ((7 - i) * 8)) & 0xff);
  }
  for (let off: usize = 0; off < totalLen; off += 64) {
    compress(STATE_PTR, changetype<usize>(buf) + off);
  }
  // 输出大端
  for (let i = 0; i < 8; i++) {
    store<u32>(outPtr + ((<usize>i) << 2), bswap<u32>(load<u32>(STATE_PTR + ((<usize>i) << 2))));
  }
}

/** 计算 SM3 摘要并返回新的 32 字节 StaticArray。 */
export function sm3HashBytes(inputPtr: usize, inputLen: usize): StaticArray<u8> {
  const out = new StaticArray<u8>(32);
  sm3HashInto(inputPtr, inputLen, changetype<usize>(out));
  return out;
}

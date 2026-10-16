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

const IV0: u32 = 0x7380166f;
const IV1: u32 = 0x4914b2b9;
const IV2: u32 = 0x172442d7;
const IV3: u32 = 0xda8a0600;
const IV4: u32 = 0xa96f30bc;
const IV5: u32 = 0x163138aa;
const IV6: u32 = 0xe38dee4d;
const IV7: u32 = 0xb0fb0e4e;

const T0: u32 = 0x79cc4519;
const T1: u32 = 0x7a879d8a;

function rotl(x: u32, n: i32): u32 {
  return (x << n) | (x >>> (32 - n));
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
const TJ_PTR: usize = heap.alloc(64 * 4);
/** 8 个 u32 状态。sm3Core 顺序调用（HMAC 亦为顺序），不重入。 */
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
  // 载入 16 个字（大端）。展开成一串常量偏移，省掉循环控制与地址计算。
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
 */
let PAD_CAP: usize = 0;
let PAD_PTR: usize = 0;

function padBuf(totalLen: usize): usize {
  if (totalLen > PAD_CAP) {
    // 按需翻倍增长，避免每次加长都重分配。
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
 */
export function sm3Hash2Into(p1: usize, n1: usize, p2: usize, n2: usize, outPtr: usize): void {
  sm3Core(p1, n1, p2, n2, outPtr);
}

// ---------------------------------------------------------------- HMAC-SM3

/** K′（归一化后的密钥，≤64 字节、右侧补零）与 pad 工作块、内层摘要。HMAC 不重入。 */
const HMAC_KEY_PTR: usize = heap.alloc(64);
const HMAC_PAD_PTR: usize = heap.alloc(64);
const HMAC_INNER_PTR: usize = heap.alloc(32);

/** ipad / opad 的 4 字节批量常量（0x36 / 0x5c 各重复 4 次）。 */
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
  for (let i = 0; i < 64; i += 4) {
    store<u32>(HMAC_PAD_PTR + <usize>i, load<u32>(HMAC_KEY_PTR + <usize>i) ^ IPAD32);
  }
  sm3Hash2Into(HMAC_PAD_PTR, 64, msgPtr, msgLen, HMAC_INNER_PTR);

  // 外层：SM3((K′ ⊕ opad) ‖ inner)
  for (let i = 0; i < 64; i += 4) {
    store<u32>(HMAC_PAD_PTR + <usize>i, load<u32>(HMAC_KEY_PTR + <usize>i) ^ OPAD32);
  }
  sm3Hash2Into(HMAC_PAD_PTR, 64, HMAC_INNER_PTR, 32, outPtr);
}

/** 计算 SM3 摘要并返回新的 32 字节 StaticArray。 */
export function sm3HashBytes(inputPtr: usize, inputLen: usize): StaticArray<u8> {
  const out = new StaticArray<u8>(32);
  sm3HashInto(inputPtr, inputLen, changetype<usize>(out));
  return out;
}

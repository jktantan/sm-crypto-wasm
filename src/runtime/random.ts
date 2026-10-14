/**
 * 宿主随机数包装（host-backed randomness）。
 *
 * 设计要点（spec §9 安全姿态）：
 * - **永远走宿主 CSPRNG**：浏览器 `globalThis.crypto.getRandomValues`、
 *   Node `webcrypto.getRandomValues`。**绝不**实例化本地 RNG。
 * - **拒绝采样（rejection sampling）**：用于 SM2/SM9 椭圆曲线私钥 k；
 *   按 64-bit limb 切分，从 256-bit 候选中重抽直至 < order。
 * - **长度边界**：输入 `n ∈ [0, 65536]`，溢出抛 `RangeError`。
 *
 * spec/plan 对应：plan Task 3；spec §9 安全姿态、§6 SM2/SM9 API。
 */
import { webcrypto } from 'node:crypto';

/** 宿主 CSPRNG 引用；优先 `globalThis.crypto`（浏览器 / Node 19+）。 */
const c: Crypto = (globalThis as { crypto?: Crypto }).crypto ?? (webcrypto as unknown as Crypto);

/**
 * 取 `n` 字节 CSPRNG 随机数。
 *
 * @param n 字节数，范围 `[0, 65536]`。
 * @returns 新分配的字节数组（拷贝）。
 * @throws RangeError n 不在范围内或不是整数。
 */
export function randomBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 65536) {
    throw new RangeError(`randomBytes: length must be integer in [0, 65536], got ${n}`);
  }
  const out = new Uint8Array(n);
  if (n > 0) c.getRandomValues(out);
  return out;
}

/**
 * 在 `[1, order)` 区间均匀取一个随机标量（用于 SM2/SM9 椭圆曲线 k）。
 *
 * 算法：64-bit limb rejection sampling。从 `getRandomValues` 取 4 个 64-bit
 * limb 拼接成 256-bit 候选值；若 ≥ `order` 则重抽。偏置 ≤ 2^-128，足够低。
 *
 * @param order 椭圆曲线子群阶（如 SM2 的 n、SM9 的 BN256 n）。
 * @returns 满足 `1 ≤ k < order` 的大整数。
 */
export function randomScalarBelow(order: bigint): bigint {
  if (order <= 1n) throw new RangeError('randomScalarBelow: order must be > 1');
  // 用 256-bit 候选：4 个 64-bit big-endian limb。
  while (true) {
    const buf = randomBytes(32); // 256 bits
    let candidate = 0n;
    for (let i = 0; i < 32; i++) {
      candidate = (candidate << 8n) | BigInt(buf[i] ?? 0);
    }
    // 严格 < order（不允许 0）。
    if (candidate > 0n && candidate < order) return candidate;
    // 否则重抽；理论上不到一次。
  }
}

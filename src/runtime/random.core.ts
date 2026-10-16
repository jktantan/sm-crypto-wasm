/**
 * 随机数共享核心（Node 版与浏览器版共用）。
 *
 * **零 `node:*` 引用** —— 浏览器版的模块图里不能出现 node 内置模块
 * （Webpack / esbuild / Rspack 解析期即失败）。宿主 CSPRNG 的获取方式由
 * `random.ts`（Node）与 `random.browser.ts`（浏览器）各自实现。
 */

/**
 * 在 `[1, order)` 区间均匀取一个随机标量（用于 SM2 / SM9 椭圆曲线 k）。
 *
 * 算法：256-bit 候选 + 拒绝采样。从宿主 CSPRNG 取 32 字节拼成大整数，
 * 若为 0 或 ≥ `order` 则重抽。SM2 的 n 几乎等于 2²⁵⁶（一次命中），
 * SM9 的 n ≈ 0.712 × 2²⁵⁶（平均约 1.4 次）。偏置上界 ≈ `order / 2²⁵⁶`，
 * 量级在 2⁻¹²⁸ 以下。
 *
 * @param order 椭圆曲线子群阶（如 SM2 的 n、SM9 的 BN256 n）。
 * @param randomBytes 宿主 CSPRNG 取字节函数（由调用方注入，保证两侧实现一致）。
 * @returns 满足 `1 ≤ k < order` 的大整数。
 */
export function scalarBelowFrom(order: bigint, randomBytes: (n: number) => Uint8Array): bigint {
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

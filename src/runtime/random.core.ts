/**
 * 随机数共享核心（Node 版与浏览器版共用）。
 *
 * **零 `node:*` 引用** —— 浏览器版的模块图里不能出现 node 内置模块
 * （Webpack / esbuild / Rspack 解析期即失败）。宿主 CSPRNG 的获取方式由
 * `random.ts`（Node）与 `random.browser.ts`（浏览器）各自实现。
 *
 * Random-number shared core (used by both the Node and the browser version).
 *
 * **Zero `node:*` references** — node built-ins must not appear in the browser
 * bundle's module graph (Webpack / esbuild / Rspack fail at resolve time). How the
 * host CSPRNG is obtained is implemented separately by `random.ts` (Node) and
 * `random.browser.ts` (browser).
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
 *
 * Uniformly pick a random scalar in `[1, order)` (used for the SM2 / SM9 curve scalar
 * k).
 *
 * Algorithm: 256-bit candidate plus rejection sampling. 32 bytes are drawn from the
 * host CSPRNG and assembled into a big integer; a candidate equal to 0 or ≥ `order`
 * is redrawn. SM2's n is almost exactly 2²⁵⁶ (hits on the first try), SM9's n ≈
 * 0.712 × 2²⁵⁶ (about 1.4 tries on average). The bias bound is ≈ `order / 2²⁵⁶`, well
 * below 2⁻¹²⁸.
 *
 * @param order The elliptic-curve subgroup order (SM2's n, SM9's BN256 n, …).
 * @param randomBytes The host CSPRNG byte source (injected by the caller so both sides
 *   behave identically).
 * @returns A big integer with `1 ≤ k < order`.
 */
export function scalarBelowFrom(order: bigint, randomBytes: (n: number) => Uint8Array): bigint {
  if (order <= 1n) throw new RangeError('randomScalarBelow: order must be > 1');
  // 用 256-bit 候选：4 个 64-bit big-endian limb。
  //
  // Use a 256-bit candidate: 4 big-endian 64-bit limbs.
  while (true) {
    const buf = randomBytes(32); // 256 bits
    let candidate = 0n;
    for (let i = 0; i < 32; i++) {
      candidate = (candidate << 8n) | BigInt(buf[i] ?? 0);
    }
    // 严格 < order（不允许 0）。
    //
    // Strictly < order (0 is not allowed either).
    if (candidate > 0n && candidate < order) return candidate;
    // 否则重抽；理论上不到一次。
    //
    // Otherwise draw again; in theory this happens less than once.
  }
}

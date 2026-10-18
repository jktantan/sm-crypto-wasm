/**
 * 宿主随机数包装（**浏览器版**）。
 *
 * 打包时由 package.json 的 `browser` 字段替换 `random.js`。存在的唯一理由是：
 * `node:crypto` 会让 Webpack 5 / esbuild / Rspack 在解析期构建失败。
 * 与宿主无关的拒绝采样逻辑在 `random.core.ts`。本文件**零 `node:*` 引用**。
 *
 * 安全姿态与 Node 版一致：**只认 `globalThis.crypto`，取不到就抛错
 * （fail-closed），绝不降级到非密码学随机源。**
 *
 * Host random-number wrapper (**browser version**).
 *
 * It replaces `random.js` at bundle time via the `browser` field in package.json. The
 * only reason it exists: `node:crypto` makes Webpack 5 / esbuild / Rspack fail at
 * resolve time. Host-independent rejection sampling lives in `random.core.ts`. This
 * file has **zero `node:*` references**.
 *
 * Security posture matches the Node version: **only `globalThis.crypto` is accepted,
 * and a failure to obtain it throws (fail-closed); it never degrades to a
 * non-cryptographic random source.**
 */

import { scalarBelowFrom } from './random.core.js';

/**
 * 解析宿主 CSPRNG。浏览器里只有 `globalThis.crypto` 一个来源，
 * 拿不到就抛错 —— 宁可不可用，也不用弱随机。
 *
 * Resolve the host CSPRNG. In the browser `globalThis.crypto` is the only source, and
 * failing to obtain it throws — better unavailable than weakly random.
 */
function resolveHostCrypto(): Crypto {
  const g = (globalThis as { crypto?: Crypto }).crypto;
  if (g && typeof g.getRandomValues === 'function') return g;
  throw new Error(
    'sm-crypto-wasm: 当前环境没有 WebCrypto（crypto.getRandomValues）。' +
      '浏览器需要安全上下文（https 或 localhost）；若已被移除或未提供，' +
      '请勿继续 —— 本库不会用非密码学随机源代替。',
  );
}

/** 宿主 CSPRNG 引用；模块加载时即解析。
 *
 * Reference to the host CSPRNG, resolved as soon as the module loads.
 */
const c: Crypto = resolveHostCrypto();

/**
 * 取 `n` 字节 CSPRNG 随机数。
 *
 * @param n 字节数，范围 `[0, 65536]`（WebCrypto `getRandomValues` 的规范上限）。
 * @returns 新分配的字节数组（拷贝）。
 * @throws RangeError n 不在范围内或不是整数。
 *
 * Draw `n` bytes from the CSPRNG.
 *
 * @param n Byte count, in `[0, 65536]` (the spec cap of WebCrypto
 *   `getRandomValues`).
 * @returns A newly allocated byte array (a copy).
 * @throws RangeError n is out of range or not an integer.
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
 * 在 `[1, order)` 区间均匀取一个随机标量（用于 SM2 / SM9 椭圆曲线 k）。
 *
 * @param order 椭圆曲线子群阶（如 SM2 的 n、SM9 的 BN256 n）。
 * @returns 满足 `1 ≤ k < order` 的大整数。
 *
 * Uniformly pick a random scalar in `[1, order)` (used for the SM2 / SM9 curve scalar
 * k).
 *
 * @param order The elliptic-curve subgroup order (SM2's n, SM9's BN256 n, …).
 * @returns A big integer with `1 ≤ k < order`.
 */
export function randomScalarBelow(order: bigint): bigint {
  return scalarBelowFrom(order, randomBytes);
}

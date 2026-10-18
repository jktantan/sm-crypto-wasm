/**
 * 宿主随机数包装（**Node 版**）。
 *
 * 浏览器打包时本文件被 `random.browser.ts` 替换（package.json 的 `browser` 字段），
 * 因为 `node:crypto` 会让 Webpack / esbuild / Rspack 在解析期构建失败。
 * 与宿主无关的拒绝采样逻辑在 `random.core.ts`。
 *
 * 设计要点（spec §9 安全姿态）：
 * - **永远走宿主 CSPRNG**：Node 19+ 用 `globalThis.crypto`，Node 18 回退
 *   `node:crypto` 的 `webcrypto`（`globalThis.crypto` 直到 Node 19 才默认暴露）。
 * - **取不到就抛错（fail-closed）**：绝不实例化本地 RNG，也绝不静默降级到
 *   非密码学随机源。
 * - **长度边界**：输入 `n ∈ [0, 65536]`，溢出抛 `RangeError`
 *   （65536 是 WebCrypto `getRandomValues` 的规范上限）。
 *
 * Host random-number wrapper (**Node version**).
 *
 * When bundling for the browser this file is replaced by `random.browser.ts` (the
 * `browser` field in package.json), because `node:crypto` makes Webpack / esbuild /
 * Rspack fail at resolve time. Host-independent rejection sampling lives in
 * `random.core.ts`.
 *
 * Design notes (spec §9 security posture):
 * - **Always use the host CSPRNG**: Node 19+ uses `globalThis.crypto`, Node 18 falls
 *   back to `node:crypto`'s `webcrypto` (`globalThis.crypto` is only exposed by
 *   default from Node 19 on).
 * - **Throw when unavailable (fail-closed)**: never instantiate a local RNG and never
 *   silently fall back to a non-cryptographic source.
 * - **Length boundary**: input `n ∈ [0, 65536]`; overflow throws `RangeError` (65536 is
 *   the spec cap of WebCrypto `getRandomValues`).
 */

import * as nodeCrypto from 'node:crypto';
import { scalarBelowFrom } from './random.core.js';

/**
 * 解析宿主 CSPRNG。**取不到就抛错，绝不静默降级到非密码学随机源。**
 *
 * - Node 19+：`globalThis.crypto`（WebCrypto）；
 * - Node 18：`node:crypto` 的 `webcrypto` —— `globalThis.crypto` 直到 Node 19 才
 *   默认暴露，Node 18 需要 `--experimental-global-webcrypto`，所以回退是必要的。
 *
 * Resolve the host CSPRNG. **Throw when unavailable; never silently fall back to a
 * non-cryptographic source.**
 *
 * - Node 19+: `globalThis.crypto` (WebCrypto);
 * - Node 18: `node:crypto`'s `webcrypto` — `globalThis.crypto` is only exposed by
 *   default from Node 19 on, and Node 18 needs `--experimental-global-webcrypto`, so
 *   the fallback is necessary.
 */
function resolveHostCrypto(): Crypto {
  const g = (globalThis as { crypto?: Crypto }).crypto;
  if (g && typeof g.getRandomValues === 'function') return g;
  const wc = (nodeCrypto as { webcrypto?: Crypto }).webcrypto;
  if (wc && typeof wc.getRandomValues === 'function') return wc;
  throw new Error(
    'sm-crypto-wasm: 找不到宿主 CSPRNG（需要 WebCrypto 的 crypto.getRandomValues）；' +
      'Node 18 请加 --experimental-global-webcrypto，或先 polyfill globalThis.crypto。',
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
 * @param n 字节数，范围 `[0, 65536]`。
 * @returns 新分配的字节数组（拷贝）。
 * @throws RangeError n 不在范围内或不是整数。
 *
 * Draw `n` bytes from the CSPRNG.
 *
 * @param n Byte count, in `[0, 65536]`.
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

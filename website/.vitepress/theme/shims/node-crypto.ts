/**
 * 浏览器构建用的 `node:crypto` 替身。
 *
 * 库的 `dist/runtime/random.js` 里有一句兜底导入：
 *
 * ```js
 * import { webcrypto } from 'node:crypto';
 * const c = globalThis.crypto ?? webcrypto;   // 浏览器 / Node 19+ 走左边
 * ```
 *
 * 浏览器里 `globalThis.crypto` 必然存在，等号右边那一支不会真正被求值；但 Rollup
 * 需要在解析阶段就能找到这个模块，否则会报
 * `"webcrypto" is not exported by "__vite-browser-external"`。
 * 这里把它接住 —— 只用于文档站构建，不改动库本身。
 */

/** 与 Node 内置模块同名的命名导出。 */
export const webcrypto = globalThis.crypto;

export default { webcrypto };

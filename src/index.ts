/**
 * sm-crypto-wasm 聚合出口（facade）。
 *
 * 用法：
 * ```ts
 * import { sm3, sm4, zuc, sm2 } from 'sm-crypto-wasm';
 *
 * await sm3.ensureLoaded();          // 首次用某算法前预热其 wasm
 * sm3.hash('hello');
 * ```
 *
 * 设计：每个算法是独立命名空间，各自暴露 `ensureLoaded()` + 业务函数。
 * wasm 按算法分包，调用哪个算法才加载哪个 wasm（见 `src/runtime/loadWasm.ts`
 * 的 memoization）。也支持子路径导入以进一步 tree-shake：
 * `import { encryptECB } from 'sm-crypto-wasm/sm4'`。
 *
 * spec/plan 对应：plan Task 12；spec §5 产物结构、§6 API。
 */

export * as cms from './cms/index.js';
export { bytesToHex, fromBytes, hexToBytes, toBytes } from './runtime/convert.js';
// 运行时工具（错误类型、编解码）也导出，便于调用方捕获本库错误。
export {
  CiphertextError,
  DecryptionError,
  InvalidCiphertextError,
  InvalidKeyError,
  InvalidPublicKeyError,
  isSmCryptoError,
  SmCryptoError,
} from './runtime/errors.js';
export { loadWasm, loadWasmSync } from './runtime/loadWasm.js';
export * as sm2 from './sm2/index.js';
export * as sm3 from './sm3/index.js';
export * as sm4 from './sm4/index.js';
export * as sm9 from './sm9/index.js';
export * as webcrypto from './webcrypto/index.js';
export * as x509 from './x509/index.js';
export * as zuc from './zuc/index.js';

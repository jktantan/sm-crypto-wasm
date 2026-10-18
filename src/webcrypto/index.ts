/**
 * WebCrypto 适配层（`sm-crypto-wasm/webcrypto`）。
 *
 * 这是一个**独立**的 `subtle` 对象，不是原生 `crypto.subtle` 的 polyfill：
 * 浏览器不允许注册自定义算法，第三方库也不会自动识别它。
 *
 * 范围：SM3、HMAC(SM3)、SM2、SM4-ECB/CBC/CTR/CFB/OFB/GCM。
 * 不做 JWK、deriveKey/deriveBits、wrapKey/unwrapKey、postMessage 克隆语义。
 */

export type { AlgorithmInput, NormalizedAlgorithm } from './algorithms.js';
export type { KeyAlgorithm, KeyMaterial, KeyProvider, KeyType, KeyUsage } from './cryptoKey.js';
export { CryptoKey } from './cryptoKey.js';
export type { SmCryptoKeyPair, SmKeyFormat } from './subtle.js';
export { subtle } from './subtle.js';

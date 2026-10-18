/**
 * WebCrypto 算法名归一化与参数校验。
 *
 * 算法名大小写不敏感；对外只暴露 `sm-crypto-wasm/webcrypto` 的一个精选子集：
 * SM3、HMAC(SM3)、SM2、SM4 的 ECB/CBC/CTR/CFB/OFB/GCM。
 *
 * WebCrypto algorithm-name normalization and parameter validation.
 *
 * Algorithm names are case-insensitive; only a curated subset is exposed through
 * `sm-crypto-wasm/webcrypto`: SM3, HMAC(SM3), SM2, and SM4 in
 * ECB/CBC/CTR/CFB/OFB/GCM.
 */

import { dataError, notSupported } from './errors.js';

/** 算法输入：字符串或带 `name` 的对象。
 *
 * Algorithm input: a string or an object carrying `name`.
 */
export type AlgorithmInput = string | { readonly name: string; readonly [key: string]: unknown };

/** 归一化后的算法。
 *
 * A normalized algorithm.
 */
export interface NormalizedAlgorithm {
  readonly name: string;
  readonly [key: string]: unknown;
}

/** 对外接受的算法名集合（已大写）。
 *
 * The set of accepted algorithm names (upper-cased).
 */
const SUPPORTED = new Set([
  'SM3',
  'HMAC',
  'SM2',
  'SM4-ECB',
  'SM4-CBC',
  'SM4-CTR',
  'SM4-CFB',
  'SM4-OFB',
  'SM4-GCM',
]);

/** SM4 分组密码模式集合，供 `isSm4` / `isSymmetric` 共用。
 *
 * The SM4 block-cipher mode set, shared by `isSm4` / `isSymmetric`.
 */
const SM4_NAMES = new Set(['SM4-ECB', 'SM4-CBC', 'SM4-CTR', 'SM4-CFB', 'SM4-OFB', 'SM4-GCM']);

/**
 * 归一化算法名并校验支持性。
 *
 * @throws DOMException `NotSupportedError` / `TypeError`
 *
 * Normalize the algorithm name and check that it is supported.
 *
 * @throws DOMException `NotSupportedError` / `TypeError`
 */
export function normalizeAlgorithm(input: AlgorithmInput): NormalizedAlgorithm {
  if (typeof input === 'string') {
    const name = input.toUpperCase();
    if (!SUPPORTED.has(name)) {
      throw notSupported(`unsupported algorithm "${input}"`);
    }
    return { name };
  }
  if (input === null || typeof input !== 'object' || typeof input.name !== 'string') {
    throw new TypeError('algorithm must be a string or an object with a name');
  }
  const name = input.name.toUpperCase();
  if (!SUPPORTED.has(name)) {
    throw notSupported(`unsupported algorithm "${input.name}"`);
  }
  return { ...input, name };
}

/** 是否为 SM4 系列算法。
 *
 * Whether the name is one of the SM4 family.
 */
export function isSm4(name: string): boolean {
  return SM4_NAMES.has(name);
}

/** 是否为 AES 风格的对称算法（SM4）。
 *
 * Whether the name is an AES-style symmetric algorithm (SM4).
 */
export function isSymmetric(name: string): boolean {
  return SM4_NAMES.has(name);
}

/** BufferSource → 独立 Uint8Array（拷贝）。
 *
 * BufferSource → standalone Uint8Array (a copy).
 */
export function bufferSourceBytes(
  value: ArrayBuffer | ArrayBufferView | undefined,
  label: string,
  required = true,
): Uint8Array {
  if (value === undefined) {
    if (required) throw dataError(`${label} is required`);
    return new Uint8Array(0);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  }
  throw dataError(`${label} must be an ArrayBuffer or ArrayBufferView`);
}

/** 必需的 IV。
 *
 * The required IV.
 */
export function requireIv(algorithm: NormalizedAlgorithm): Uint8Array {
  const iv = bufferSourceBytes(
    algorithm.iv as ArrayBuffer | ArrayBufferView | undefined,
    'iv',
    true,
  );
  if (iv.length === 0) throw dataError('iv must not be empty');
  return iv;
}

/** 可选的 additionalData。
 *
 * The optional additionalData (AAD).
 */
export function optionalAad(algorithm: NormalizedAlgorithm): Uint8Array {
  return bufferSourceBytes(
    algorithm.additionalData as ArrayBuffer | ArrayBufferView | undefined,
    'additionalData',
    false,
  );
}

/** GCM 的 tagLength：只支持 128。
 *
 * tagLength for GCM: only 128 is supported.
 */
export function requireGcmTagLength(algorithm: NormalizedAlgorithm): 128 {
  const tagLength = algorithm.tagLength ?? 128;
  if (!Number.isInteger(tagLength) || tagLength !== 128) {
    throw notSupported(`SM4-GCM tagLength ${String(tagLength)} is not supported (only 128)`);
  }
  return 128;
}

/** SM4-CTR 的 length：只支持 128。
 *
 * length for SM4-CTR: only 128 is supported.
 */
export function requireCtrLength(algorithm: NormalizedAlgorithm): 128 {
  const length = algorithm.length ?? 128;
  if (!Number.isInteger(length) || length !== 128) {
    throw notSupported(`SM4-CTR length ${String(length)} is not supported (only 128)`);
  }
  return 128;
}

/** SM4 密钥长度：固定 128。
 *
 * SM4 key length: fixed at 128.
 */
export function requireAesLength(algorithm: NormalizedAlgorithm): 128 {
  const length = algorithm.length ?? 128;
  if (!Number.isInteger(length) || length !== 128) {
    throw notSupported(`SM4 key length ${String(length)} is not supported (only 128)`);
  }
  return 128;
}

/** HMAC 的 hash 参数归一化为 SM3。
 *
 * Normalize the HMAC `hash` parameter to SM3.
 */
export function hashName(hash: unknown): 'SM3' {
  if (hash === undefined) throw dataError('HMAC requires a hash parameter');
  const name =
    typeof hash === 'string'
      ? hash.toUpperCase()
      : typeof hash === 'object' && hash !== null && 'name' in hash
        ? String((hash as { name: unknown }).name).toUpperCase()
        : '';
  if (name !== 'SM3') throw notSupported(`HMAC hash "${name}" is not supported (only SM3)`);
  return 'SM3';
}

/** SM2 的可选 userID。
 *
 * The optional SM2 userID.
 */
export function optionalUserId(algorithm: NormalizedAlgorithm): Uint8Array | undefined {
  const raw = algorithm.userID;
  if (raw === undefined) return undefined;
  if (!(raw instanceof Uint8Array)) throw dataError('SM2 userID must be a Uint8Array');
  return new Uint8Array(raw);
}

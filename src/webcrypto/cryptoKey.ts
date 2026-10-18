/**
 * WebCrypto 风格的 `CryptoKey`。
 *
 * 密钥材料放在模块级 `WeakMap` 中，对象本身只暴露只读元数据；这样：
 * - 无法通过序列化/枚举把私钥带出去；
 * - 将来接入 HSM/RemoteSigner 时可把材料换成 `provider`，公共 API 不变。
 *
 * A WebCrypto-style `CryptoKey`.
 *
 * Key material lives in a module-level `WeakMap` and the object itself only exposes
 * read-only metadata, so that:
 * - a private key cannot be exfiltrated through serialization or enumeration;
 * - a future HSM/RemoteSigner can swap the material for a `provider` without changing
 *   the public API.
 */

import { invalidAccess, notSupported } from './errors.js';

/** 密钥类型。
 *
 * Key type.
 */
export type KeyType = 'secret' | 'public' | 'private';

/** WebCrypto 密钥用途。
 *
 * WebCrypto key usages.
 */
export type KeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'deriveKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'unwrapKey';

/** 已知的全部密钥用途（校验 `keyUsages` 用）。
 *
 * All known key usages (used to validate `keyUsages`).
 */
const ALL_USAGES: readonly KeyUsage[] = [
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveKey',
  'deriveBits',
  'wrapKey',
  'unwrapKey',
];

/** 密钥算法元数据（只读）。
 *
 * Key algorithm metadata (read-only).
 */
export interface KeyAlgorithm {
  readonly name: string;
  readonly [key: string]: unknown;
}

/**
 * 将来的外部密钥提供者（HSM / RemoteSigner）。
 *
 * v1 不实现；`KeyMaterial` 已按联合类型预留，后续无需改公共 API。
 *
 * Future external key provider (HSM / RemoteSigner).
 *
 * Not implemented in v1; `KeyMaterial` already models it as a union member, so the
 * public API will not need to change later.
 */
export interface KeyProvider {
  sign?(algorithm: KeyAlgorithm, data: Uint8Array): Uint8Array | Promise<Uint8Array>;
  verify?(
    algorithm: KeyAlgorithm,
    signature: Uint8Array,
    data: Uint8Array,
  ): boolean | Promise<boolean>;
  encrypt?(algorithm: KeyAlgorithm, data: Uint8Array): Uint8Array | Promise<Uint8Array>;
  decrypt?(algorithm: KeyAlgorithm, data: Uint8Array): Uint8Array | Promise<Uint8Array>;
  exportKey?(format: string): Uint8Array | Promise<Uint8Array>;
}

/** 密钥材料。v1 只创建 `bytes`；`provider` 为将来预留。
 *
 * Key material. v1 only creates `bytes`; `provider` is reserved for the future.
 */
export type KeyMaterial =
  | { readonly kind: 'bytes'; readonly bytes: Uint8Array }
  | { readonly kind: 'provider'; readonly provider: KeyProvider };

/** 密钥对象 → 密钥材料的映射。放在模块级 WeakMap，不随对象枚举/序列化泄出。
 *
 * Key object → key material map. Held in a module-level WeakMap so it never leaks
 * through object enumeration or serialization.
 */
const MATERIAL = new WeakMap<CryptoKey, KeyMaterial>();

/** WebCrypto 风格的密钥对象。
 *
 * A WebCrypto-style key object.
 */
export class CryptoKey {
  readonly type: KeyType;
  readonly extractable: boolean;
  readonly algorithm: KeyAlgorithm;
  readonly usages: readonly KeyUsage[];

  /**
   * 构造只含元数据的密钥；密钥材料由 `MATERIAL` 另行绑定。
   *
   * Build a key holding metadata only; the key material is bound separately in
   * `MATERIAL`.
   */
  constructor(
    type: KeyType,
    algorithm: KeyAlgorithm,
    extractable: boolean,
    usages: readonly KeyUsage[],
  ) {
    this.type = type;
    this.extractable = extractable;
    this.algorithm = Object.freeze({ ...algorithm });
    this.usages = Object.freeze([...usages]);
  }
}

/** 创建带字节材料的密钥（内部使用）。
 *
 * Create a key backed by byte material (internal use).
 */
export function createBytesKey(
  type: KeyType,
  algorithm: KeyAlgorithm,
  extractable: boolean,
  usages: readonly KeyUsage[],
  bytes: Uint8Array,
): CryptoKey {
  const key = new CryptoKey(type, algorithm, extractable, usages);
  MATERIAL.set(key, { kind: 'bytes', bytes: new Uint8Array(bytes) });
  return key;
}

/** 创建带外部 provider 的密钥（v1 预留，内部使用）。
 *
 * Create a key backed by an external provider (reserved for v1, internal use).
 */
export function createProviderKey(
  type: KeyType,
  algorithm: KeyAlgorithm,
  extractable: boolean,
  usages: readonly KeyUsage[],
  provider: KeyProvider,
): CryptoKey {
  const key = new CryptoKey(type, algorithm, extractable, usages);
  MATERIAL.set(key, { kind: 'provider', provider });
  return key;
}

/** 读取密钥材料（内部使用）。
 *
 * Read the key material (internal use).
 */
export function getKeyMaterial(key: CryptoKey): KeyMaterial {
  const material = MATERIAL.get(key);
  if (material === undefined) {
    throw invalidAccess('key has no material (was it created by this module?)');
  }
  return material;
}

/** 读取字节材料（内部使用）；provider 材料暂不支持同步读取。
 *
 * Read the byte material (internal use); synchronously reading provider material is
 * not supported yet.
 */
export function getKeyBytes(key: CryptoKey): Uint8Array {
  const material = getKeyMaterial(key);
  if (material.kind !== 'bytes') {
    throw notSupported('external key providers are not supported yet');
  }
  return material.bytes;
}

/** 校验密钥类型。
 *
 * Validate the key type.
 */
export function assertKeyType(
  key: unknown,
  expected: KeyType,
  operation: string,
): asserts key is CryptoKey {
  if (!(key instanceof CryptoKey)) {
    throw new TypeError(`${operation}: key must be a CryptoKey`);
  }
  if (key.type !== expected) {
    throw invalidAccess(`${operation} requires a ${expected} key, got ${key.type}`);
  }
}

/** 校验密钥用途。
 *
 * Validate the key usage.
 */
export function assertUsage(key: CryptoKey, usage: KeyUsage, operation: string): void {
  if (!key.usages.includes(usage)) {
    throw invalidAccess(`${operation}: key does not allow "${usage}"`);
  }
}

/** 校验密钥算法名。
 *
 * Validate the key algorithm name.
 */
export function assertKeyAlgorithm(key: CryptoKey, name: string, operation: string): void {
  if (key.algorithm.name !== name) {
    throw invalidAccess(`${operation}: key algorithm is ${key.algorithm.name}, expected ${name}`);
  }
}

/** 校验 usage 列表合法（未知值抛 SyntaxError）。
 *
 * Validate the usage list (an unknown value throws SyntaxError).
 */
export function normalizeUsages(usages: readonly string[] | undefined): KeyUsage[] {
  if (usages === undefined) return [];
  if (!Array.isArray(usages)) throw new TypeError('keyUsages must be an array');
  const out: KeyUsage[] = [];
  for (const usage of usages) {
    if (!ALL_USAGES.includes(usage as KeyUsage)) {
      throw new DOMException(`unknown key usage "${usage}"`, 'SyntaxError');
    }
    if (!out.includes(usage as KeyUsage)) out.push(usage as KeyUsage);
  }
  return out;
}

/** 检查 usage 是否属于允许集合；不允许时抛 SyntaxError。
 *
 * Check that each usage belongs to the allowed set; a disallowed one throws
 * SyntaxError.
 */
export function assertUsagesAllowed(
  usages: readonly KeyUsage[],
  allowed: readonly KeyUsage[],
  algorithm: string,
): void {
  for (const usage of usages) {
    if (!allowed.includes(usage)) {
      throw new DOMException(`usage "${usage}" is not valid for ${algorithm}`, 'SyntaxError');
    }
  }
}

/** 取交集（保持 requesting 顺序）。
 *
 * Intersect the lists (keeping the order of `usages`).
 */
export function filterUsages(
  usages: readonly KeyUsage[],
  allowed: readonly KeyUsage[],
): KeyUsage[] {
  return usages.filter((usage) => allowed.includes(usage));
}

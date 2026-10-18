/**
 * `crypto.subtle` 风格的 SM2 / SM3 / SM4 适配层。
 *
 * 注意：这是**独立对象**，不是原生 `crypto.subtle` 的 polyfill —— 浏览器
 * 不允许注册自定义算法，生态库也不会自动识别它。
 *
 * 所有方法都是异步的（WebCrypto 语义），内部调用仍是同步的 wasm 计算；
 * 首次使用时按算法自动 `ensureLoaded()`。
 *
 * A `crypto.subtle`-style adapter for SM2 / SM3 / SM4.
 *
 * Note: this is a **standalone object**, not a polyfill of the native `crypto.subtle` —
 * browsers do not allow registering custom algorithms, and ecosystem libraries will not
 * recognize it automatically either.
 *
 * All methods are async (WebCrypto semantics) while the internal computation is still
 * the synchronous wasm; the first use triggers `ensureLoaded()` for the algorithm
 * involved.
 */

import {
  encodeSm2PrivateKeyDer,
  encodeSm2PublicKeyDer,
  parseSm2PrivateKeyDer,
  parseSm2PrivateKeyPem,
  parseSm2PublicKeyDer,
  parseSm2PublicKeyPem,
} from '../pem/sm2.js';
import { hexToBytes } from '../runtime/convert.js';
import { randomBytes } from '../runtime/random.js';
import * as sm2 from '../sm2/index.js';
import * as sm3 from '../sm3/index.js';
import * as sm4 from '../sm4/index.js';
import {
  type AlgorithmInput,
  bufferSourceBytes,
  hashName,
  isSm4,
  normalizeAlgorithm,
  optionalAad,
  optionalUserId,
  requireAesLength,
  requireCtrLength,
  requireGcmTagLength,
  requireIv,
} from './algorithms.js';
import {
  assertKeyAlgorithm,
  assertKeyType,
  assertUsage,
  assertUsagesAllowed,
  CryptoKey,
  createBytesKey,
  filterUsages,
  getKeyBytes,
  type KeyUsage,
  normalizeUsages,
} from './cryptoKey.js';
import { dataError, invalidAccess, notSupported, toDOMException } from './errors.js';

/** 密钥对（结构兼容 WebCrypto 的 `CryptoKeyPair`）。
 *
 * A key pair (structurally compatible with WebCrypto's `CryptoKeyPair`).
 */
export interface SmCryptoKeyPair {
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
}

/** 支持的密钥格式。JWK 不在范围内。
 *
 * Supported key formats. JWK is out of scope.
 */
export type SmKeyFormat = 'raw' | 'pkcs8' | 'spki' | 'jwk';

/** 各算法允许的密钥用途：私钥签名/解密，公钥验签/加密，HMAC 与 SM4 对称用途。
 *
 * Key usages allowed per algorithm: sign/decrypt for a private key, verify/encrypt for
 * a public key, and the symmetric usages for HMAC and SM4.
 */
const SM2_PRIVATE_USAGES: readonly KeyUsage[] = ['sign', 'decrypt'];
const SM2_PUBLIC_USAGES: readonly KeyUsage[] = ['verify', 'encrypt'];
const HMAC_USAGES: readonly KeyUsage[] = ['sign', 'verify'];
const SM4_USAGES: readonly KeyUsage[] = ['encrypt', 'decrypt'];

/** `sm-crypto-wasm/webcrypto` 的 `subtle` 对象。
 *
 * The `subtle` object of `sm-crypto-wasm/webcrypto`.
 */
export const subtle = {
  /**
   * 摘要。仅支持 `{ name: 'SM3' }`。
   *
   * Digest. Only `{ name: 'SM3' }` is supported.
   */
  async digest(
    algorithm: AlgorithmInput,
    data: ArrayBuffer | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    try {
      const alg = normalizeAlgorithm(algorithm);
      if (alg.name !== 'SM3') throw notSupported(`digest does not support ${alg.name}`);
      const bytes = bufferSourceBytes(data, 'data');
      await sm3.ensureLoaded();
      return toArrayBuffer(hexToBytes(sm3.hash(bytes), 'digest'));
    } catch (err) {
      throw toDOMException(err);
    }
  },

  /**
   * 生成密钥。
   *
   * - `{ name: 'SM2' }` → `{ privateKey, publicKey }`
   * - `{ name: 'HMAC', hash: 'SM3', length?: bits }` → secret key
   * - `{ name: 'SM4-*', length: 128 }` → secret key
   *
   * Generate a key.
   *
   * - `{ name: 'SM2' }` → `{ privateKey, publicKey }`
   * - `{ name: 'HMAC', hash: 'SM3', length?: bits }` → secret key
   * - `{ name: 'SM4-*', length: 128 }` → secret key
   */
  async generateKey(
    algorithm: AlgorithmInput,
    extractable: boolean,
    keyUsages: readonly string[],
  ): Promise<CryptoKey | SmCryptoKeyPair> {
    try {
      const alg = normalizeAlgorithm(algorithm);
      const usages = normalizeUsages(keyUsages);

      if (alg.name === 'SM2') {
        await sm2.ensureLoaded();
        const pair = await sm2.generateKeyPair();
        // 复用既有 PEM 解析器，不重复实现 PEM 解包。
        //
        // Reuse the existing PEM parser instead of reimplementing PEM unwrapping.
        const priv = new Uint8Array(parseSm2PrivateKeyPem(pair.privateKeyPem));
        const pub = new Uint8Array(parseSm2PublicKeyPem(pair.publicKeyPem));
        return {
          privateKey: createBytesKey(
            'private',
            { name: 'SM2' },
            extractable,
            filterUsages(usages, SM2_PRIVATE_USAGES),
            priv,
          ),
          publicKey: createBytesKey(
            'public',
            { name: 'SM2' },
            extractable,
            filterUsages(usages, SM2_PUBLIC_USAGES),
            pub,
          ),
        };
      }

      if (alg.name === 'HMAC') {
        await sm3.ensureLoaded();
        assertUsagesAllowed(usages, HMAC_USAGES, 'HMAC');
        const hash = hashName(alg.hash);
        const rawLength = alg.length;
        const lengthBits = rawLength === undefined ? 256 : rawLength;
        if (
          typeof lengthBits !== 'number' ||
          !Number.isInteger(lengthBits) ||
          lengthBits <= 0 ||
          lengthBits % 8 !== 0
        ) {
          throw dataError('HMAC length must be a positive multiple of 8 bits');
        }
        return createBytesKey(
          'secret',
          { name: 'HMAC', hash: { name: hash }, length: lengthBits },
          extractable,
          usages,
          randomBytes(lengthBits / 8),
        );
      }

      if (isSm4(alg.name)) {
        requireAesLength(alg);
        assertUsagesAllowed(usages, SM4_USAGES, alg.name);
        return createBytesKey(
          'secret',
          { name: alg.name, length: 128 },
          extractable,
          usages,
          randomBytes(16),
        );
      }

      throw notSupported(`generateKey does not support ${alg.name}`);
    } catch (err) {
      throw toDOMException(err);
    }
  },

  /**
   * 导入密钥。
   *
   * - `raw`：HMAC / SM4
   * - `pkcs8`：SM2 私钥 DER
   * - `spki`：SM2 公钥 DER
   *
   * Import a key.
   *
   * - `raw`: HMAC / SM4
   * - `pkcs8`: SM2 private key DER
   * - `spki`: SM2 public key DER
   */
  async importKey(
    format: SmKeyFormat,
    keyData: ArrayBuffer | ArrayBufferView,
    algorithm: AlgorithmInput,
    extractable: boolean,
    keyUsages: readonly string[],
  ): Promise<CryptoKey> {
    try {
      if (format === 'jwk') throw notSupported('JWK is not supported');
      if (format !== 'raw' && format !== 'pkcs8' && format !== 'spki') {
        throw notSupported(`unsupported key format "${String(format)}"`);
      }
      const alg = normalizeAlgorithm(algorithm);
      const usages = normalizeUsages(keyUsages);
      const bytes = keyDataBytes(keyData);

      if (format === 'raw') {
        if (alg.name === 'HMAC') {
          assertUsagesAllowed(usages, HMAC_USAGES, 'HMAC');
          const hash = hashName(alg.hash);
          return createBytesKey(
            'secret',
            { name: 'HMAC', hash: { name: hash }, length: bytes.length * 8 },
            extractable,
            usages,
            bytes,
          );
        }
        if (isSm4(alg.name)) {
          requireAesLength(alg);
          if (bytes.length !== 16) throw dataError('SM4 key must be 16 bytes');
          assertUsagesAllowed(usages, SM4_USAGES, alg.name);
          return createBytesKey(
            'secret',
            { name: alg.name, length: 128 },
            extractable,
            usages,
            bytes,
          );
        }
        throw notSupported(`importKey('raw') does not support ${alg.name}`);
      }

      if (alg.name !== 'SM2') {
        throw notSupported(`importKey('${format}') only supports SM2`);
      }
      if (format === 'pkcs8') {
        return createBytesKey(
          'private',
          { name: 'SM2' },
          extractable,
          filterUsages(usages, SM2_PRIVATE_USAGES),
          parseSm2PrivateKeyDer(bytes),
        );
      }
      return createBytesKey(
        'public',
        { name: 'SM2' },
        extractable,
        filterUsages(usages, SM2_PUBLIC_USAGES),
        parseSm2PublicKeyDer(bytes),
      );
    } catch (err) {
      throw toDOMException(err);
    }
  },

  /**
   * 导出密钥。
   *
   * `extractable === false` 时抛 `InvalidAccessError`（红线 #7）。
   *
   * Export a key.
   *
   * Throws `InvalidAccessError` when `extractable === false` (red line #7).
   */
  async exportKey(format: SmKeyFormat, key: CryptoKey): Promise<ArrayBuffer> {
    try {
      if (!(key instanceof CryptoKey)) throw new TypeError('exportKey: key must be a CryptoKey');
      if (!key.extractable) throw invalidAccess('exportKey: key is not extractable');
      if (format === 'raw') {
        if (key.type !== 'secret') {
          throw invalidAccess('exportKey: raw export requires a secret key');
        }
        return toArrayBuffer(getKeyBytes(key));
      }
      if (format === 'pkcs8') {
        if (key.type !== 'private' || key.algorithm.name !== 'SM2') {
          throw invalidAccess('exportKey: pkcs8 export requires an SM2 private key');
        }
        return toArrayBuffer(encodeSm2PrivateKeyDer(getKeyBytes(key)));
      }
      if (format === 'spki') {
        if (key.type !== 'public' || key.algorithm.name !== 'SM2') {
          throw invalidAccess('exportKey: spki export requires an SM2 public key');
        }
        return toArrayBuffer(encodeSm2PublicKeyDer(getKeyBytes(key)));
      }
      throw notSupported(`exportKey format "${String(format)}" is not supported`);
    } catch (err) {
      throw toDOMException(err);
    }
  },

  /**
   * 签名。
   *
   * - `HMAC` + `hash: 'SM3'`
   * - `SM2`（64 字节 `r ‖ s`，与 `sm2.sign` 一致）
   *
   * Sign.
   *
   * - `HMAC` + `hash: 'SM3'`
   * - `SM2` (64 bytes `r ‖ s`, matching `sm2.sign`)
   */
  async sign(
    algorithm: AlgorithmInput,
    key: CryptoKey,
    data: ArrayBuffer | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    try {
      const alg = normalizeAlgorithm(algorithm);
      const bytes = bufferSourceBytes(data, 'data');

      if (alg.name === 'HMAC') {
        assertKeyType(key, 'secret', 'sign');
        assertUsage(key, 'sign', 'sign');
        assertKeyAlgorithm(key, 'HMAC', 'sign');
        assertHmacHash(key);
        await sm3.ensureLoaded();
        return toArrayBuffer(hexToBytes(sm3.hmac(getKeyBytes(key), bytes), 'signature'));
      }

      if (alg.name === 'SM2') {
        assertKeyType(key, 'private', 'sign');
        assertUsage(key, 'sign', 'sign');
        assertKeyAlgorithm(key, 'SM2', 'sign');
        await sm2.ensureLoaded();
        const userID = optionalUserId(alg);
        const signature =
          userID === undefined
            ? sm2.sign(getKeyBytes(key), bytes)
            : sm2.signWithID(getKeyBytes(key), bytes, userID);
        return toArrayBuffer(hexToBytes(signature, 'signature'));
      }

      throw notSupported(`sign does not support ${alg.name}`);
    } catch (err) {
      throw toDOMException(err);
    }
  },

  /**
   * 验签。
   *
   * Verify a signature.
   */
  async verify(
    algorithm: AlgorithmInput,
    key: CryptoKey,
    signature: ArrayBuffer | ArrayBufferView,
    data: ArrayBuffer | ArrayBufferView,
  ): Promise<boolean> {
    try {
      const alg = normalizeAlgorithm(algorithm);
      const bytes = bufferSourceBytes(data, 'data');
      const signatureBytes = bufferSourceBytes(signature, 'signature');

      if (alg.name === 'HMAC') {
        assertKeyType(key, 'secret', 'verify');
        assertUsage(key, 'verify', 'verify');
        assertKeyAlgorithm(key, 'HMAC', 'verify');
        assertHmacHash(key);
        await sm3.ensureLoaded();
        const expected = hexToBytes(sm3.hmac(getKeyBytes(key), bytes), 'signature');
        return constantTimeEqual(expected, signatureBytes);
      }

      if (alg.name === 'SM2') {
        assertKeyType(key, 'public', 'verify');
        assertUsage(key, 'verify', 'verify');
        assertKeyAlgorithm(key, 'SM2', 'verify');
        if (signatureBytes.length !== 64) {
          throw dataError('SM2 signature must be 64 bytes (r || s)');
        }
        await sm2.ensureLoaded();
        const userID = optionalUserId(alg);
        return userID === undefined
          ? sm2.verify(getKeyBytes(key), bytes, signatureBytes)
          : sm2.verifyWithID(getKeyBytes(key), bytes, signatureBytes, userID);
      }

      throw notSupported(`verify does not support ${alg.name}`);
    } catch (err) {
      throw toDOMException(err);
    }
  },

  /**
   * 加密。
   *
   * SM4-GCM 输出 `ciphertext ‖ tag`（tag 在尾部，与原生 AES-GCM 一致）。
   *
   * Encrypt.
   *
   * SM4-GCM outputs `ciphertext ‖ tag` (the tag at the end, matching native AES-GCM).
   */
  async encrypt(
    algorithm: AlgorithmInput,
    key: CryptoKey,
    data: ArrayBuffer | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    try {
      const alg = normalizeAlgorithm(algorithm);
      const bytes = bufferSourceBytes(data, 'data');
      assertKeyType(key, 'secret', 'encrypt');
      assertUsage(key, 'encrypt', 'encrypt');
      assertKeyAlgorithm(key, alg.name, 'encrypt');
      await sm4.ensureLoaded();
      const k = getKeyBytes(key);

      switch (alg.name) {
        case 'SM4-GCM': {
          requireGcmTagLength(alg);
          const iv = requireIv(alg);
          const aad = optionalAad(alg);
          const { ct, tag } = sm4.encryptGCM(k, iv, bytes, aad);
          return toArrayBuffer(concat(hexToBytes(ct, 'ciphertext'), hexToBytes(tag, 'tag')));
        }
        case 'SM4-CBC':
          return toArrayBuffer(hexToBytes(sm4.encryptCBC(k, requireIv(alg), bytes), 'ciphertext'));
        case 'SM4-CTR': {
          requireCtrLength(alg);
          return toArrayBuffer(hexToBytes(sm4.cryptCTR(k, requireIv(alg), bytes), 'ciphertext'));
        }
        case 'SM4-CFB':
          return toArrayBuffer(hexToBytes(sm4.encryptCFB(k, requireIv(alg), bytes), 'ciphertext'));
        case 'SM4-OFB':
          return toArrayBuffer(hexToBytes(sm4.cryptOFB(k, requireIv(alg), bytes), 'ciphertext'));
        case 'SM4-ECB':
          return toArrayBuffer(hexToBytes(sm4.encryptECB(k, bytes), 'ciphertext'));
        default:
          throw notSupported(`encrypt does not support ${alg.name}`);
      }
    } catch (err) {
      throw toDOMException(err);
    }
  },

  /**
   * 解密。
   *
   * Decrypt.
   */
  async decrypt(
    algorithm: AlgorithmInput,
    key: CryptoKey,
    data: ArrayBuffer | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    try {
      const alg = normalizeAlgorithm(algorithm);
      const bytes = bufferSourceBytes(data, 'data');
      assertKeyType(key, 'secret', 'decrypt');
      assertUsage(key, 'decrypt', 'decrypt');
      assertKeyAlgorithm(key, alg.name, 'decrypt');
      await sm4.ensureLoaded();
      const k = getKeyBytes(key);

      switch (alg.name) {
        case 'SM4-GCM': {
          requireGcmTagLength(alg);
          if (bytes.length < 16) throw dataError('SM4-GCM ciphertext is shorter than the tag');
          const iv = requireIv(alg);
          const aad = optionalAad(alg);
          const ct = bytes.subarray(0, bytes.length - 16);
          const tag = bytes.subarray(bytes.length - 16);
          const plaintext = sm4.decryptGCM(k, iv, ct, tag, { aad });
          return toArrayBuffer(hexToBytes(plaintext, 'plaintext'));
        }
        case 'SM4-CBC':
          return toArrayBuffer(hexToBytes(sm4.decryptCBC(k, requireIv(alg), bytes), 'plaintext'));
        case 'SM4-CTR': {
          requireCtrLength(alg);
          return toArrayBuffer(hexToBytes(sm4.cryptCTR(k, requireIv(alg), bytes), 'plaintext'));
        }
        case 'SM4-CFB':
          return toArrayBuffer(hexToBytes(sm4.decryptCFB(k, requireIv(alg), bytes), 'plaintext'));
        case 'SM4-OFB':
          return toArrayBuffer(hexToBytes(sm4.cryptOFB(k, requireIv(alg), bytes), 'plaintext'));
        case 'SM4-ECB':
          return toArrayBuffer(hexToBytes(sm4.decryptECB(k, bytes), 'plaintext'));
        default:
          throw notSupported(`decrypt does not support ${alg.name}`);
      }
    } catch (err) {
      throw toDOMException(err);
    }
  },
};

// ---------- 内部 ----------
//
// ---------- Internals ----------

// 校验 HMAC 的 hash 参数。
//
// Validates the HMAC hash parameter.
function assertHmacHash(key: CryptoKey): void {
  const hash = key.algorithm.hash as { readonly name?: unknown } | undefined;
  if (hash?.name !== 'SM3') {
    throw invalidAccess('HMAC key is not bound to SM3');
  }
}

// 把 keyData 输入转为字节。
//
// Normalizes keyData input to bytes.
function keyDataBytes(keyData: unknown): Uint8Array {
  if (keyData instanceof ArrayBuffer) return new Uint8Array(keyData.slice(0));
  if (ArrayBuffer.isView(keyData)) {
    return new Uint8Array(keyData.buffer, keyData.byteOffset, keyData.byteLength).slice();
  }
  throw dataError('keyData must be an ArrayBuffer or ArrayBufferView');
}

// 把 Uint8Array 转为独立 ArrayBuffer。
//
// Converts a Uint8Array to a standalone ArrayBuffer.
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

// 拼接两个字节数组。
//
// Concatenates two byte arrays.
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// 常量时间比较两个字节数组。
//
// Compares two byte arrays in constant time.
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

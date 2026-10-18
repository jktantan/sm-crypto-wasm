/**
 * SM2 密钥输入归一化：把 hex / 裸字节 / PEM 统一成运算层需要的字节。
 *
 * - 私钥 → 32 字节 `d`：裸 32 字节，或 PKCS#8（`PRIVATE KEY`）/
 *   SEC1（`EC PRIVATE KEY`）PEM。
 * - 公钥 → 64 字节 `x || y`：裸 64 / 65 字节（含可选 `04` 前缀），
 *   或 SPKI（`PUBLIC KEY`）PEM。
 *
 * 供 `./index`（sign/verify/encrypt/decrypt/getPublicKey）与 `./exchange`
 * 共用，避免两处各写一份嗅探逻辑。
 *
 * SM2 key-input normalisation: unify hex / raw bytes / PEM into the bytes the
 * arithmetic layer needs.
 *
 * - Private key → 32-byte `d`: either a raw 32-byte value, or a PKCS#8
 *   (`PRIVATE KEY`) / SEC1 (`EC PRIVATE KEY`) PEM.
 * - Public key → 64-byte `x || y`: either raw 64 / 65 bytes (with an optional
 *   `04` prefix), or an SPKI (`PUBLIC KEY`) PEM.
 *
 * Shared by `./index` (sign/verify/encrypt/decrypt/getPublicKey) and `./exchange`
 * so the sniffing logic is not written twice.
 */

import { parseSm2PrivateKeyPem, parseSm2PublicKeyPem } from '../pem/sm2.js';
import { toBytes } from '../runtime/convert.js';
import { InvalidKeyError } from '../runtime/errors.js';

/**
 * 是否为 PEM 文本（而非裸字节 / hex）。
 *
 * Whether the input is PEM text (rather than raw bytes / hex).
 */
export function isPem(input: string | Uint8Array): input is string {
  return typeof input === 'string' && input.startsWith('-----BEGIN');
}

/**
 * 归一化私钥为 32 字节 `d`。
 *
 * Normalise a private key to the 32-byte `d`.
 *
 * @param input Raw bytes, hex or a PKCS#8 / SEC1 PEM.
 * @param label Label used in error messages (defaults to `privateKey`).
 * @returns The 32-byte private scalar.
 */
export function toPrivateKeyBytes(input: string | Uint8Array, label = 'privateKey'): Uint8Array {
  if (isPem(input)) return parseSm2PrivateKeyPem(input);
  const b = toBytes(input, label);
  if (b.length !== 32) throw new InvalidKeyError(`sm2: ${label} must be 32 bytes`);
  return b;
}

/**
 * 归一化公钥为 64 字节 `x || y`。
 *
 * Normalise a public key to the 64-byte `x || y`.
 *
 * Accepts a raw 64-byte point, 65 bytes with a leading `04`, or an SPKI PEM.
 *
 * @param input Raw bytes, hex or an SPKI PEM.
 * @param label Label used in error messages (defaults to `publicKey`).
 * @returns The 64-byte uncompressed point without the prefix byte.
 */
export function toPublicKeyBytes(input: string | Uint8Array, label = 'publicKey'): Uint8Array {
  if (isPem(input)) return parseSm2PublicKeyPem(input).subarray(1);
  let b = toBytes(input, label);
  if (b.length === 65 && b[0] === 0x04) b = b.subarray(1);
  if (b.length !== 64) throw new InvalidKeyError(`sm2: ${label} must be 64 or 65 bytes`);
  return b;
}

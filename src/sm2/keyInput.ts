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
 */
import { toBytes } from '../runtime/convert.js';
import { parseSm2PrivateKeyPem, parseSm2PublicKeyPem } from '../pem/sm2.js';

/** 是否为 PEM 文本（而非裸字节 / hex）。 */
export function isPem(input: string | Uint8Array): input is string {
  return typeof input === 'string' && input.startsWith('-----BEGIN');
}

/** 归一化私钥为 32 字节 `d`。 */
export function toPrivateKeyBytes(input: string | Uint8Array, label = 'privateKey'): Uint8Array {
  if (isPem(input)) return parseSm2PrivateKeyPem(input);
  const b = toBytes(input, label);
  if (b.length !== 32) throw new RangeError(`sm2: ${label} must be 32 bytes`);
  return b;
}

/** 归一化公钥为 64 字节 `x || y`。 */
export function toPublicKeyBytes(input: string | Uint8Array, label = 'publicKey'): Uint8Array {
  if (isPem(input)) return parseSm2PublicKeyPem(input).subarray(1);
  let b = toBytes(input, label);
  if (b.length === 65 && b[0] === 0x04) b = b.subarray(1);
  if (b.length !== 64) throw new RangeError(`sm2: ${label} must be 64 or 65 bytes`);
  return b;
}

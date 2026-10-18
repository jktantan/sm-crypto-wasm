/**
 * SM9 密钥 PEM 编解码（PKCS#8 / SPKI + 自定义算法 OID）。
 *
 * spec/plan 对应：plan Task 4；spec §12.1 Q3。
 *
 * 四类密钥都用同一个 SM9 算法 OID（`1.2.156.10197.1.100`），区别只在
 * payload 的字节长度与含义：
 *
 * | 密钥        | 容器                  | payload                                   |
 * |-------------|-----------------------|-------------------------------------------|
 * | 主私钥 ks/ke| PKCS#8 PrivateKeyInfo | 32 字节标量                                |
 * | 主公钥      | SPKI                  | 签名 `[ks]P2`（G2，128B）/ 加密 `[ke]P1`（G1，64B） |
 * | 用户私钥 ds/de | PKCS#8             | 签名 `[ks/(H1+ks)]P1`（G1，64B）/ 加密（G2，128B） |
 *
 * SM9 的用户"公钥"是 `(id, 主公钥)` 的确定函数、不是独立持有物，因此不单独编码。
 *
 * SM9 key PEM encoding/decoding (PKCS#8 / SPKI with a custom algorithm OID).
 *
 * spec/plan: plan Task 4; spec §12.1 Q3.
 *
 * All four key kinds share the single SM9 algorithm OID (`1.2.156.10197.1.100`); they
 * differ only in the length and meaning of the payload:
 *
 * | key                       | container             | payload                                                     |
 * |---------------------------|-----------------------|-------------------------------------------------------------|
 * | master private ks/ke      | PKCS#8 PrivateKeyInfo | 32-byte scalar                                              |
 * | master public             | SPKI                  | signing `[ks]P2` (G2, 128B) / encryption `[ke]P1` (G1, 64B)  |
 * | user private ds/de        | PKCS#8                | signing `[ks/(H1+ks)]P1` (G1, 64B) / encryption (G2, 128B)   |
 *
 * An SM9 user "public key" is the deterministic function of `(id, master public key)`
 * rather than a separately held object, so it is never encoded on its own.
 */

import { InvalidKeyError } from '../runtime/errors.js';
import {
  encodePkcs8PrivateKey,
  encodeSpkiPublicKey,
  parsePkcs8PrivateKey,
  parseSpkiPublicKey,
} from './pkcs8.js';

/**
 * SM9 算法 OID（`1.2.156.10197.1.100`）。
 *
 * SM9 algorithm OID (`1.2.156.10197.1.100`).
 */
export const SM9_OID = '1.2.156.10197.1.100';

/**
 * 编码 SM9 私钥（主私钥或用户私钥）为 PKCS#8 PEM。
 *
 * @param privateKey 私钥字节（主私钥 32B；用户私钥为仿射点）
 *
 * Encodes an SM9 private key (master or user) as PKCS#8 PEM.
 *
 * @param privateKey Private key bytes (32B for a master key; an affine point for a
 *   user key).
 */
export function encodeSm9PrivateKeyPem(privateKey: Uint8Array): string {
  return encodePkcs8PrivateKey(SM9_OID, privateKey);
}

/**
 * 解析 SM9 私钥 PEM，返回 payload 字节。
 *
 * @throws InvalidKeyError PEM 结构非法、或算法 OID 不是 SM9。
 *
 * Parses an SM9 private key PEM and returns the payload bytes.
 *
 * @throws InvalidKeyError When the PEM structure is invalid or the algorithm OID is
 *   not SM9.
 */
export function parseSm9PrivateKeyPem(pem: string): Uint8Array {
  const parsed = parsePkcs8PrivateKey(pem);
  if (parsed.algorithmOid !== SM9_OID) {
    throw new InvalidKeyError(
      `parseSm9PrivateKeyPem: 算法 OID ${parsed.algorithmOid} 不是 SM9（${SM9_OID}）`,
    );
  }
  return parsed.privateKey;
}

/**
 * 编码 SM9 主公钥为 SPKI PEM。
 *
 * @param publicKey 主公钥点仿射字节（签名 G2 128B / 加密 G1 64B）。
 *
 * Encodes the SM9 master public key as SPKI PEM.
 *
 * @param publicKey Master public point in affine bytes (G2 128B for signing / G1 64B
 *   for encryption).
 */
export function encodeSm9PublicKeyPem(publicKey: Uint8Array): string {
  return encodeSpkiPublicKey(SM9_OID, publicKey);
}

/**
 * 解析 SM9 主公钥 PEM，返回点字节。
 *
 * @throws InvalidKeyError PEM 结构非法、或算法 OID 不是 SM9。
 *
 * Parses the SM9 master public key PEM and returns the point bytes.
 *
 * @throws InvalidKeyError When the PEM structure is invalid or the algorithm OID is
 *   not SM9.
 */
export function parseSm9PublicKeyPem(pem: string): Uint8Array {
  const parsed = parseSpkiPublicKey(pem);
  if (parsed.algorithmOid !== SM9_OID) {
    throw new InvalidKeyError(
      `parseSm9PublicKeyPem: 算法 OID ${parsed.algorithmOid} 不是 SM9（${SM9_OID}）`,
    );
  }
  return parsed.publicKey;
}

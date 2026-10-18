/**
 * 单证书签名验证与有效期检查。
 *
 * 只验证“这张证书的 TBS 是否被持有对应私钥的一方签过”，**不做信任链/
 * 策略/名称约束校验**（plan 明确不做）。链校验需要调用方自己按
 * `issuer` / `authorityKeyIdentifier` 逐级调用 `verifySignature`。
 *
 * SM2 用户标识：
 * - GM/T 0009 默认标识 `1234567812345678`；
 * - OpenSSL 的 X.509 签名路径默认使用**空标识**，因此未显式传
 *   `opts.userID` 时先按默认标识验证，失败后再按空标识重试，兼顾两类证书。
 *
 * Single-certificate signature verification and validity checks.
 *
 * Only verifies "whether this certificate's TBS was signed by the party holding
 * the matching private key"; **no trust-chain / policy / name-constraint
 * validation** (deliberately out of scope). Chain validation is the caller's
 * job, walking `verifySignature` level by level along `issuer` /
 * `authorityKeyIdentifier`.
 *
 * SM2 user identity:
 * - the GM/T 0009 default identity `1234567812345678`;
 * - OpenSSL's X.509 signing path uses the **empty** identity by default, so
 *   when `opts.userID` is not given we verify with the default identity first
 *   and retry with the empty identity, covering both kinds of certificate.
 */

import * as sm2 from '../sm2/index.js';
import { OID_SM3_WITH_SM2 } from './oids.js';
import { derSignatureToRaw } from './sig.js';
import type { Certificate, Validity } from './types.js';

/**
 * SM2 默认用户标识（GM/T 0009）。
 *
 * The default SM2 user identity (GM/T 0009).
 */
export const DEFAULT_SM2_USER_ID = new TextEncoder().encode('1234567812345678');

/**
 * OpenSSL X.509 路径的默认用户标识（空）。
 *
 * `openssl req -x509 -newkey sm2` / `openssl x509 -req` 在未显式设置
 * `-sigopt distid:...` 时使用空标识。
 *
 * The default user identity of OpenSSL's X.509 path (empty).
 *
 * `openssl req -x509 -newkey sm2` / `openssl x509 -req` use the empty identity
 * unless `-sigopt distid:...` is passed explicitly.
 */
export const OPENSSL_SM2_USER_ID = new Uint8Array(0);

/**
 * 验签选项。
 *
 * Signature verification options.
 */
export interface VerifySignatureOptions {
  /**
   * SM2 ZA 用户标识。
   *
   * 省略时先按 GM/T 默认标识验证，失败后按空标识重试（OpenSSL 兼容）。
   * 显式传入时只按该标识验证（允许空数组）。
   *
   * The SM2 ZA user identity.
   *
   * When omitted, verification runs with the GM/T default identity first and
   * then retries with the empty identity (OpenSSL compatibility). When passed
   * explicitly, only that identity is used (an empty array is allowed).
   */
  userID?: Uint8Array;
}

/**
 * 用签发者公钥验证证书签名。
 *
 * @param cert 待验证证书。
 * @param issuerPublicKey 签发者公钥（64/65 字节）。
 * @returns 签名是否有效；不支持的算法返回 `false`。
 *
 * Verifies a certificate signature with the issuer public key.
 *
 * @param cert The certificate to verify.
 * @param issuerPublicKey The issuer public key (64/65 bytes).
 * @returns Whether the signature is valid; unsupported algorithms return `false`.
 */
export function verifyCertificateSignature(
  cert: Certificate,
  issuerPublicKey: Uint8Array,
  opts: VerifySignatureOptions = {},
): boolean {
  if (cert.publicKeyAlgorithm !== 'SM2') return false;
  if (cert.signatureAlgorithm.oid !== OID_SM3_WITH_SM2) return false;
  if (!isUsableSm2PublicKey(issuerPublicKey)) return false;

  let signature: Uint8Array;
  try {
    signature = derSignatureToRaw(cert.signatureValue);
  } catch {
    // 签名值结构非法 = 验签失败，而不是解析异常。
    //
    // A malformed signature value means failed verification, not a parse error.
    return false;
  }

  if (opts.userID !== undefined) {
    return sm2.verifyWithID(issuerPublicKey, cert.tbsCertificate, signature, opts.userID);
  }
  if (sm2.verify(issuerPublicKey, cert.tbsCertificate, signature)) return true;
  return sm2.verifyWithID(issuerPublicKey, cert.tbsCertificate, signature, OPENSSL_SM2_USER_ID);
}

/**
 * 检查 `at`（默认当前时间）是否落在有效期内。
 *
 * Checks whether `at` (default: the current time) falls inside the validity period.
 */
export function isWithinValidity(validity: Validity, at: Date = new Date()): boolean {
  if (!(at instanceof Date) || Number.isNaN(at.getTime())) return false;
  const t = at.getTime();
  return t >= validity.notBefore.getTime() && t <= validity.notAfter.getTime();
}

/**
 * 公钥是否为本库可用的 SM2 未压缩点。
 *
 * Whether the public key is an SM2 uncompressed point this library can use.
 */
export function isUsableSm2PublicKey(publicKey: Uint8Array): boolean {
  if (publicKey.length === 64) return true;
  return publicKey.length === 65 && publicKey[0] === 0x04;
}

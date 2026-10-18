/**
 * X.509 / CMS 使用的 OID 常量。
 *
 * 只收录本库直接需要的项；未知 OID 一律保留原值，不做白名单校验
 * （红线 #9：国密证书常带私有扩展）。
 *
 * OID constants used by X.509 / CMS.
 *
 * Only the entries this library needs directly are listed; unknown OIDs are
 * always preserved verbatim and never whitelist-checked (red line #9: SM
 * certificates frequently carry private extensions).
 */

// ---------- 算法 ----------
//
// ---------- Algorithms ----------

/**
 * `id-ecPublicKey`（1.2.840.10045.2.1）。SM2 证书的常见算法标识。
 *
 * `id-ecPublicKey` (1.2.840.10045.2.1); the usual algorithm identifier in SM2 certificates.
 */
export const OID_ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

/**
 * `sm2p256v1` 推荐曲线（1.2.156.10197.1.301）。
 *
 * The `sm2p256v1` recommended curve (1.2.156.10197.1.301).
 */
export const OID_SM2_CURVE = '1.2.156.10197.1.301';

/**
 * SM3withSM2（1.2.156.10197.1.501）。
 *
 * SM3withSM2 (1.2.156.10197.1.501).
 */
export const OID_SM3_WITH_SM2 = '1.2.156.10197.1.501';

/**
 * `rsaEncryption`（1.2.840.113549.1.1.1）。
 *
 * `rsaEncryption` (1.2.840.113549.1.1.1).
 */
export const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

/**
 * 任意 `sha*WithRSAEncryption` 的公共前缀。
 *
 * Common prefix of every `sha*WithRSAEncryption` OID.
 */
export const OID_RSA_SIGNATURE_PREFIX = '1.2.840.113549.1.1.';

/**
 * `sha256WithRSAEncryption`（1.2.840.113549.1.1.11）。
 *
 * `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
 */
export const OID_SHA256_WITH_RSA = '1.2.840.113549.1.1.11';

// ---------- Name 属性 ----------
//
// ---------- Name attributes ----------

// Name 属性 OID。
//
// Name attribute OIDs.

export const OID_COMMON_NAME = '2.5.4.3';
export const OID_ORGANIZATION = '2.5.4.10';
export const OID_ORGANIZATIONAL_UNIT = '2.5.4.11';
export const OID_COUNTRY = '2.5.4.6';
export const OID_STATE = '2.5.4.8';
export const OID_LOCALITY = '2.5.4.7';
export const OID_EMAIL_ADDRESS = '1.2.840.113549.1.9.1';

/**
 * Name 属性 OID → RFC 4514 简写。
 *
 * Name attribute OID to RFC 4514 shorthand label.
 */
export const NAME_OID_LABELS: Readonly<Record<string, string>> = {
  [OID_COMMON_NAME]: 'CN',
  [OID_ORGANIZATION]: 'O',
  [OID_ORGANIZATIONAL_UNIT]: 'OU',
  [OID_COUNTRY]: 'C',
  [OID_STATE]: 'ST',
  [OID_LOCALITY]: 'L',
  [OID_EMAIL_ADDRESS]: 'emailAddress',
};

// ---------- 扩展 ----------
//
// ---------- Extensions ----------

// 证书扩展 OID。
//
// Certificate extension OIDs.

export const OID_SUBJECT_KEY_IDENTIFIER = '2.5.29.14';
export const OID_KEY_USAGE = '2.5.29.15';
export const OID_SUBJECT_ALT_NAME = '2.5.29.17';
export const OID_ISSUER_ALT_NAME = '2.5.29.18';
export const OID_BASIC_CONSTRAINTS = '2.5.29.19';
export const OID_AUTHORITY_KEY_IDENTIFIER = '2.5.29.35';
export const OID_EXTENDED_KEY_USAGE = '2.5.29.37';

// ---------- 扩展密钥用法 ----------
//
// ---------- Extended Key Usage ----------

// Extended Key Usage OID。
//
// Extended Key Usage OIDs.

export const OID_EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
export const OID_EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
export const OID_EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
export const OID_EKU_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';
export const OID_EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
export const OID_EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

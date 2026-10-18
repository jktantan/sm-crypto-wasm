/**
 * CMS SignedData 验签。
 *
 * 只验证签名与 messageDigest，**不建立信任链**、不检查证书有效期/用途；
 * 需要信任判断时由调用方对 `signers[i].certificate` 另行处理。
 *
 * CMS SignedData verification.
 *
 * Only the signature and messageDigest are checked; **no trust chain is built** and
 * certificate validity/key usage are not examined. When a trust decision is needed, the
 * caller handles `signers[i].certificate` separately.
 */

import { bytesToHex, hexToBytes } from '../runtime/convert.js';
import * as sm2 from '../sm2/index.js';
import * as sm3 from '../sm3/index.js';
import { parseCertificate } from '../x509/parse.js';
import { derSignatureToRaw } from '../x509/sig.js';
import type { Certificate } from '../x509/types.js';
import { DEFAULT_SM2_USER_ID } from '../x509/verify.js';
import { CmsError, type CmsVerifyErrorCode } from './errors.js';
import {
  OID_CMS_CONTENT_TYPE,
  OID_CMS_MESSAGE_DIGEST,
  OID_CMS_SIGNING_TIME,
  OID_SM3,
  OID_SM3_WITH_SM2,
} from './oids.js';
import {
  attributeOctets,
  attributeOid,
  attributeTime,
  type CmsAttribute,
  type CmsSignerInfo,
  type ParsedSignedData,
  parseSignedData,
} from './parse.js';

/**
 * `verifySignedData` 的选项。
 *
 * Options of `verifySignedData`.
 */
export interface VerifySignedDataOptions {
  /**
   * detached 模式下的原始内容（字符串按 UTF-8 编码）。
   *
   * The original content in detached mode (strings are treated as UTF-8).
   */
  readonly detachedData?: string | Uint8Array;
  /**
   * 额外候选证书（CMS 未内嵌签名者证书时使用）。
   *
   * Extra candidate certificates, used when the CMS does not embed the signer
   * certificate.
   */
  readonly certificates?: readonly (Certificate | string | Uint8Array)[];
  /**
   * 显式指定 SM2 用户标识；省略时依次尝试空标识与 GM/T 默认标识。
   *
   * An explicit SM2 user identifier; when omitted, the empty identifier and then the
   * GM/T default identifier are tried in turn.
   */
  readonly userID?: Uint8Array;
}

/**
 * 单个签名者的验签结果。
 *
 * The verification result of a single signer.
 */
export interface VerifySignerResult {
  /**
   * 是否通过校验（签名 + messageDigest 均通过）。
   *
   * Whether both the signature and the messageDigest checks passed.
   */
  readonly valid: boolean;
  /**
   * 匹配到的签名者证书。
   *
   * The matched signer certificate.
   */
  readonly certificate?: Certificate;
  /**
   * signedAttrs 中的 signingTime（该属性缺失时为 `undefined`）。
   *
   * The signingTime from signedAttrs (`undefined` when the attribute is absent).
   */
  readonly signingTime?: Date;
  /**
   * 人类可读的补充说明。
   *
   * A human-readable explanation.
   */
  readonly error?: string;
  /**
   * 结构化失败原因（`valid === true` 时不存在）。
   *
   * The structured failure reason (absent when `valid === true`).
   */
  readonly errorCode?: CmsVerifyErrorCode;
}

/**
 * `verifySignedData` 的结果。
 *
 * Result of `verifySignedData`.
 */
export interface VerifySignedDataResult {
  /**
   * 至少有一个签名者且所有签名者都通过校验。
   *
   * True when there is at least one signer and every signer is valid.
   */
  readonly valid: boolean;
  /**
   * 每个签名者的结果，顺序与 `signerInfos` 一致。
   *
   * Per-signer results, in `signerInfos` order.
   */
  readonly signers: readonly VerifySignerResult[];
}

/**
 * SM2 空用户标识（OpenSSL CMS 默认）。
 *
 * The empty SM2 user identifier (the OpenSSL CMS default).
 */
const EMPTY_USER_ID = new Uint8Array(0);

/**
 * 验证 CMS SignedData。
 *
 * 结构完全无法解析时返回 `{ valid: false, signers: [{ errorCode: 'MALFORMED' }] }`，
 * 而不是抛错；wasm 未预热等环境错误仍会抛出。
 *
 * Verifies a CMS SignedData.
 *
 * When the structure cannot be parsed at all it returns
 * `{ valid: false, signers: [{ errorCode: 'MALFORMED' }] }` instead of throwing;
 * environment errors such as an unloaded wasm module are still thrown.
 */
export function verifySignedData(
  cms: string | Uint8Array,
  opts: VerifySignedDataOptions = {},
): VerifySignedDataResult {
  let parsed: ParsedSignedData;
  try {
    parsed = parseSignedData(cms);
  } catch (err) {
    return {
      valid: false,
      signers: [
        {
          valid: false,
          errorCode: 'MALFORMED',
          error: err instanceof Error ? err.message : String(err),
        },
      ],
    };
  }

  const certificates = [
    ...parsed.certificates,
    ...(opts.certificates ?? []).map((cert) => resolveCertificate(cert)),
  ];
  const detachedData = opts.detachedData === undefined ? undefined : toDataBytes(opts.detachedData);

  const signers = parsed.signerInfos.map((signer) =>
    verifySigner(parsed, signer, certificates, detachedData, opts.userID),
  );
  return {
    valid: signers.length > 0 && signers.every((signer) => signer.valid),
    signers,
  };
}

// 验证单个 SignerInfo。
//
// Verifies a single SignerInfo.
function verifySigner(
  parsed: ParsedSignedData,
  signer: CmsSignerInfo,
  certificates: readonly Certificate[],
  detachedData: Uint8Array | undefined,
  userID: Uint8Array | undefined,
): VerifySignerResult {
  if (signer.digestAlgorithm !== OID_SM3) {
    return fail('UNSUPPORTED_ALGORITHM', `unsupported digest algorithm ${signer.digestAlgorithm}`);
  }
  if (signer.signatureAlgorithm !== OID_SM3_WITH_SM2) {
    return fail(
      'UNSUPPORTED_ALGORITHM',
      `unsupported signature algorithm ${signer.signatureAlgorithm}`,
    );
  }

  const certificate = findCertificate(signer, certificates);
  if (certificate === undefined) {
    return fail('NO_CERTIFICATE', 'signer certificate is not embedded and was not provided');
  }
  if (!certificate.supported) {
    return fail('UNSUPPORTED_ALGORITHM', 'signer certificate public key is not SM2');
  }

  const content = parsed.eContent ?? detachedData;
  let signingInput: Uint8Array;
  let signingTime: Date | undefined;

  if (signer.signedAttrs !== undefined) {
    if (content === undefined) {
      return fail('MALFORMED', 'detached data is required but was not supplied');
    }
    const attributes = signer.signedAttrs.attributes;
    const contentType = attributeOid(attributeByOid(attributes, OID_CMS_CONTENT_TYPE));
    if (contentType !== parsed.eContentType) {
      return fail(
        'DIGEST_MISMATCH',
        `contentType attribute ${String(contentType)} does not match ${parsed.eContentType}`,
      );
    }
    const expectedDigest = attributeOctets(attributeByOid(attributes, OID_CMS_MESSAGE_DIGEST));
    if (expectedDigest === undefined) {
      return fail('MALFORMED', 'missing messageDigest attribute');
    }
    const actualDigest = hexToBytes(sm3.hash(content), 'messageDigest');
    if (!equalBytes(expectedDigest, actualDigest)) {
      return fail('DIGEST_MISMATCH', 'messageDigest does not match the content');
    }
    signingInput = signer.signedAttrs.raw;
    signingTime = attributeTime(attributeByOid(attributes, OID_CMS_SIGNING_TIME));
  } else {
    if (content === undefined) {
      return fail('MALFORMED', 'detached data is required but was not supplied');
    }
    signingInput = content;
  }

  let signature: Uint8Array;
  try {
    signature = derSignatureToRaw(signer.signature);
  } catch {
    return fail('SIGNATURE_INVALID', 'malformed DER signature');
  }

  const valid = verifyWithUserId(certificate.subjectPublicKey, signingInput, signature, userID);
  if (!valid) return fail('SIGNATURE_INVALID', 'SM2 signature verification failed');

  return {
    valid: true,
    certificate,
    ...(signingTime === undefined ? {} : { signingTime }),
  };
}

// 使用指定 SM2 用户 ID 验签。
//
// Verifies with an explicit SM2 user ID.
function verifyWithUserId(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  userID: Uint8Array | undefined,
): boolean {
  if (userID !== undefined) {
    return sm2.verifyWithID(publicKey, message, signature, userID);
  }
  // 先试 OpenSSL CMS 的空标识，再试 GM/T 默认标识。
  //
  // Try the empty OpenSSL-CMS identifier first, then the GM/T default identifier.
  if (sm2.verifyWithID(publicKey, message, signature, EMPTY_USER_ID)) return true;
  return sm2.verifyWithID(publicKey, message, signature, DEFAULT_SM2_USER_ID);
}

// 按签名者标识查找证书。
//
// Finds the signer certificate by identifier.
function findCertificate(
  signer: CmsSignerInfo,
  certificates: readonly Certificate[],
): Certificate | undefined {
  const sid = signer.sid;
  if (sid.type === 'issuerAndSerialNumber') {
    return certificates.find(
      (cert) =>
        cert.serialNumber === sid.serialNumber && equalBytes(cert.issuer.raw, sid.issuerRaw),
    );
  }
  return certificates.find(
    (cert) =>
      cert.subjectKeyIdentifier !== undefined &&
      equalBytes(cert.subjectKeyIdentifier, sid.keyIdentifier),
  );
}

// 按 OID 查找签名属性。
//
// Finds a signed attribute by OID.
function attributeByOid(
  attributes: readonly CmsAttribute[],
  target: string,
): CmsAttribute | undefined {
  return attributes.find((attribute) => attribute.oid === target);
}

// 把 Certificate / PEM / DER 输入统一为 Certificate。
//
// Normalizes Certificate / PEM / DER input.
function resolveCertificate(input: Certificate | string | Uint8Array): Certificate {
  if (isCertificateLike(input)) return input;
  try {
    return parseCertificate(input);
  } catch (err) {
    throw new CmsError('verifySignedData: invalid certificate', { cause: err });
  }
}

// 判断值是否像 Certificate。
//
// Checks whether a value looks like a Certificate.
function isCertificateLike(value: Certificate | string | Uint8Array): value is Certificate {
  return (
    typeof value === 'object' &&
    value !== null &&
    !(value instanceof Uint8Array) &&
    'tbsCertificate' in value &&
    'subjectPublicKey' in value
  );
}

// 把 data 输入统一为字节。
//
// Normalizes data input to bytes.
function toDataBytes(data: string | Uint8Array): Uint8Array {
  if (data instanceof Uint8Array) return new Uint8Array(data);
  if (typeof data === 'string') return new TextEncoder().encode(data);
  throw new TypeError('verifySignedData: detachedData must be a string or Uint8Array');
}

// 常量时间比较两个字节数组。
//
// Compares two byte arrays in constant time.
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

// 构造失败结果。
//
// Builds a failure result.
function fail(code: CmsVerifyErrorCode, message: string): VerifySignerResult {
  return { valid: false, errorCode: code, error: message };
}

/**
 * 供调试：签名者标识的十六进制表示。
 *
 * For debugging: the signer identifier as hex.
 */
export function signerIdentifierHex(signer: CmsSignerInfo): string {
  if (signer.sid.type === 'subjectKeyIdentifier') {
    return bytesToHex(signer.sid.keyIdentifier);
  }
  return `${bytesToHex(signer.sid.issuerRaw)}#${signer.sid.serialNumber.toString(16)}`;
}

/**
 * CMS SignedData 签名（detached / attached）。
 *
 * 签名的计算对象是 `signedAttrs` 的 DER 编码（SET tag 0x31）——与验签层
 * 使用完全相同的规则；`contentType` / `messageDigest` / `signingTime` 三个
 * 属性按 DER SET OF 排序后编码。
 *
 * 只做 SignedData，不做 EnvelopedData / RFC 3161 时间戳。
 *
 * CMS SignedData signing (detached / attached).
 *
 * The signed object is the DER encoding of `signedAttrs` (SET tag 0x31) — exactly the
 * same rule the verification layer uses; the `contentType` / `messageDigest` /
 * `signingTime` attributes are encoded after DER SET OF sorting.
 *
 * SignedData only: no EnvelopedData, no RFC 3161 timestamping.
 */

import {
  type Asn1Node,
  explicit,
  implicit,
  integer,
  octetString,
  oid,
  parseDer,
  seq,
  setOf,
  time,
} from '../asn1/index.js';
import { bytesToBase64, bytesToPem, hexToBytes } from '../runtime/convert.js';
import * as sm2 from '../sm2/index.js';
import * as sm3 from '../sm3/index.js';
import { parseCertificate } from '../x509/parse.js';
import { rawSignatureToDer } from '../x509/sig.js';
import type { Certificate } from '../x509/types.js';
import { CmsError } from './errors.js';
import {
  OID_CMS_CONTENT_TYPE,
  OID_CMS_DATA,
  OID_CMS_MESSAGE_DIGEST,
  OID_CMS_SIGNED_DATA,
  OID_CMS_SIGNING_TIME,
  OID_SM3,
  OID_SM3_WITH_SM2,
} from './oids.js';

/**
 * `signData` 的输入。
 *
 * Input of `signData`.
 */
export interface SignDataOptions {
  /**
   * 待签名数据；字符串按 UTF-8 编码（不是 hex/base64）。
   *
   * Data to sign; strings are treated as UTF-8 (not hex/base64).
   */
  readonly data: string | Uint8Array;
  /**
   * PKCS#8 / SEC1 PEM、32 字节私钥或其 hex。
   *
   * PKCS#8 / SEC1 PEM, a 32-byte private key, or its hex.
   */
  readonly privateKey: string | Uint8Array;
  /**
   * 签名者证书；省略时取 `certificates[0]`。
   *
   * The signer certificate; `certificates[0]` is used when omitted.
   */
  readonly certificate?: Certificate | string | Uint8Array;
  /**
   * 额外证书（链）。
   *
   * Additional certificates (the chain).
   */
  readonly certificates?: readonly (Certificate | string | Uint8Array)[];
  /**
   * 默认 `true`：只输出签名，内容由调用方另行传输。
   *
   * Defaults to `true`: emit the signature only; the content travels separately.
   */
  readonly detached?: boolean;
  /**
   * 默认当前时间；`false` 表示不加入 signingTime 属性。
   *
   * Defaults to the current time; `false` omits the signingTime attribute.
   */
  readonly signingTime?: Date | false;
  /**
   * SM2 用户标识；默认空（与 OpenSSL 的 CMS 路径一致）。
   *
   * SM2 user identifier; empty by default (matching OpenSSL's CMS path).
   */
  readonly userID?: Uint8Array;
}

/**
 * `signData` 的结果。
 *
 * Result of `signData`.
 */
export interface SignDataResult {
  /**
   * DER 编码的 ContentInfo。
   *
   * The DER-encoded ContentInfo.
   */
  readonly der: Uint8Array;
  /**
   * 上述 DER 的 PEM 文本（`BEGIN CMS`）。
   *
   * The PEM text of that DER (`BEGIN CMS`).
   */
  readonly pem: string;
  /**
   * 上述 DER 的 base64。
   *
   * The base64 form of that DER.
   */
  readonly base64: string;
}

/**
 * 生成 CMS SignedData（单签名者）。
 *
 * 调用前需要预热 wasm：`await sm2.ensureLoaded(); await sm3.ensureLoaded();`
 *
 * @throws CmsError 缺少签名者证书或输入不合法。
 *
 * Builds a CMS SignedData structure (single signer).
 *
 * The wasm modules must be warmed up beforehand:
 * `await sm2.ensureLoaded(); await sm3.ensureLoaded();`
 *
 * @throws CmsError When the signer certificate is missing or the input is invalid.
 */
export function signData(opts: SignDataOptions): SignDataResult {
  const content = toDataBytes(opts.data);
  const signerCertificate = resolveSignerCertificate(opts);
  const chain = (opts.certificates ?? []).map((item) => resolveCertificate(item));
  const certificates = dedupeCertificates([signerCertificate, ...chain]);

  const digest = hexToBytes(sm3.hash(content), 'messageDigest');
  const signingTime = opts.signingTime === false ? undefined : (opts.signingTime ?? new Date());

  const attributes: Asn1Node[] = [
    attribute(OID_CMS_CONTENT_TYPE, setOf([oid(OID_CMS_DATA)])),
    attribute(OID_CMS_MESSAGE_DIGEST, setOf([octetString(digest)])),
  ];
  if (signingTime !== undefined) {
    attributes.push(attribute(OID_CMS_SIGNING_TIME, setOf([time(signingTime)])));
  }
  const signedAttrs = setOf(attributes);

  const signature = hexToBytes(
    sm2.signWithID(opts.privateKey, signedAttrs.raw, opts.userID ?? new Uint8Array(0)),
    'signature',
  );
  const signatureDer = rawSignatureToDer(signature);

  const signerInfo = seq([
    integer(1),
    issuerAndSerialNumber(signerCertificate),
    algorithmIdentifier(OID_SM3),
    implicit(0, signedAttrs),
    algorithmIdentifier(OID_SM3_WITH_SM2),
    octetString(signatureDer),
  ]);

  const encapContentInfo =
    opts.detached === false
      ? seq([oid(OID_CMS_DATA), explicit(0, octetString(content))])
      : seq([oid(OID_CMS_DATA)]);

  const signedDataChildren: Asn1Node[] = [
    integer(1),
    setOf([algorithmIdentifier(OID_SM3)]),
    encapContentInfo,
  ];
  if (certificates.length > 0) {
    signedDataChildren.push(implicit(0, setOf(certificates.map((cert) => parseDer(cert.raw)))));
  }
  signedDataChildren.push(setOf([signerInfo]));

  const signedData = seq(signedDataChildren);
  const contentInfo = seq([oid(OID_CMS_SIGNED_DATA), explicit(0, signedData)]);
  const der = new Uint8Array(contentInfo.raw);
  return {
    der,
    pem: bytesToPem(der, 'CMS'),
    base64: bytesToBase64(der),
  };
}

// ---------- 编码辅助 ----------
//
// ---------- Encoding helpers ----------

// 构造 CMS Attribute（OID + SET OF 值）。
//
// Builds a CMS Attribute (OID + SET OF values).
function attribute(attrOid: string, values: Asn1Node): Asn1Node {
  return seq([oid(attrOid), values]);
}

// 构造 AlgorithmIdentifier。
//
// Builds an AlgorithmIdentifier.
function algorithmIdentifier(oidValue: string): Asn1Node {
  return seq([oid(oidValue)]);
}

// 构造 IssuerAndSerialNumber 签名者标识。
//
// Builds an IssuerAndSerialNumber signer identifier.
function issuerAndSerialNumber(cert: Certificate): Asn1Node {
  let issuer: Asn1Node;
  try {
    issuer = parseDer(cert.issuer.raw);
  } catch (err) {
    throw new CmsError('signData: failed to re-encode issuer name', { cause: err });
  }
  return seq([issuer, integer(cert.serialNumber)]);
}

// ---------- 输入辅助 ----------
//
// ---------- Input helpers ----------

/**
 * 字符串按 UTF-8 处理；CMS 的 data 语义是报文内容，不是 hex。
 *
 * Strings are treated as UTF-8; the CMS data field carries message content, not hex.
 */
function toDataBytes(data: string | Uint8Array): Uint8Array {
  if (data instanceof Uint8Array) return new Uint8Array(data);
  if (typeof data === 'string') return new TextEncoder().encode(data);
  throw new TypeError('signData: data must be a string or Uint8Array');
}

// 从 options 解析签名者证书。
//
// Resolves the signer certificate from options.
function resolveSignerCertificate(opts: SignDataOptions): Certificate {
  const input = opts.certificate ?? opts.certificates?.[0];
  if (input === undefined) {
    throw new CmsError('signData: certificate is required to build the SignerInfo');
  }
  return resolveCertificate(input);
}

// 把 Certificate / PEM / DER 输入统一为 Certificate。
//
// Normalizes Certificate / PEM / DER input.
function resolveCertificate(input: Certificate | string | Uint8Array): Certificate {
  if (isCertificateLike(input)) return input;
  try {
    return parseCertificate(input);
  } catch (err) {
    throw new CmsError('signData: invalid certificate', { cause: err });
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

// 按 DER 去重证书。
//
// Deduplicates certificates by DER.
function dedupeCertificates(certificates: readonly Certificate[]): Certificate[] {
  const seen = new Set<string>();
  const out: Certificate[] = [];
  for (const cert of certificates) {
    const key = base64Key(cert.raw);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(cert);
  }
  return out;
}

// 把证书 DER 字节映射成单字节字符串，作为去重 key（只用于等值比较，不是 base64）。
//
// Maps certificate DER bytes to a one-code-unit-per-byte string used as a dedup key
// (equality comparison only; this is not a base64 encoding).
function base64Key(bytes: Uint8Array): string {
  let key = '';
  for (let i = 0; i < bytes.length; i++) key += String.fromCharCode(bytes[i] as number);
  return key;
}

/**
 * 证书集合中的证书原始 DER（供外部检查）。
 *
 * Raw DER of each certificate in the set, for external inspection.
 */
export function certificateChainDer(certificates: readonly Certificate[]): Uint8Array[] {
  return certificates.map((cert) => new Uint8Array(cert.raw));
}

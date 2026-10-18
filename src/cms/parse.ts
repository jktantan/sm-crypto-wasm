/**
 * CMS SignedData 解析（只读）。
 *
 * 关键点（红线 #1）：
 * `signedAttrs` 的签名输入是**原始 DER 字节**（SET OF Attribute），而不是
 * 解析后重新编码的结果。这里保留：
 * - `raw`：把 `[0] IMPLICIT` 的首字节（0xA0）换成 SET（0x31）后的字节；
 * - 对 BER indefinite-length，先编码为 definite-length 再替换首字节。
 * 除首字节外不做任何重编码，避免 SET 顺序/长度编码差异破坏合法签名。
 *
 * BER 只在 CMS 路径启用；证书本身仍按 DER 严格解析。
 *
 * CMS SignedData parsing (read-only).
 *
 * Key point (red line #1): the signing input of `signedAttrs` is the **original DER
 * bytes** (a SET OF Attribute), not a re-encoding of the parsed form. This module keeps:
 * - `raw`: the bytes obtained by replacing the leading byte of `[0] IMPLICIT` (0xA0)
 *   with the SET tag (0x31);
 * - for BER indefinite-length, the value is first encoded as definite-length and then
 *   the leading byte is replaced.
 * Nothing but the leading byte is re-encoded, so SET ordering or length-encoding
 * differences can never break a valid signature.
 *
 * BER is enabled on the CMS path only; certificates themselves are still parsed as
 * strict DER.
 */

import {
  Asn1Class,
  type Asn1Node,
  encode,
  expectSequence,
  expectUniversal,
  parseBer,
  readInteger,
  readOid,
  readTime,
  UniversalTag,
} from '../asn1/index.js';
import { base64ToBytes, bytesToHex, hexToBytes } from '../runtime/convert.js';
import { parseCertificate } from '../x509/parse.js';
import type { Certificate } from '../x509/types.js';
import { CmsError } from './errors.js';
import { OID_CMS_SIGNED_DATA } from './oids.js';

/**
 * 一个签名属性（Attribute ::= SEQUENCE { attrType, attrValues SET OF }).
 *
 * A single signed attribute (`Attribute ::= SEQUENCE { attrType, attrValues SET OF }`).
 */
export interface CmsAttribute {
  /**
   * 属性类型 OID。
   *
   * The attribute type OID.
   */
  readonly oid: string;
  /**
   * AttributeValue 节点（原始视图）。
   *
   * AttributeValue nodes (raw views).
   */
  readonly values: readonly Asn1Node[];
  /**
   * 整个 Attribute 的原始 DER。
   *
   * Raw DER of the whole Attribute.
   */
  readonly raw: Uint8Array;
}

/**
 * 签名者标识。
 *
 * The signer identifier.
 */
export type CmsSignerIdentifier =
  | {
      readonly type: 'issuerAndSerialNumber';
      /**
       * 签发者 Name 的原始 DER，用于按字节匹配证书。
       *
       * Raw DER of the issuer Name, used to match certificates byte for byte.
       */
      readonly issuerRaw: Uint8Array;
      /**
       * 证书序列号（ASN.1 INTEGER，无符号大整数）。
       *
       * The certificate serial number (an ASN.1 INTEGER held as a bigint).
       */
      readonly serialNumber: bigint;
    }
  | {
      readonly type: 'subjectKeyIdentifier';
      /**
       * `subjectKeyIdentifier` 的原始字节。
       *
       * Raw bytes of the `subjectKeyIdentifier` extension value.
       */
      readonly keyIdentifier: Uint8Array;
    };

/**
 * 解析后的 SignerInfo。
 *
 * A parsed SignerInfo.
 */
export interface CmsSignerInfo {
  /**
   * SignerInfo 版本号（原样解析，不做校验）。
   *
   * The SignerInfo version, taken as parsed and not validated.
   */
  readonly version: number;
  /**
   * 签名者标识（`issuerAndSerialNumber` 或 `subjectKeyIdentifier`）。
   *
   * The signer identifier (`issuerAndSerialNumber` or `subjectKeyIdentifier`).
   */
  readonly sid: CmsSignerIdentifier;
  /**
   * 摘要算法 OID；验签层只接受 SM3（`OID_SM3`）。
   *
   * Digest algorithm OID; the verification layer only accepts SM3 (`OID_SM3`).
   */
  readonly digestAlgorithm: string;
  /**
   * signedAttrs 的签名输入字节（SET tag 0x31）。
   * 没有 signedAttrs 时为 `undefined`（直接签内容）。
   *
   * The signing-input bytes of signedAttrs (SET tag 0x31).
   * `undefined` when there are no signedAttrs (the content is signed directly).
   */
  readonly signedAttrs?: {
    readonly raw: Uint8Array;
    readonly attributes: readonly CmsAttribute[];
  };
  /**
   * 签名算法 OID；验签层只接受 SM3withSM2（`OID_SM3_WITH_SM2`）。
   *
   * Signature algorithm OID; the verification layer only accepts SM3withSM2
   * (`OID_SM3_WITH_SM2`).
   */
  readonly signatureAlgorithm: string;
  /**
   * 签名字节（DER 的 `SEQUENCE { r, s }`，验签前转成裸 `r || s`）。
   *
   * Signature bytes (a DER `SEQUENCE { r, s }`, converted to raw `r || s` before
   * verification).
   */
  readonly signature: Uint8Array;
}

/**
 * 解析后的 SignedData。
 *
 * A parsed SignedData.
 */
export interface ParsedSignedData {
  /**
   * SignedData 版本号（原样解析，不做校验）。
   *
   * The SignedData version, taken as parsed and not validated.
   */
  readonly version: number;
  /**
   * `digestAlgorithms` 里的算法 OID 列表。
   *
   * The algorithm OIDs listed in `digestAlgorithms`.
   */
  readonly digestAlgorithms: readonly string[];
  /**
   * 内容类型 OID（本仓库的签名路径固定输出 id-data）。
   *
   * The content type OID (the signing path here always emits id-data).
   */
  readonly eContentType: string;
  /**
   * 内嵌内容；detached 时为 `undefined`。
   *
   * The embedded content; `undefined` for detached signatures.
   */
  readonly eContent?: Uint8Array;
  /**
   * 解析成功的 X.509 证书（无法解析的 CertificateChoices 已跳过）。
   *
   * Successfully parsed X.509 certificates (unparseable CertificateChoices skipped).
   */
  readonly certificates: readonly Certificate[];
  /**
   * SignerInfo 列表，顺序与 CMS 中一致。
   *
   * The SignerInfo entries, in the order they appear in the CMS.
   */
  readonly signerInfos: readonly CmsSignerInfo[];
  /**
   * 整个 ContentInfo 的原始 DER。
   *
   * Raw DER of the whole ContentInfo.
   */
  readonly raw: Uint8Array;
}

/**
 * 解析 CMS ContentInfo（仅接受 SignedData）。
 *
 * @param input PEM（`CMS` / `PKCS7`）、base64、hex 或 DER/BER 字节。
 * @throws CmsError 结构非法、不是 SignedData、或尾部有多余字节。
 *
 * Parses a CMS ContentInfo (SignedData only).
 *
 * @param input PEM (`CMS` / `PKCS7`), base64, hex, or DER/BER bytes.
 * @throws CmsError When the structure is invalid, is not SignedData, or has trailing
 *   bytes.
 */
export function parseSignedData(input: string | Uint8Array): ParsedSignedData {
  const der = decodeCmsInput(input);
  let top: Asn1Node;
  try {
    top = parseBer(der);
  } catch (err) {
    throw new CmsError(`parseSignedData: invalid DER/BER (${errorMessage(err)})`, { cause: err });
  }
  try {
    return signedDataFromContentInfo(top, der);
  } catch (err) {
    if (err instanceof CmsError) throw err;
    throw new CmsError(`parseSignedData: ${errorMessage(err)}`, { cause: err });
  }
}

// 从 ContentInfo 提取 SignedData。
//
// Extracts SignedData from ContentInfo.
function signedDataFromContentInfo(top: Asn1Node, raw: Uint8Array): ParsedSignedData {
  const kids = expectSequence(top, 'ContentInfo');
  const contentType = readOid(kids[0] as Asn1Node, 'ContentInfo.contentType');
  if (contentType !== OID_CMS_SIGNED_DATA) {
    throw new CmsError(`parseSignedData: content type ${contentType} is not signedData`);
  }
  const wrapper = kids[1];
  if (wrapper === undefined || wrapper.cls !== Asn1Class.ContextSpecific || wrapper.tag !== 0) {
    throw new CmsError('parseSignedData: missing [0] EXPLICIT content');
  }
  const signedData = wrapper.children?.[0];
  if (signedData === undefined) {
    throw new CmsError('parseSignedData: empty SignedData content');
  }
  return parseSignedDataNode(signedData, raw);
}

// 解析 SignedData 节点。
//
// Parses a SignedData node.
function parseSignedDataNode(node: Asn1Node, raw: Uint8Array): ParsedSignedData {
  const kids = expectSequence(node, 'SignedData');
  if (kids.length < 4) {
    throw new CmsError(`SignedData: expected at least 4 elements, got ${kids.length}`);
  }
  let index = 0;
  const version = Number(readInteger(kids[index++] as Asn1Node, 'SignedData.version'));
  const digestAlgorithms = parseAlgorithmSet(kids[index++], 'digestAlgorithms');
  const encap = parseEncapContentInfo(kids[index++] as Asn1Node);

  let certificates: Certificate[] = [];
  const maybeCerts = kids[index];
  if (maybeCerts !== undefined && maybeCerts.cls === Asn1Class.ContextSpecific) {
    if (maybeCerts.tag === 0) {
      certificates = parseCertificates(maybeCerts);
      index++;
    } else if (maybeCerts.tag === 1) {
      // crls：v1 不处理。
      //
      // crls: not handled in v1.
      index++;
    }
  }

  const signerSet = kids[index];
  if (signerSet === undefined) throw new CmsError('SignedData: missing signerInfos');
  const signerInfos = (signerSet.children ?? []).map((child) =>
    parseSignerInfo(expectSequence(child, 'SignerInfo')),
  );

  return {
    version,
    digestAlgorithms,
    eContentType: encap.eContentType,
    ...(encap.eContent === undefined ? {} : { eContent: encap.eContent }),
    certificates,
    signerInfos,
    raw: new Uint8Array(raw),
  };
}

// 解析算法标识集合。
//
// Parses a set of algorithm identifiers.
function parseAlgorithmSet(node: Asn1Node | undefined, what: string): string[] {
  const entries = node?.children ?? [];
  return entries.map((entry) => {
    const kids = expectSequence(entry, what);
    return readOid(kids[0] as Asn1Node, what);
  });
}

// 解析 EncapsulatedContentInfo。
//
// Parses EncapsulatedContentInfo.
function parseEncapContentInfo(node: Asn1Node): { eContentType: string; eContent?: Uint8Array } {
  const kids = expectSequence(node, 'EncapsulatedContentInfo');
  const eContentType = readOid(kids[0] as Asn1Node, 'eContentType');
  const wrapper = kids[1];
  if (wrapper === undefined || wrapper.cls !== Asn1Class.ContextSpecific || wrapper.tag !== 0) {
    return { eContentType };
  }
  const octets = wrapper.children?.[0];
  if (octets === undefined) {
    throw new CmsError('EncapsulatedContentInfo: empty eContent');
  }
  return { eContentType, eContent: octetStringBytes(octets) };
}

// 解析 SignedData 中的证书集合。
//
// Parses the certificate set in SignedData.
function parseCertificates(node: Asn1Node): Certificate[] {
  const certificates: Certificate[] = [];
  for (const child of node.children ?? []) {
    // CertificateChoices 还可能是其它证书类型；解析失败的项跳过，不影响 SignedData。
    //
    // CertificateChoices may hold other certificate types; entries that fail to parse
    // are skipped without affecting the SignedData.
    try {
      certificates.push(parseCertificate(child.raw));
    } catch {
      // 非 X.509 证书或损坏项：忽略。
      //
      // Not an X.509 certificate, or corrupted: ignore it.
    }
  }
  return certificates;
}

// 解析 SignerInfo。
//
// Parses a SignerInfo.
function parseSignerInfo(kids: readonly Asn1Node[]): CmsSignerInfo {
  let index = 0;
  const version = Number(readInteger(kids[index++] as Asn1Node, 'SignerInfo.version'));
  const sidNode = kids[index++];
  if (sidNode === undefined) throw new CmsError('SignerInfo: missing sid');
  const sid = parseSignerIdentifier(sidNode);

  const digestNode = kids[index++];
  const digestKids = expectSequence(digestNode, 'digestAlgorithm');
  const digestAlgorithm = readOid(digestKids[0] as Asn1Node, 'digestAlgorithm');

  let signedAttrs: CmsSignerInfo['signedAttrs'];
  const attrsNode = kids[index];
  if (
    attrsNode !== undefined &&
    attrsNode.cls === Asn1Class.ContextSpecific &&
    attrsNode.tag === 0
  ) {
    signedAttrs = parseSignedAttrs(attrsNode);
    index++;
  }

  const signatureAlgKids = expectSequence(kids[index++], 'signatureAlgorithm');
  const signatureAlgorithm = readOid(signatureAlgKids[0] as Asn1Node, 'signatureAlgorithm');
  const signatureNode = kids[index++];
  if (signatureNode === undefined) throw new CmsError('SignerInfo: missing signature');
  const signature = octetStringBytes(signatureNode);

  return {
    version,
    sid,
    digestAlgorithm,
    ...(signedAttrs === undefined ? {} : { signedAttrs }),
    signatureAlgorithm,
    signature,
  };
}

// 解析 SignerIdentifier。
//
// Parses a SignerIdentifier.
function parseSignerIdentifier(node: Asn1Node): CmsSignerIdentifier {
  if (node.cls === Asn1Class.Universal && node.tag === UniversalTag.Sequence) {
    const kids = expectSequence(node, 'IssuerAndSerialNumber');
    const issuer = kids[0];
    const serial = kids[1];
    if (issuer === undefined || serial === undefined) {
      throw new CmsError('IssuerAndSerialNumber: missing issuer/serialNumber');
    }
    return {
      type: 'issuerAndSerialNumber',
      issuerRaw: new Uint8Array(issuer.raw),
      serialNumber: readInteger(serial, 'IssuerAndSerialNumber.serialNumber'),
    };
  }
  if (node.cls === Asn1Class.ContextSpecific && node.tag === 0) {
    return { type: 'subjectKeyIdentifier', keyIdentifier: new Uint8Array(node.value) };
  }
  throw new CmsError('SignerInfo: unsupported signer identifier');
}

// 解析 signedAttrs。
//
// Parses signedAttrs.
function parseSignedAttrs(node: Asn1Node): NonNullable<CmsSignerInfo['signedAttrs']> {
  const attributes = (node.children ?? []).map((child) => {
    const kids = expectSequence(child, 'Attribute');
    const oidNode = kids[0];
    const valuesNode = kids[1];
    if (oidNode === undefined || valuesNode === undefined) {
      throw new CmsError('Attribute: missing attrType or attrValues');
    }
    return {
      oid: readOid(oidNode, 'Attribute.attrType'),
      values: valuesNode.children ?? [],
      raw: new Uint8Array(child.raw),
    };
  });
  return { raw: signedAttrsDer(node), attributes };
}

/**
 * 还原 signedAttrs 的签名输入字节。
 *
 * `[0] IMPLICIT` 与 `SET` 的唯一区别是首字节（0xA0 vs 0x31），长度和内容
 * 完全相同。definite-length 时只改首字节；BER indefinite-length 时先编码为
 * definite-length（子节点顺序不变），再改首字节。
 *
 * Restores the signing-input bytes of signedAttrs.
 *
 * The only difference between `[0] IMPLICIT` and `SET` is the leading byte
 * (0xA0 vs 0x31); length and content are identical. For definite-length only that
 * leading byte changes; for BER indefinite-length the value is first encoded as
 * definite-length (keeping the child order) and then the leading byte is replaced.
 */
function signedAttrsDer(node: Asn1Node): Uint8Array {
  if (!node.indefinite) {
    const copy = new Uint8Array(node.raw);
    copy[0] = 0x31;
    return copy;
  }
  const encoded = encode(node);
  encoded[0] = 0x31;
  return encoded;
}

// 读取 OCTET STRING 内容。
//
// Reads OCTET STRING content.
function octetStringBytes(node: Asn1Node): Uint8Array {
  const target = expectUniversal(node, UniversalTag.OctetString, 'OCTET STRING');
  if (!target.constructed) return new Uint8Array(target.value);
  // constructed OCTET STRING（BER 分块）：拼接子节点内容。
  //
  // Constructed OCTET STRING (BER chunking): concatenate the children's contents.
  const parts = (target.children ?? []).map((child) => octetStringBytes(child));
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// ---------- 输入解码 ----------
//
// ---------- Input decoding ----------

// 解码 DER / PEM / base64 CMS 输入。
//
// Decodes DER / PEM / base64 CMS input.
function decodeCmsInput(input: string | Uint8Array): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.length === 0) throw new CmsError('parseSignedData: empty input');
    if (isPemText(input)) return decodeCmsInput(new TextDecoder().decode(input));
    return input;
  }
  if (typeof input !== 'string') {
    throw new TypeError('parseSignedData: expected string or Uint8Array');
  }
  const text = input.trim();
  if (text.length === 0) throw new CmsError('parseSignedData: empty input');
  const pem = /-----BEGIN (?:CMS|PKCS7)-----([\s\S]*?)-----END (?:CMS|PKCS7)-----/.exec(text);
  if (pem !== null) {
    try {
      return base64ToBytes((pem[1] as string).replace(/\s+/g, ''), 'cms');
    } catch (err) {
      throw new CmsError('parseSignedData: invalid base64 in PEM block', { cause: err });
    }
  }
  const compact = text.replace(/\s+/g, '');
  const candidates: Uint8Array[] = [];
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) {
    candidates.push(hexToBytes(compact, 'cms'));
  }
  try {
    candidates.push(base64ToBytes(compact, 'cms'));
  } catch {
    // 不是 base64。
    //
    // Not base64.
  }
  for (const candidate of candidates) {
    try {
      parseBer(candidate);
      return candidate;
    } catch {
      // 尝试下一个。
      //
      // Try the next candidate.
    }
  }
  throw new CmsError('parseSignedData: input is neither PEM, hex nor base64 DER');
}

// 判断输入是否像 PEM 文本。
//
// Checks whether input looks like PEM text.
function isPemText(bytes: Uint8Array): boolean {
  const prefix = '-----BEGIN ';
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix.charCodeAt(i)) return false;
  }
  return true;
}

// 把未知异常转成可读消息。
//
// Converts an unknown error to a readable message.
function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * 读取签名属性中的时间值（供验签层使用）。
 *
 * Reads the time value of a signed attribute (used by the verification layer).
 */
export function attributeTime(attribute: CmsAttribute | undefined): Date | undefined {
  const value = attribute?.values[0];
  if (value === undefined) return undefined;
  try {
    return readTime(value, 'signingTime');
  } catch {
    return undefined;
  }
}

/**
 * 读取签名属性中的 OCTET STRING 值（messageDigest）。
 *
 * Reads the OCTET STRING value of a signed attribute (messageDigest).
 */
export function attributeOctets(attribute: CmsAttribute | undefined): Uint8Array | undefined {
  const value = attribute?.values[0];
  if (value === undefined) return undefined;
  try {
    return octetStringBytes(value);
  } catch {
    return undefined;
  }
}

/**
 * 读取签名属性中的 OID 值（contentType）。
 *
 * Reads the OID value of a signed attribute (contentType).
 */
export function attributeOid(attribute: CmsAttribute | undefined): string | undefined {
  const value = attribute?.values[0];
  if (value === undefined) return undefined;
  try {
    return readOid(value, 'contentType');
  } catch {
    return undefined;
  }
}

/**
 * 十六进制便捷函数（供错误信息/调试使用）。
 *
 * Hex convenience helper, for error messages and debugging.
 */
export function cmsHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

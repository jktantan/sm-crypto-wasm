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

/** 一个签名属性（Attribute ::= SEQUENCE { attrType, attrValues SET OF }). */
export interface CmsAttribute {
  readonly oid: string;
  /** AttributeValue 节点（原始视图）。 */
  readonly values: readonly Asn1Node[];
  /** 整个 Attribute 的原始 DER。 */
  readonly raw: Uint8Array;
}

/** 签名者标识。 */
export type CmsSignerIdentifier =
  | {
      readonly type: 'issuerAndSerialNumber';
      /** 签发者 Name 的原始 DER，用于按字节匹配证书。 */
      readonly issuerRaw: Uint8Array;
      readonly serialNumber: bigint;
    }
  | {
      readonly type: 'subjectKeyIdentifier';
      readonly keyIdentifier: Uint8Array;
    };

/** 解析后的 SignerInfo。 */
export interface CmsSignerInfo {
  readonly version: number;
  readonly sid: CmsSignerIdentifier;
  readonly digestAlgorithm: string;
  /**
   * signedAttrs 的签名输入字节（SET tag 0x31）。
   * 没有 signedAttrs 时为 `undefined`（直接签内容）。
   */
  readonly signedAttrs?: {
    readonly raw: Uint8Array;
    readonly attributes: readonly CmsAttribute[];
  };
  readonly signatureAlgorithm: string;
  readonly signature: Uint8Array;
}

/** 解析后的 SignedData。 */
export interface ParsedSignedData {
  readonly version: number;
  readonly digestAlgorithms: readonly string[];
  readonly eContentType: string;
  /** 内嵌内容；detached 时为 `undefined`。 */
  readonly eContent?: Uint8Array;
  readonly certificates: readonly Certificate[];
  readonly signerInfos: readonly CmsSignerInfo[];
  /** 整个 ContentInfo 的原始 DER。 */
  readonly raw: Uint8Array;
}

/**
 * 解析 CMS ContentInfo（仅接受 SignedData）。
 *
 * @param input PEM（`CMS` / `PKCS7`）、base64、hex 或 DER/BER 字节。
 * @throws CmsError 结构非法、不是 SignedData、或尾部有多余字节。
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

function parseAlgorithmSet(node: Asn1Node | undefined, what: string): string[] {
  const entries = node?.children ?? [];
  return entries.map((entry) => {
    const kids = expectSequence(entry, what);
    return readOid(kids[0] as Asn1Node, what);
  });
}

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

function parseCertificates(node: Asn1Node): Certificate[] {
  const certificates: Certificate[] = [];
  for (const child of node.children ?? []) {
    // CertificateChoices 还可能是其它证书类型；解析失败的项跳过，不影响 SignedData。
    try {
      certificates.push(parseCertificate(child.raw));
    } catch {
      // 非 X.509 证书或损坏项：忽略。
    }
  }
  return certificates;
}

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

function octetStringBytes(node: Asn1Node): Uint8Array {
  const target = expectUniversal(node, UniversalTag.OctetString, 'OCTET STRING');
  if (!target.constructed) return new Uint8Array(target.value);
  // constructed OCTET STRING（BER 分块）：拼接子节点内容。
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
  }
  for (const candidate of candidates) {
    try {
      parseBer(candidate);
      return candidate;
    } catch {
      // 尝试下一个。
    }
  }
  throw new CmsError('parseSignedData: input is neither PEM, hex nor base64 DER');
}

function isPemText(bytes: Uint8Array): boolean {
  const prefix = '-----BEGIN ';
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix.charCodeAt(i)) return false;
  }
  return true;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** 读取签名属性中的时间值（供验签层使用）。 */
export function attributeTime(attribute: CmsAttribute | undefined): Date | undefined {
  const value = attribute?.values[0];
  if (value === undefined) return undefined;
  try {
    return readTime(value, 'signingTime');
  } catch {
    return undefined;
  }
}

/** 读取签名属性中的 OCTET STRING 值（messageDigest）。 */
export function attributeOctets(attribute: CmsAttribute | undefined): Uint8Array | undefined {
  const value = attribute?.values[0];
  if (value === undefined) return undefined;
  try {
    return octetStringBytes(value);
  } catch {
    return undefined;
  }
}

/** 读取签名属性中的 OID 值（contentType）。 */
export function attributeOid(attribute: CmsAttribute | undefined): string | undefined {
  const value = attribute?.values[0];
  if (value === undefined) return undefined;
  try {
    return readOid(value, 'contentType');
  } catch {
    return undefined;
  }
}

/** 十六进制便捷函数（供错误信息/调试使用）。 */
export function cmsHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

/**
 * X.509 证书解析（只读）。
 *
 * 支持 DER / PEM / base64 输入；不做链校验、不拉 CRL/OCSP。
 *
 * 严格性（红线 #3）：
 * - 单个证书必须恰好是一个完整 DER 对象，尾部多余字节直接拒绝；
 * - X.509 路径不使用 BER indefinite-length；
 * - 未知扩展 / 未知算法 / 未知 Name 属性不抛错，保留原始值（红线 #9）。
 */

import {
  Asn1Class,
  type Asn1Node,
  expectSequence,
  expectUniversal,
  parseDer,
  parseDerAll,
  readBitString,
  readBoolean,
  readInteger,
  readOctetString,
  readOid,
  readString,
  readTime,
  UniversalTag,
} from '../asn1/index.js';
import { decodeOid } from '../asn1/oid.js';
import { base64ToBytes, bytesToHex, hexToBytes } from '../runtime/convert.js';
import * as sm3 from '../sm3/index.js';
import { CertificateError } from './errors.js';
import {
  parseAuthorityKeyIdentifier,
  parseBasicConstraints,
  parseExtendedKeyUsage,
  parseKeyUsage,
  parseSubjectAltName,
  parseSubjectKeyIdentifier,
} from './extensions.js';
import {
  NAME_OID_LABELS,
  OID_AUTHORITY_KEY_IDENTIFIER,
  OID_BASIC_CONSTRAINTS,
  OID_COMMON_NAME,
  OID_COUNTRY,
  OID_EMAIL_ADDRESS,
  OID_EXTENDED_KEY_USAGE,
  OID_ID_EC_PUBLIC_KEY,
  OID_KEY_USAGE,
  OID_LOCALITY,
  OID_ORGANIZATION,
  OID_ORGANIZATIONAL_UNIT,
  OID_RSA_ENCRYPTION,
  OID_RSA_SIGNATURE_PREFIX,
  OID_SM2_CURVE,
  OID_STATE,
  OID_SUBJECT_ALT_NAME,
  OID_SUBJECT_KEY_IDENTIFIER,
} from './oids.js';
import { sha256Hex } from './sha256.js';
import type {
  AlgorithmIdentifier,
  Certificate,
  CertificateInput,
  Extension,
  Name,
  NameAttribute,
  SubjectPublicKeyInfo,
  Validity,
} from './types.js';
import {
  isUsableSm2PublicKey,
  isWithinValidity,
  type VerifySignatureOptions,
  verifyCertificateSignature,
} from './verify.js';

// ---------- 公开入口 ----------

/**
 * 解析单张证书。
 *
 * @param input PEM 字符串、base64 字符串、hex 字符串或 DER 字节。
 * @throws CertificateError 结构非法、截断或尾部有多余字节。
 */
export function parseCertificate(input: CertificateInput): Certificate {
  const der = decodeCertificateInput(input);
  try {
    return certificateFromNode(parseDer(der));
  } catch (err) {
    if (err instanceof CertificateError) throw err;
    throw new CertificateError(`parseCertificate: ${errorMessage(err)}`, { cause: err });
  }
}

/**
 * 解析一个或多个证书（PEM bundle / 连续 DER）。
 *
 * @throws CertificateError 任一证书结构非法。
 */
export function parseCertificates(input: CertificateInput): Certificate[] {
  if (typeof input === 'string') {
    const text = input.trim();
    const blocks = extractPemBlocks(text);
    if (blocks.length > 0) {
      return blocks.map((block) => parseCertificate(block));
    }
    return [parseCertificate(text)];
  }
  if (isPemText(input)) {
    return parseCertificates(new TextDecoder().decode(input));
  }
  let nodes: Asn1Node[];
  try {
    nodes = parseDerAll(input);
  } catch (err) {
    throw new CertificateError(`parseCertificates: ${errorMessage(err)}`, { cause: err });
  }
  if (nodes.length === 0) throw new CertificateError('parseCertificates: empty input');
  return nodes.map((node) => {
    try {
      return certificateFromNode(node);
    } catch (err) {
      if (err instanceof CertificateError) throw err;
      throw new CertificateError(`parseCertificates: ${errorMessage(err)}`, { cause: err });
    }
  });
}

// ---------- 输入解码 ----------

function decodeCertificateInput(input: CertificateInput): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.length === 0) throw new CertificateError('parseCertificate: empty input');
    if (isPemText(input)) return decodeCertificateInput(new TextDecoder().decode(input));
    return input;
  }
  if (typeof input !== 'string') {
    throw new TypeError('parseCertificate: expected string or Uint8Array');
  }
  const text = input.trim();
  if (text.length === 0) throw new CertificateError('parseCertificate: empty input');
  const block = extractPemBlocks(text)[0];
  if (block !== undefined) return pemBodyToDer(block);

  // 非 PEM：依次尝试 hex 与 base64，以“能否解析出完整 DER 对象”为准。
  const candidates: Uint8Array[] = [];
  const compact = text.replace(/\s+/g, '');
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) {
    candidates.push(hexToBytes(compact, 'certificate'));
  }
  try {
    candidates.push(base64ToBytes(compact, 'certificate'));
  } catch {
    // 不是 base64；保留 hex 候选（若也没有，下面统一报错）。
  }
  for (const candidate of candidates) {
    try {
      parseDer(candidate);
      return candidate;
    } catch {
      // 换下一个候选。
    }
  }
  throw new CertificateError('parseCertificate: input is neither PEM, hex nor base64 DER');
}

function extractPemBlocks(text: string): string[] {
  const blocks: string[] = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  for (;;) {
    const match = re.exec(text);
    if (match === null) break;
    blocks.push(match[0]);
  }
  return blocks;
}

function pemBodyToDer(pem: string): Uint8Array {
  const match = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  if (match === null) throw new CertificateError('parseCertificate: missing CERTIFICATE PEM block');
  const body = (match[1] as string).replace(/\s+/g, '');
  try {
    return base64ToBytes(body, 'certificate');
  } catch (err) {
    throw new CertificateError('parseCertificate: invalid base64 in PEM block', { cause: err });
  }
}

function isPemText(bytes: Uint8Array): boolean {
  const prefix = '-----BEGIN ';
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix.charCodeAt(i)) return false;
  }
  return true;
}

// ---------- Certificate ----------

function certificateFromNode(top: Asn1Node): Certificate {
  const kids = expectSequence(top, 'Certificate');
  if (kids.length !== 3) {
    throw new CertificateError(`Certificate: expected 3 elements, got ${kids.length}`);
  }
  const tbsNode = expectUniversal(kids[0], UniversalTag.Sequence, 'tbsCertificate');
  const signatureAlgorithm = parseAlgorithmIdentifier(kids[1], 'signatureAlgorithm');
  const signatureValue = new Uint8Array(
    readBitString(
      expectUniversal(kids[2], UniversalTag.BitString, 'signatureValue'),
      'signatureValue',
    ).bytes,
  );

  const tbs = parseTbsCertificate(tbsNode);
  const raw = copy(top.raw);
  const publicKeyAlgorithm = classifyPublicKey(tbs.subjectPublicKeyInfo.algorithm);
  const subjectPublicKey = tbs.subjectPublicKeyInfo.publicKey;
  const supported =
    publicKeyAlgorithm === 'SM2' &&
    (subjectPublicKey.length === 64 ||
      (subjectPublicKey.length === 65 && subjectPublicKey[0] === 0x04));

  const extensions = tbs.extensions;
  const cert: Certificate = {
    version: tbs.version,
    serialNumber: tbs.serialNumber,
    serialNumberHex: tbs.serialNumber.toString(16),
    signatureAlgorithm,
    issuer: tbs.issuer,
    validity: tbs.validity,
    subject: tbs.subject,
    subjectPublicKeyInfo: tbs.subjectPublicKeyInfo,
    extensions,
    signatureValue,
    tbsCertificate: copy(tbsNode.raw),
    raw,

    subjectPublicKey,
    publicKeyAlgorithm,
    supported,

    keyUsage: extensionValue(extensions, OID_KEY_USAGE, parseKeyUsage),
    basicConstraints: extensionValue(extensions, OID_BASIC_CONSTRAINTS, parseBasicConstraints),
    subjectAltNames: extensionValue(extensions, OID_SUBJECT_ALT_NAME, parseSubjectAltName) ?? [],
    extendedKeyUsage:
      extensionValue(extensions, OID_EXTENDED_KEY_USAGE, parseExtendedKeyUsage) ?? [],
    subjectKeyIdentifier: extensionValue(
      extensions,
      OID_SUBJECT_KEY_IDENTIFIER,
      parseSubjectKeyIdentifier,
    ),
    authorityKeyIdentifier: extensionValue(
      extensions,
      OID_AUTHORITY_KEY_IDENTIFIER,
      parseAuthorityKeyIdentifier,
    ),

    getExtension(oid: string): Extension | undefined {
      return extensions.find((ext) => ext.oid === oid);
    },
    checkValidity(at: Date = new Date()): boolean {
      return isWithinValidity(cert.validity, at);
    },
    verifySignature(issuer: Certificate | Uint8Array, opts: VerifySignatureOptions = {}): boolean {
      if (!cert.supported) return false;
      const publicKey = resolveIssuerPublicKey(issuer);
      if (publicKey === null) return false;
      return verifyCertificateSignature(cert, publicKey, opts);
    },
    fingerprint(hash: 'sm3' | 'sha256' = 'sm3'): string {
      if (hash === 'sm3') return sm3.hash(raw);
      if (hash === 'sha256') return sha256Hex(raw);
      throw new TypeError(`fingerprint: unsupported hash "${String(hash)}"`);
    },
  };
  return cert;
}

interface ParsedTbs {
  version: 1 | 2 | 3;
  serialNumber: bigint;
  issuer: Name;
  validity: Validity;
  subject: Name;
  subjectPublicKeyInfo: SubjectPublicKeyInfo;
  extensions: Extension[];
}

function parseTbsCertificate(tbsNode: Asn1Node): ParsedTbs {
  const kids = expectSequence(tbsNode, 'TBSCertificate');
  let index = 0;

  let version: 1 | 2 | 3 = 1;
  const first = kids[0];
  if (first !== undefined && first.cls === Asn1Class.ContextSpecific && first.tag === 0) {
    const inner = first.children?.[0];
    const rawVersion = Number(readInteger(expectUniversal(inner, UniversalTag.Integer, 'version')));
    if (rawVersion < 0 || rawVersion > 2) {
      throw new CertificateError(`TBSCertificate: unsupported version ${rawVersion}`);
    }
    version = (rawVersion + 1) as 1 | 2 | 3;
    index = 1;
  }

  const serialNode = kids[index++];
  const serialNumber = serialNode
    ? readInteger(serialNode, 'serialNumber')
    : (() => {
        throw new CertificateError('TBSCertificate: missing serialNumber');
      })();

  // TBS 内签名算法（与外层应一致；这里只解析，不做强一致断言）。
  parseAlgorithmIdentifier(kids[index++], 'signature');
  const issuer = parseName(kids[index++], 'issuer');
  const validity = parseValidity(kids[index++]);
  const subject = parseName(kids[index++], 'subject');
  const spkiNode = expectUniversal(kids[index++], UniversalTag.Sequence, 'subjectPublicKeyInfo');
  const subjectPublicKeyInfo = parseSpki(spkiNode);

  let extensions: Extension[] = [];
  for (; index < kids.length; index++) {
    const node = kids[index];
    if (node === undefined) continue;
    if (node.cls === Asn1Class.ContextSpecific && node.tag === 3) {
      extensions = parseExtensions(node);
    }
    // [1] issuerUniqueID / [2] subjectUniqueID 与未知尾部字段：忽略。
  }

  return { version, serialNumber, issuer, validity, subject, subjectPublicKeyInfo, extensions };
}

function parseValidity(node: Asn1Node | undefined): Validity {
  const kids = expectSequence(node, 'validity');
  if (kids.length < 2) throw new CertificateError('validity: expected notBefore and notAfter');
  return {
    notBefore: readTime(kids[0] as Asn1Node, 'notBefore'),
    notAfter: readTime(kids[1] as Asn1Node, 'notAfter'),
  };
}

function parseSpki(node: Asn1Node): SubjectPublicKeyInfo {
  const kids = expectSequence(node, 'subjectPublicKeyInfo');
  if (kids.length < 2) throw new CertificateError('subjectPublicKeyInfo: missing public key');
  const algorithm = parseAlgorithmIdentifier(kids[0], 'subjectPublicKeyInfo.algorithm');
  const bits = readBitString(kids[1] as Asn1Node, 'subjectPublicKey');
  return {
    algorithm,
    publicKey: new Uint8Array(bits.bytes),
    raw: copy(node.raw),
  };
}

function parseAlgorithmIdentifier(node: Asn1Node | undefined, what: string): AlgorithmIdentifier {
  const kids = expectSequence(node, what);
  const first = kids[0];
  if (first === undefined) throw new CertificateError(`${what}: missing algorithm OID`);
  const oid = readOid(first, what);
  const parameterNode = kids[1];
  if (parameterNode === undefined) return { oid };
  return {
    oid,
    parameters: new Uint8Array(parameterNode.value),
    parametersRaw: copy(parameterNode.raw),
  };
}

// ---------- Name ----------

function parseName(node: Asn1Node | undefined, what: string): Name {
  const rdns = expectSequence(node, what);
  const attributes: NameAttribute[] = [];
  for (const rdn of rdns) {
    const set = expectUniversal(rdn, UniversalTag.Set, what);
    const atvs = set.children;
    if (!atvs) continue;
    for (const atv of atvs) {
      const parts = expectSequence(atv, what);
      const typeNode = parts[0];
      const valueNode = parts[1];
      if (typeNode === undefined || valueNode === undefined) {
        throw new CertificateError(`${what}: malformed AttributeTypeAndValue`);
      }
      attributes.push({
        oid: readOid(typeNode, what),
        value: decodeAttributeValue(valueNode),
        raw: copy(atv.raw),
      });
    }
  }
  const find = (oid: string): string | undefined =>
    attributes.find((attribute) => attribute.oid === oid)?.value;
  return {
    commonName: find(OID_COMMON_NAME),
    organization: find(OID_ORGANIZATION),
    organizationalUnit: find(OID_ORGANIZATIONAL_UNIT),
    country: find(OID_COUNTRY),
    state: find(OID_STATE),
    locality: find(OID_LOCALITY),
    emailAddress: find(OID_EMAIL_ADDRESS),
    attributes,
    raw: copy((node as Asn1Node).raw),
    toString(): string {
      return attributes.map((a) => formatNameAttribute(a.oid, a.value)).join(',');
    },
  };
}

function decodeAttributeValue(node: Asn1Node): string {
  try {
    return readString(node, 'Name attribute');
  } catch {
    // 未知字符串类型（如私有编码）：保留原始内容，绝不抛错。
    return `#${bytesToHex(node.value)}`;
  }
}

function formatNameAttribute(oid: string, value: string): string {
  const label = NAME_OID_LABELS[oid] ?? oid;
  return `${label}=${escapeRdnValue(value)}`;
}

/** RFC 4514 的最小转义集。 */
function escapeRdnValue(value: string): string {
  let out = value.replace(/([,+"\\<>;])/g, '\\$1');
  if (out.startsWith(' ')) out = `\\${out}`;
  if (out.endsWith(' ')) out = `${out.slice(0, -1)}\\ `;
  if (out.startsWith('#')) out = `\\${out}`;
  return out;
}

// ---------- Extensions ----------

function parseExtensions(node: Asn1Node): Extension[] {
  const inner = node.children?.[0];
  const listNode = expectUniversal(inner, UniversalTag.Sequence, 'extensions');
  const entries = listNode.children ?? [];
  return entries.map((entry) => {
    const kids = expectSequence(entry, 'Extension');
    const oidNode = kids[0];
    if (oidNode === undefined) throw new CertificateError('Extension: missing OID');
    const oid = readOid(oidNode, 'Extension');
    let index = 1;
    let critical = false;
    const criticalNode = kids[index];
    if (
      criticalNode !== undefined &&
      criticalNode.cls === Asn1Class.Universal &&
      criticalNode.tag === UniversalTag.Boolean
    ) {
      critical = readBoolean(criticalNode, 'Extension.critical');
      index++;
    }
    const valueNode = kids[index];
    if (valueNode === undefined) throw new CertificateError(`Extension ${oid}: missing value`);
    return {
      oid,
      critical,
      value: new Uint8Array(readOctetString(valueNode, `Extension ${oid}`)),
      raw: copy(entry.raw),
    };
  });
}

function extensionValue<T>(
  extensions: readonly Extension[],
  oid: string,
  parse: (value: Uint8Array) => T,
): T | undefined {
  const extension = extensions.find((item) => item.oid === oid);
  if (extension === undefined) return undefined;
  try {
    return parse(extension.value);
  } catch {
    // 已知扩展损坏 → 视为缺失（红线 #9：不让真实证书解析失败）。
    return undefined;
  }
}

// ---------- 辅助 ----------

function classifyPublicKey(algorithm: AlgorithmIdentifier): 'SM2' | 'RSA' | 'UNKNOWN' {
  if (algorithm.oid === OID_SM2_CURVE) return 'SM2';
  if (algorithm.oid === OID_ID_EC_PUBLIC_KEY) {
    if (algorithm.parameters === undefined) return 'UNKNOWN';
    try {
      return decodeOid(algorithm.parameters) === OID_SM2_CURVE ? 'SM2' : 'UNKNOWN';
    } catch {
      return 'UNKNOWN';
    }
  }
  if (algorithm.oid === OID_RSA_ENCRYPTION || algorithm.oid.startsWith(OID_RSA_SIGNATURE_PREFIX)) {
    return 'RSA';
  }
  return 'UNKNOWN';
}

function resolveIssuerPublicKey(issuer: Certificate | Uint8Array): Uint8Array | null {
  if (isCertificateLike(issuer)) return issuer.subjectPublicKey;
  if (issuer.length === 64 || issuer.length === 65) {
    return isUsableSm2PublicKey(issuer) ? issuer : null;
  }
  try {
    return parseCertificate(issuer).subjectPublicKey;
  } catch {
    return null;
  }
}

function isCertificateLike(value: Certificate | Uint8Array): value is Certificate {
  return (
    typeof value === 'object' &&
    value !== null &&
    'tbsCertificate' in value &&
    'subjectPublicKey' in value
  );
}

function copy(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

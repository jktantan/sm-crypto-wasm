/**
 * X.509 证书 DER 编码（签发侧）。
 *
 * 只负责把结构化输入编码为 RFC 5280 证书；签名算法固定为 SM3withSM2。
 * 编码复用 `src/asn1/`，不重复实现任何算法。
 *
 * X.509 certificate DER encoding (issuance side).
 *
 * Only encodes structured input into an RFC 5280 certificate; the signature
 * algorithm is fixed to SM3withSM2. Encoding reuses `src/asn1/` and does not
 * reimplement any algorithm.
 */

import {
  type Asn1Node,
  bitString,
  boolean,
  explicit,
  ia5String,
  implicit,
  integer,
  octetString,
  oid,
  printableString,
  seq,
  set,
  time,
  utf8String,
} from '../asn1/index.js';
import { CertificateError } from './errors.js';
import { parseIpAddress } from './ip.js';
import {
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
  OID_SM2_CURVE,
  OID_SM3_WITH_SM2,
  OID_STATE,
  OID_SUBJECT_ALT_NAME,
  OID_SUBJECT_KEY_IDENTIFIER,
} from './oids.js';
import type {
  BasicConstraintsInput,
  DistinguishedNameInput,
  SubjectAltNameInput,
  Validity,
} from './types.js';

/**
 * KeyUsage 的位顺序（RFC 5280）。
 *
 * KeyUsage bit order (RFC 5280).
 */
const KEY_USAGE_ORDER = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
] as const;

/**
 * 待编码的一个扩展。
 *
 * One extension waiting to be encoded.
 */
export interface EncodedExtension {
  readonly oid: string;
  readonly critical: boolean;
  readonly value: Uint8Array;
}

/**
 * 编码 Name（RDNSequence）。
 *
 * Encodes a Name (RDNSequence).
 */
export function encodeName(dn: DistinguishedNameInput): Asn1Node {
  const rdns: Asn1Node[] = [];
  const add = (
    value: string | undefined,
    attrOid: string,
    encodeValue: (v: string) => Asn1Node,
  ) => {
    if (value === undefined || value.length === 0) return;
    rdns.push(set([seq([oid(attrOid), encodeValue(value)])]));
  };
  add(dn.country, OID_COUNTRY, printableString);
  add(dn.state, OID_STATE, utf8String);
  add(dn.locality, OID_LOCALITY, utf8String);
  add(dn.organization, OID_ORGANIZATION, utf8String);
  add(dn.organizationalUnit, OID_ORGANIZATIONAL_UNIT, utf8String);
  add(dn.commonName, OID_COMMON_NAME, utf8String);
  add(dn.emailAddress, OID_EMAIL_ADDRESS, ia5String);
  if (rdns.length === 0) {
    throw new CertificateError('Name: at least one attribute is required');
  }
  return seq(rdns);
}

/**
 * 编码 SM2 的 SubjectPublicKeyInfo。
 *
 * Encodes the SubjectPublicKeyInfo for SM2.
 */
export function encodeSubjectPublicKeyInfo(publicKey: Uint8Array): Asn1Node {
  const point = normalizePublicKey(publicKey);
  return seq([seq([oid(OID_ID_EC_PUBLIC_KEY), oid(OID_SM2_CURVE)]), bitString(point)]);
}

/**
 * 编码 Validity。
 *
 * Encodes Validity.
 */
export function encodeValidity(validity: Validity): Asn1Node {
  return seq([time(validity.notBefore), time(validity.notAfter)]);
}

/**
 * 编码 AlgorithmIdentifier（SM3withSM2，无参数）。
 *
 * Encodes the AlgorithmIdentifier (SM3withSM2, no parameters).
 */
export function encodeSignatureAlgorithm(): Asn1Node {
  return seq([oid(OID_SM3_WITH_SM2)]);
}

/**
 * 编码 BasicConstraints 的 extnValue。
 *
 * Encodes the extnValue of BasicConstraints.
 */
export function encodeBasicConstraints(input: BasicConstraintsInput): Uint8Array {
  if (!input.ca && input.pathLen !== undefined) {
    throw new RangeError('basicConstraints.pathLen is only valid for CA certificates');
  }
  if (input.pathLen !== undefined && (!Number.isInteger(input.pathLen) || input.pathLen < 0)) {
    throw new RangeError(`basicConstraints.pathLen must be a non-negative integer`);
  }
  const children: Asn1Node[] = [];
  if (input.ca) children.push(boolean(true));
  if (input.pathLen !== undefined) children.push(integer(BigInt(input.pathLen)));
  return seq(children).raw;
}

/**
 * 编码 KeyUsage 的 extnValue（BIT STRING）。
 *
 * Encodes the extnValue of KeyUsage as a BIT STRING.
 */
export function encodeKeyUsage(names: readonly string[]): Uint8Array {
  let maxBit = -1;
  for (const name of names) {
    const index = KEY_USAGE_ORDER.indexOf(name as (typeof KEY_USAGE_ORDER)[number]);
    if (index < 0) throw new CertificateError(`keyUsage: unknown bit "${name}"`);
    if (index > maxBit) maxBit = index;
  }
  if (maxBit < 0) throw new CertificateError('keyUsage: at least one bit is required');
  const bytes = new Uint8Array(Math.floor(maxBit / 8) + 1);
  for (const name of names) {
    const index = KEY_USAGE_ORDER.indexOf(name as (typeof KEY_USAGE_ORDER)[number]);
    const byteIndex = Math.floor(index / 8);
    bytes[byteIndex] = (bytes[byteIndex] as number) | (0x80 >> (index % 8));
  }
  const unusedBits = bytes.length * 8 - (maxBit + 1);
  return bitString(bytes, unusedBits).raw;
}

/**
 * 编码 ExtendedKeyUsage 的 extnValue（SEQUENCE OF OID）。
 *
 * Encodes the extnValue of ExtendedKeyUsage (SEQUENCE OF OID).
 */
export function encodeExtendedKeyUsage(oids: readonly string[]): Uint8Array {
  return seq(oids.map((value) => oid(value))).raw;
}

/**
 * 编码 SubjectAltName 的 extnValue（SEQUENCE OF GeneralName）。
 *
 * Encodes the extnValue of SubjectAltName (SEQUENCE OF GeneralName).
 */
export function encodeSubjectAltName(names: readonly SubjectAltNameInput[]): Uint8Array {
  return seq(names.map(encodeGeneralName)).raw;
}

// 编码 GeneralName。
//
// Encodes a GeneralName.
function encodeGeneralName(name: SubjectAltNameInput): Asn1Node {
  switch (name.type) {
    case 'dns':
      return implicit(2, ia5String(name.value));
    case 'ip':
      return implicit(7, octetString(parseIpAddress(name.value)));
    case 'email':
      return implicit(1, ia5String(name.value));
    case 'uri':
      return implicit(6, ia5String(name.value));
    default: {
      const exhaustive: never = name.type;
      throw new CertificateError(`subjectAltName: unknown type ${String(exhaustive)}`);
    }
  }
}

/**
 * 编码 SubjectKeyIdentifier 的 extnValue（OCTET STRING）。
 *
 * Encodes the extnValue of SubjectKeyIdentifier (OCTET STRING).
 */
export function encodeSubjectKeyIdentifier(keyIdentifier: Uint8Array): Uint8Array {
  return octetString(keyIdentifier).raw;
}

/**
 * 编码 AuthorityKeyIdentifier 的 extnValue（[0] keyIdentifier）。
 *
 * Encodes the extnValue of AuthorityKeyIdentifier ([0] keyIdentifier).
 */
export function encodeAuthorityKeyIdentifier(keyIdentifier: Uint8Array): Uint8Array {
  return seq([implicit(0, octetString(keyIdentifier))]).raw;
}

/**
 * 把扩展列表编码为 `[3] EXPLICIT Extensions`。
 *
 * Encodes the extension list as `[3] EXPLICIT Extensions`.
 */
export function encodeExtensions(extensions: readonly EncodedExtension[]): Asn1Node {
  const entries = extensions.map((ext) => {
    const children: Asn1Node[] = [oid(ext.oid)];
    if (ext.critical) children.push(boolean(true));
    children.push(octetString(ext.value));
    return seq(children);
  });
  return explicit(3, seq(entries));
}

/**
 * 编码 TBSCertificate。
 *
 * Encodes a TBSCertificate.
 */
export function encodeTbsCertificate(input: {
  version: 1 | 2 | 3;
  serialNumber: bigint;
  issuer: DistinguishedNameInput;
  validity: Validity;
  subject: DistinguishedNameInput;
  publicKey: Uint8Array;
  extensions: readonly EncodedExtension[];
}): Asn1Node {
  const children: Asn1Node[] = [
    explicit(0, integer(BigInt(input.version - 1))),
    integer(input.serialNumber),
    encodeSignatureAlgorithm(),
    encodeName(input.issuer),
    encodeValidity(input.validity),
    encodeName(input.subject),
    encodeSubjectPublicKeyInfo(input.publicKey),
  ];
  if (input.extensions.length > 0) {
    children.push(encodeExtensions(input.extensions));
  }
  return seq(children);
}

/**
 * 组装 Certificate ::= SEQUENCE { tbs, signatureAlgorithm, signatureValue }。
 *
 * Assembles Certificate ::= SEQUENCE { tbs, signatureAlgorithm, signatureValue }.
 */
export function encodeCertificate(tbs: Asn1Node, signatureDer: Uint8Array): Uint8Array {
  return seq([tbs, encodeSignatureAlgorithm(), bitString(signatureDer)]).raw;
}

/**
 * 64/65 字节公钥 → 65 字节未压缩点。
 *
 * A 64/65-byte public key to the 65-byte uncompressed point form.
 */
export function normalizePublicKey(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length === 65 && publicKey[0] === 0x04) return new Uint8Array(publicKey);
  if (publicKey.length === 64) {
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(publicKey, 1);
    return out;
  }
  throw new CertificateError('publicKey: expected 64 or 65 (uncompressed) bytes');
}

/**
 * 扩展 OID 常量（供签发逻辑使用）。
 *
 * Extension OID constants, used by the issuance logic.
 */
export const EXTENSION_OIDS = {
  basicConstraints: OID_BASIC_CONSTRAINTS,
  keyUsage: OID_KEY_USAGE,
  extendedKeyUsage: OID_EXTENDED_KEY_USAGE,
  subjectAltName: OID_SUBJECT_ALT_NAME,
  subjectKeyIdentifier: OID_SUBJECT_KEY_IDENTIFIER,
  authorityKeyIdentifier: OID_AUTHORITY_KEY_IDENTIFIER,
} as const;

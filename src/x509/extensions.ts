/**
 * X.509 扩展解析。
 *
 * 原则（红线 #9）：未知扩展、未知值类型一律保留原始字节，不抛错；
 * 已知扩展内容损坏时返回 `undefined`，由调用方按“扩展缺失”处理。
 */

import {
  Asn1Class,
  type Asn1Node,
  expectSequence,
  parseDer,
  readBitString,
  readOctetString,
  readOid,
  readString,
  UniversalTag,
} from '../asn1/index.js';
import { bytesToHex } from '../runtime/convert.js';
import {
  OID_AUTHORITY_KEY_IDENTIFIER,
  OID_BASIC_CONSTRAINTS,
  OID_EXTENDED_KEY_USAGE,
  OID_KEY_USAGE,
  OID_SUBJECT_ALT_NAME,
  OID_SUBJECT_KEY_IDENTIFIER,
} from './oids.js';
import type { AuthorityKeyIdentifier, BasicConstraints, GeneralName, KeyUsage } from './types.js';

/** 解析 KeyUsage（BIT STRING）。 */
export function parseKeyUsage(value: Uint8Array): KeyUsage {
  const node = parseExtensionValue(value, 'KeyUsage');
  const bits = readBitString(node, 'KeyUsage');
  const get = (index: number): boolean => {
    const byte = bits.bytes[Math.floor(index / 8)];
    if (byte === undefined) return false;
    return ((byte >> (7 - (index % 8))) & 1) === 1;
  };
  return {
    digitalSignature: get(0),
    nonRepudiation: get(1),
    keyEncipherment: get(2),
    dataEncipherment: get(3),
    keyAgreement: get(4),
    keyCertSign: get(5),
    cRLSign: get(6),
    encipherOnly: get(7),
    decipherOnly: get(8),
  };
}

/** 解析 BasicConstraints。 */
export function parseBasicConstraints(value: Uint8Array): BasicConstraints {
  const node = parseExtensionValue(value, 'BasicConstraints');
  const children = expectSequence(node, 'BasicConstraints');
  let ca = false;
  let pathLen: number | undefined;
  let index = 0;
  const first = children[0];
  if (first !== undefined && first.cls === Asn1Class.Universal && first.tag === 1) {
    if (first.value.length !== 1) throw new Error('BasicConstraints: bad BOOLEAN');
    ca = (first.value[0] as number) !== 0;
    index = 1;
  }
  const lenNode = children[index];
  if (lenNode !== undefined) {
    if (lenNode.cls !== Asn1Class.Universal || lenNode.tag !== UniversalTag.Integer) {
      throw new Error('BasicConstraints: pathLenConstraint is not INTEGER');
    }
    let n = 0;
    for (let i = 0; i < lenNode.value.length; i++) {
      n = n * 256 + (lenNode.value[i] as number);
      if (!Number.isSafeInteger(n)) throw new Error('BasicConstraints: pathLen too large');
    }
    pathLen = n;
  }
  return pathLen === undefined ? { ca } : { ca, pathLen };
}

/** 解析 SubjectAltName（SEQUENCE OF GeneralName）。 */
export function parseSubjectAltName(value: Uint8Array): GeneralName[] {
  const node = parseExtensionValue(value, 'SubjectAltName');
  const children = expectSequence(node, 'SubjectAltName');
  return children.map(parseGeneralName);
}

/** 解析 SubjectKeyIdentifier（OCTET STRING）。 */
export function parseSubjectKeyIdentifier(value: Uint8Array): Uint8Array {
  const node = parseExtensionValue(value, 'SubjectKeyIdentifier');
  return new Uint8Array(readOctetString(node, 'SubjectKeyIdentifier'));
}

/** 解析 AuthorityKeyIdentifier。 */
export function parseAuthorityKeyIdentifier(value: Uint8Array): AuthorityKeyIdentifier {
  const node = parseExtensionValue(value, 'AuthorityKeyIdentifier');
  const children = expectSequence(node, 'AuthorityKeyIdentifier');
  let keyIdentifier: Uint8Array | undefined;
  let authorityCertSerialNumber: bigint | undefined;
  for (const child of children) {
    if (child.cls !== Asn1Class.ContextSpecific) continue;
    if (child.tag === 0) {
      keyIdentifier = new Uint8Array(child.value);
    } else if (child.tag === 2) {
      authorityCertSerialNumber = positiveIntegerFromBytes(child.value);
    }
  }
  return authorityCertSerialNumber === undefined
    ? keyIdentifier === undefined
      ? {}
      : { keyIdentifier }
    : keyIdentifier === undefined
      ? { authorityCertSerialNumber }
      : { keyIdentifier, authorityCertSerialNumber };
}

/** 解析 ExtendedKeyUsage（SEQUENCE OF OID）。 */
export function parseExtendedKeyUsage(value: Uint8Array): string[] {
  const node = parseExtensionValue(value, 'ExtendedKeyUsage');
  const children = expectSequence(node, 'ExtendedKeyUsage');
  return children.map((child) => readOid(child, 'ExtendedKeyUsage'));
}

/**
 * 按扩展 OID 解析已知扩展；未知 OID 返回 `undefined`，不抛错。
 *
 * @internal 供 `parse.ts` 与签发逻辑复用。
 */
export function parseKnownExtension(
  oid: string,
  value: Uint8Array,
):
  | KeyUsage
  | BasicConstraints
  | GeneralName[]
  | Uint8Array
  | AuthorityKeyIdentifier
  | string[]
  | undefined {
  try {
    switch (oid) {
      case OID_KEY_USAGE:
        return parseKeyUsage(value);
      case OID_BASIC_CONSTRAINTS:
        return parseBasicConstraints(value);
      case OID_SUBJECT_ALT_NAME:
        return parseSubjectAltName(value);
      case OID_SUBJECT_KEY_IDENTIFIER:
        return parseSubjectKeyIdentifier(value);
      case OID_AUTHORITY_KEY_IDENTIFIER:
        return parseAuthorityKeyIdentifier(value);
      case OID_EXTENDED_KEY_USAGE:
        return parseExtendedKeyUsage(value);
      default:
        return undefined;
    }
  } catch {
    // 已知扩展损坏：按“扩展缺失”处理，绝不让整张证书解析失败。
    return undefined;
  }
}

function parseExtensionValue(value: Uint8Array, what: string): Asn1Node {
  try {
    return parseDer(value);
  } catch (err) {
    throw new Error(`${what}: invalid extension value`, { cause: err });
  }
}

function parseGeneralName(node: Asn1Node): GeneralName {
  if (node.cls !== Asn1Class.ContextSpecific) {
    throw new Error(`GeneralName: unexpected class ${node.cls}`);
  }
  const raw = node.raw;
  switch (node.tag) {
    case 1:
      return { type: 'email', value: readString(asStringNode(node), 'GeneralName'), raw };
    case 2:
      return { type: 'dns', value: readString(asStringNode(node), 'GeneralName'), raw };
    case 6:
      return { type: 'uri', value: readString(asStringNode(node), 'GeneralName'), raw };
    case 7:
      return { type: 'ip', value: formatIp(node.value), raw };
    default:
      return { type: 'other', tag: node.tag, value: `#${bytesToHex(node.value)}`, raw };
  }
}

/** IMPLICIT IA5String：把内容字节包装成 UNIVERSAL IA5String 节点供 readString 使用。 */
function asStringNode(node: Asn1Node): Asn1Node {
  return {
    cls: Asn1Class.Universal,
    tag: UniversalTag.Ia5String,
    constructed: false,
    indefinite: false,
    length: node.value.length,
    value: node.value,
    raw: node.raw,
  };
}

/** 4 字节 IPv4 / 16 字节 IPv6 → 文本。 */
export function formatIp(bytes: Uint8Array): string {
  if (bytes.length === 4) {
    return `${bytes[0] as number}.${bytes[1] as number}.${bytes[2] as number}.${bytes[3] as number}`;
  }
  if (bytes.length !== 16) return `#${bytesToHex(bytes)}`;
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((bytes[i] as number) << 8) | (bytes[i + 1] as number));
  }
  // 找出最长的一段连续 0（长度 >= 2）压缩为 `::`。
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(':');
  const left = groups
    .slice(0, bestStart)
    .map((g) => g.toString(16))
    .join(':');
  const right = groups
    .slice(bestStart + bestLen)
    .map((g) => g.toString(16))
    .join(':');
  return `${left}::${right}`;
}

/** 正 INTEGER 内容字节 → bigint（用于 [2] IMPLICIT INTEGER）。 */
function positiveIntegerFromBytes(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v = (v << 8n) | BigInt(bytes[i] as number);
  return v;
}

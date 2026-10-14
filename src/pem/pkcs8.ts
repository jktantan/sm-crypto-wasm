/**
 * PKCS#8 PrivateKeyInfo 与 SPKI SubjectPublicKeyInfo 解析/编码。
 *
 * spec/plan 对应：plan Task 4；spec §12.1 Q3。
 *
 * 涉及类型：
 * - PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier, privateKey OCTET STRING [, attributes ...] }
 * - SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
 * - AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY DEFINED BY algorithm OPTIONAL }
 *
 * 本仓库只支持"parameters = NULL"这一类算法（SM2 / SM9 都符合）。
 */

import { InvalidKeyError } from '../runtime/errors.js';
import { asn1Int, asn1Null, asn1Octets, asn1Oid, asn1Seq, parseDer } from './asn1.js';

/**
 * PrivateKeyInfo 的最小化解析结果。
 */
export interface ParsedPrivateKey {
  /** 算法 OID，如 `"1.2.156.10197.1.100"`（SM9）。 */
  readonly algorithmOid: string;
  /** 原始私钥字节（EC privateKey OCTET STRING 内容，含可选 public-key 拼接）。 */
  readonly privateKey: Uint8Array;
}

/** 编码 PrivateKeyInfo PEM。 */
export function encodePkcs8PrivateKey(algorithmOid: string, privateKey: Uint8Array): string {
  const seq = asn1Seq([
    asn1Int(0),
    asn1Seq([asn1Oid(algorithmOid), asn1Null()]),
    asn1Octets(privateKey),
  ]);
  return derToPem(seq.raw, 'PRIVATE KEY');
}

/** 解析 PRIVATE KEY PEM。 */
export function parsePkcs8PrivateKey(pem: string): ParsedPrivateKey {
  const seq = parseDer(pemToDer(pem));
  if (seq.tag !== 0x10) {
    // SEQUENCE = 0x10 in low-tag form (constructed context-specific) but
    // UNIVERSAL SEQUENCE is 0x30. asn1.ts 把 tag 数字按 UNIVERSAL 存。
    throw new InvalidKeyError('parsePkcs8PrivateKey: top-level is not SEQUENCE');
  }
  if (!seq.children || seq.children.length < 3) {
    throw new InvalidKeyError('parsePkcs8PrivateKey: PrivateKeyInfo needs at least 3 elements');
  }
  const [version, algId, privateKeyOctets] = seq.children;
  if (version?.tag !== 0x02) {
    throw new InvalidKeyError('parsePkcs8PrivateKey: missing version INTEGER');
  }
  if (version.value[0] !== 0) {
    throw new InvalidKeyError(`parsePkcs8PrivateKey: unsupported version ${version.value[0]}`);
  }
  if (!algId?.children || algId.children.length < 1) {
    throw new InvalidKeyError('parsePkcs8PrivateKey: missing AlgorithmIdentifier');
  }
  const oidNode = algId.children[0];
  if (oidNode?.tag !== 0x06) {
    throw new InvalidKeyError('parsePkcs8PrivateKey: missing algorithm OID');
  }
  if (privateKeyOctets?.tag !== 0x04) {
    throw new InvalidKeyError('parsePkcs8PrivateKey: missing privateKey OCTET STRING');
  }
  return {
    algorithmOid: decodeOidFromNode(oidNode),
    privateKey: privateKeyOctets.value,
  };
}

/** SPKI 解析结果。 */
export interface ParsedPublicKey {
  readonly algorithmOid: string;
  /** 公钥 BIT STRING 内容。对 EC 类算法：未使用字节 0x00 + X || Y（66 字节）。 */
  readonly publicKey: Uint8Array;
}

/** 编码 SPKI PEM（算法 OID + 公钥 BIT STRING）。 */
export function encodeSpkiPublicKey(algorithmOid: string, publicKey: Uint8Array): string {
  // BIT STRING：未使用位 = 0，前缀一字节 0x00。
  const bitStringValue = new Uint8Array(publicKey.length + 1);
  bitStringValue.set(publicKey, 1);
  const seq = asn1Seq([
    asn1Seq([asn1Oid(algorithmOid), asn1Null()]),
    bitStringNode(bitStringValue),
  ]);
  return derToPem(seq.raw, 'PUBLIC KEY');
}

/** 解析 PUBLIC KEY PEM。 */
export function parseSpkiPublicKey(pem: string): ParsedPublicKey {
  const seq = parseDer(pemToDer(pem));
  if (seq.tag !== 0x10) {
    throw new InvalidKeyError('parseSpkiPublicKey: top-level is not SEQUENCE');
  }
  if (!seq.children || seq.children.length < 2) {
    throw new InvalidKeyError('parseSpkiPublicKey: SPKI needs at least 2 elements');
  }
  const algId = seq.children[0];
  const bitString = seq.children[1];
  if (!algId?.children || algId.children.length < 1) {
    throw new InvalidKeyError('parseSpkiPublicKey: missing AlgorithmIdentifier');
  }
  const oidNode = algId.children[0];
  if (oidNode?.tag !== 0x06) {
    throw new InvalidKeyError('parseSpkiPublicKey: missing algorithm OID');
  }
  if (bitString?.tag !== 0x03) {
    throw new InvalidKeyError('parseSpkiPublicKey: missing BIT STRING');
  }
  // 去掉 BIT STRING 第一个字节的"未使用位"计数（我们固定为 0）。
  const inner = bitString.value.subarray(1);
  return {
    algorithmOid: decodeOidFromNode(oidNode),
    publicKey: inner,
  };
}

// ----------------- 内部 -----------------

function decodeOidFromNode(node: { tag: number; value: Uint8Array }): string {
  if (node.tag !== 0x06) throw new InvalidKeyError('decodeOidFromNode: not OID');
  const first = node.value[0] ?? 0;
  const a = Math.floor(first / 40);
  const b = first % 40;
  const parts: number[] = [a, b];
  let value = 0;
  for (let i = 1; i < node.value.length; i++) {
    const octet = node.value[i] ?? 0;
    value = (value << 7) | (octet & 0x7f);
    if ((octet & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  if (value !== 0) throw new InvalidKeyError('decodeOid: truncated');
  return parts.join('.');
}

function pemToDer(pem: string): Uint8Array {
  const lines = pem.split(/\r?\n/);
  const body: string[] = [];
  let hasBegin = false;
  let hasEnd = false;
  for (const line of lines) {
    if (line.startsWith('-----BEGIN')) {
      hasBegin = true;
      continue;
    }
    if (line.startsWith('-----END')) {
      hasEnd = true;
      continue;
    }
    if (line.trim().length > 0) body.push(line.trim());
  }
  if (!hasBegin || !hasEnd) {
    throw new InvalidKeyError('pemToDer: missing BEGIN/END markers');
  }
  const b64 = body.join('');
  return base64ToBytes(b64);
}

function derToPem(der: Uint8Array, kind: string): string {
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${kind}-----\n${lines.join('\n')}\n-----END ${kind}-----\n`;
}

function bitStringNode(value: Uint8Array): {
  tag: number;
  length: number;
  value: Uint8Array;
  raw: Uint8Array;
  cls: number;
} {
  const lengthBytes = encodeLen(value.length);
  const raw = new Uint8Array(1 + lengthBytes.length + value.length);
  raw[0] = 0x03;
  for (let i = 0; i < lengthBytes.length; i++) raw[1 + i] = lengthBytes[i] ?? 0;
  for (let i = 0; i < value.length; i++) {
    raw[1 + lengthBytes.length + i] = value[i] ?? 0;
  }
  return { cls: 0, tag: 0x03, length: value.length, value, raw };
}

function encodeLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] ?? 0);
    return btoa(bin);
  }
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

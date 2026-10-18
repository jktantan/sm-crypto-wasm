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
 *
 * PKCS#8 PrivateKeyInfo and SPKI SubjectPublicKeyInfo parsing/encoding.
 *
 * spec/plan: plan Task 4; spec §12.1 Q3.
 *
 * Types involved:
 * - PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier,
 *   privateKey OCTET STRING [, attributes ...] }
 * - SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING }
 * - AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY DEFINED BY
 *   algorithm OPTIONAL }
 *
 * This repository only supports algorithms of the "parameters = NULL" kind (both SM2
 * and SM9 qualify).
 */

import { base64ToBytes, bytesToBase64 } from '../runtime/convert.js';
import { InvalidKeyError } from '../runtime/errors.js';
import { asn1Int, asn1Null, asn1Octets, asn1Oid, asn1Seq, parseDer } from './asn1.js';

/**
 * PrivateKeyInfo 的最小化解析结果。
 *
 * The minimally parsed result of a PrivateKeyInfo.
 */
export interface ParsedPrivateKey {
  /**
   * 算法 OID，如 `"1.2.156.10197.1.100"`（SM9）。
   *
   * Algorithm OID, e.g. `"1.2.156.10197.1.100"` (SM9).
   */
  readonly algorithmOid: string;
  /**
   * 原始私钥字节（EC privateKey OCTET STRING 内容，含可选 public-key 拼接）。
   *
   * Raw private key bytes (the contents of the EC privateKey OCTET STRING, including an
   * optional concatenated public key).
   */
  readonly privateKey: Uint8Array;
}

/**
 * 编码 PrivateKeyInfo PEM。
 *
 * Encodes a PrivateKeyInfo PEM.
 */
export function encodePkcs8PrivateKey(algorithmOid: string, privateKey: Uint8Array): string {
  const seq = asn1Seq([
    asn1Int(0),
    asn1Seq([asn1Oid(algorithmOid), asn1Null()]),
    asn1Octets(privateKey),
  ]);
  return derToPem(seq.raw, 'PRIVATE KEY');
}

/**
 * 解析 PRIVATE KEY PEM。
 *
 * Parses a PRIVATE KEY PEM.
 */
export function parsePkcs8PrivateKey(pem: string): ParsedPrivateKey {
  const seq = parseDer(pemToDer(pem));
  if (seq.tag !== 0x10) {
    // `src/asn1` 存的是 UNIVERSAL tag 编号（SEQUENCE = 16 = 0x10），不是首字节
    // 0x30，因此这里按编号比较。
    //
    // `src/asn1` stores the UNIVERSAL tag number (SEQUENCE = 16 = 0x10) rather than
    // the leading byte 0x30, so the comparison uses the number.
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

/**
 * SPKI 解析结果。
 *
 * The parsed result of an SPKI.
 */
export interface ParsedPublicKey {
  /**
   * 算法 OID，如 `"1.2.156.10197.1.100"`（SM9）。
   *
   * Algorithm OID, e.g. `"1.2.156.10197.1.100"` (SM9).
   */
  readonly algorithmOid: string;
  /**
   * 公钥 BIT STRING 内容。对 EC 类算法：未使用字节 0x00 + X || Y（66 字节）。
   *
   * Contents of the public key BIT STRING. For EC-like algorithms: the unused-bits byte
   * 0x00 followed by X || Y (66 bytes).
   */
  readonly publicKey: Uint8Array;
}

/**
 * 编码 SPKI PEM（算法 OID + 公钥 BIT STRING）。
 *
 * Encodes an SPKI PEM (algorithm OID + public key BIT STRING).
 */
export function encodeSpkiPublicKey(algorithmOid: string, publicKey: Uint8Array): string {
  // BIT STRING：未使用位 = 0，前缀一字节 0x00。
  //
  // BIT STRING: zero unused bits, prefixed with a single 0x00 byte.
  const bitStringValue = new Uint8Array(publicKey.length + 1);
  bitStringValue.set(publicKey, 1);
  const seq = asn1Seq([
    asn1Seq([asn1Oid(algorithmOid), asn1Null()]),
    bitStringNode(bitStringValue),
  ]);
  return derToPem(seq.raw, 'PUBLIC KEY');
}

/**
 * 解析 PUBLIC KEY PEM。
 *
 * Parses a PUBLIC KEY PEM.
 */
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
  //
  // Strip the leading unused-bit count of the BIT STRING (always 0 in our encoding).
  const inner = bitString.value.subarray(1);
  return {
    algorithmOid: decodeOidFromNode(oidNode),
    publicKey: inner,
  };
}

// ----------------- 内部 -----------------
//
// ----------------- Internals -----------------

// 从 ASN.1 节点解码 OID。
//
// Decodes an OID from an ASN.1 node.
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

// PEM → DER。
//
// PEM to DER.
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

// DER → PEM。
//
// DER to PEM.
function derToPem(der: Uint8Array, kind: string): string {
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${kind}-----\n${lines.join('\n')}\n-----END ${kind}-----\n`;
}

// 构造 BIT STRING 节点。
//
// Builds a BIT STRING node.
function bitStringNode(value: Uint8Array): {
  tag: number;
  length: number;
  value: Uint8Array;
  raw: Uint8Array;
  cls: 0;
  constructed: false;
  indefinite: false;
} {
  const lengthBytes = encodeLen(value.length);
  const raw = new Uint8Array(1 + lengthBytes.length + value.length);
  raw[0] = 0x03;
  for (let i = 0; i < lengthBytes.length; i++) raw[1 + i] = lengthBytes[i] ?? 0;
  for (let i = 0; i < value.length; i++) {
    raw[1 + lengthBytes.length + i] = value[i] ?? 0;
  }
  return {
    cls: 0,
    tag: 0x03,
    constructed: false,
    indefinite: false,
    length: value.length,
    value,
    raw,
  };
}

// 编码 DER 长度。
//
// Encodes a DER length.
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

// base64 编解码统一走 `../runtime/convert.js` 的跨运行时实现（Node 走 Buffer
// 快路径、浏览器回落 btoa/atob）；本文件原先自带一份，其 Node 分支直接引用了
// `Buffer`，在浏览器里会 ReferenceError。
//
// base64 encoding/decoding goes through the cross-runtime implementation in
// `../runtime/convert.js` (a Buffer fast path on Node, a btoa/atob fallback in the
// browser). This file used to carry its own copy whose Node branch referenced `Buffer`
// directly, which raised a ReferenceError in the browser.

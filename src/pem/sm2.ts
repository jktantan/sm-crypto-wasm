/**
 * SM2 密钥 PEM 编解码（PKCS#8 / SEC1 / SPKI）。
 *
 * 与 `./pkcs8` 的通用解析不同，这一层知道 SM2 的具体编码：
 * - 私钥：
 *   - PKCS#8 `PrivateKeyInfo`（`-----BEGIN PRIVATE KEY-----`），其
 *     `privateKey` OCTET STRING 内为 RFC 5915 `ECPrivateKey`：
 *     ```
 *     ECPrivateKey ::= SEQUENCE {
 *       version      INTEGER (1),
 *       privateKey   OCTET STRING,        -- 32 字节 d
 *       parameters   [0] EXPLICIT OBJECT IDENTIFIER OPTIONAL,  -- sm2p256v1
 *       publicKey    [1] EXPLICIT BIT STRING OPTIONAL
 *     }
 *     ```
 *   - SEC1 `ECPrivateKey`（`-----BEGIN EC PRIVATE KEY-----`）直接就是上面的结构。
 * - 公钥：SPKI `SubjectPublicKeyInfo`（`-----BEGIN PUBLIC KEY-----`），
 *   `algorithm = { id-ecPublicKey, sm2p256v1 }`，`subjectPublicKey` 为
 *   65 字节未压缩点 `04 || X || Y`。
 *
 * 算法标识 / 曲线 OID：
 * - id-ecPublicKey = 1.2.840.10045.2.1
 * - sm2p256v1      = 1.2.156.10197.1.301
 *
 * 编码函数接受/产出与解析一致的格式（私钥 PKCS#8、公钥 SPKI），供
 * 密钥生成与测试使用。
 */

import { bytesToPem, hexToBytes, pemToBytes, toBytes } from '../runtime/convert.js';
import { InvalidKeyError } from '../runtime/errors.js';
import {
  type Asn1Node,
  asn1Int,
  asn1Octets,
  asn1Oid,
  asn1Seq,
  decodeOid,
  parseDer,
} from './asn1.js';

/** `id-ecPublicKey` OID。 */
export const OID_ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

/** `sm2p256v1`（推荐曲线）OID。 */
export const OID_SM2_CURVE = '1.2.156.10197.1.301';

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x10; // UNIVERSAL SEQUENCE 的 tag 编号
const CLS_CONTEXT = 2;

// ---------- 解析 ----------

/**
 * 解析 SM2 私钥 PEM，返回 32 字节私钥 d。
 *
 * 支持 PKCS#8（`BEGIN PRIVATE KEY`）与 SEC1（`BEGIN EC PRIVATE KEY`）。
 *
 * @throws InvalidKeyError PEM/DER 结构非法、或曲线不是 SM2。
 */
export function parseSm2PrivateKeyPem(pem: string): Uint8Array {
  return parseSm2PrivateKeyDer(pemToBytes(pem, 'sm2.privateKey'));
}

/**
 * 解析 SM2 私钥 DER（PKCS#8 或 SEC1），返回 32 字节私钥 d。
 *
 * WebCrypto 的 `importKey('pkcs8', ...)` 使用这个入口。
 */
export function parseSm2PrivateKeyDer(der: Uint8Array): Uint8Array {
  const top = parseOrThrow(der, 'parseSm2PrivateKeyPem');
  const kids = top.children;
  if (top.tag !== TAG_SEQUENCE || !kids) {
    throw new InvalidKeyError('parseSm2PrivateKeyPem: top-level is not a SEQUENCE');
  }

  let ec: Asn1Node;
  if (
    kids.length >= 3 &&
    kids[0]?.tag === TAG_INTEGER &&
    kids[1]?.tag === TAG_SEQUENCE &&
    kids[2]?.tag === TAG_OCTET_STRING
  ) {
    // PKCS#8 PrivateKeyInfo
    assertSm2Curve(kids[1], 'parseSm2PrivateKeyPem');
    ec = parseOrThrow(kids[2].value, 'parseSm2PrivateKeyPem (ECPrivateKey)');
  } else if (
    kids.length >= 2 &&
    kids[0]?.tag === TAG_INTEGER &&
    kids[1]?.tag === TAG_OCTET_STRING
  ) {
    // SEC1 ECPrivateKey
    ec = top;
  } else {
    throw new InvalidKeyError('parseSm2PrivateKeyPem: unrecognized private key structure');
  }

  const ecKids = ec.children;
  if (
    ec.tag !== TAG_SEQUENCE ||
    !ecKids ||
    ecKids.length < 2 ||
    ecKids[1]?.tag !== TAG_OCTET_STRING
  ) {
    throw new InvalidKeyError('parseSm2PrivateKeyPem: missing EC private key OCTET STRING');
  }
  // 若带 [0] parameters，则其中的曲线 OID 必须是 SM2。
  for (const child of ecKids) {
    if (child.cls === CLS_CONTEXT && child.tag === 0 && child.children?.[0]) {
      assertSm2Curve(child, 'parseSm2PrivateKeyPem');
    }
  }
  return padScalarTo32(ecKids[1].value, 'parseSm2PrivateKeyPem');
}

/**
 * 解析 SM2 公钥 PEM，返回 65 字节未压缩点 `04 || X || Y`。
 *
 * @throws InvalidKeyError PEM/DER 结构非法、曲线不是 SM2、或点不是未压缩形式。
 */
export function parseSm2PublicKeyPem(pem: string): Uint8Array {
  return parseSm2PublicKeyDer(pemToBytes(pem, 'sm2.publicKey'));
}

/**
 * 解析 SM2 公钥 DER（SPKI），返回 65 字节未压缩点。
 *
 * WebCrypto 的 `importKey('spki', ...)` 使用这个入口。
 */
export function parseSm2PublicKeyDer(der: Uint8Array): Uint8Array {
  const top = parseOrThrow(der, 'parseSm2PublicKeyPem');
  const kids = top.children;
  if (top.tag !== TAG_SEQUENCE || !kids || kids.length < 2) {
    throw new InvalidKeyError('parseSm2PublicKeyPem: invalid SPKI structure');
  }
  assertSm2Curve(kids[0], 'parseSm2PublicKeyPem');
  const bitString = kids[1];
  if (!bitString || bitString.tag !== TAG_BIT_STRING) {
    throw new InvalidKeyError('parseSm2PublicKeyPem: missing BIT STRING');
  }
  // 去掉 BIT STRING 首个「未使用位数」字节。
  const pub = bitString.value.subarray(1);
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new InvalidKeyError(
      `parseSm2PublicKeyPem: expected 65-byte uncompressed point, got ${pub.length} bytes`,
    );
  }
  return new Uint8Array(pub);
}

// ---------- 编码 ----------

/**
 * 编码 SM2 私钥为 PKCS#8 PEM（`BEGIN PRIVATE KEY`）。
 *
 * @param d 32 字节私钥（hex / Uint8Array）。
 * @param pub 可选公钥（64 或 65 字节）；给出则内嵌到 ECPrivateKey 的 `[1]`。
 */
export function encodeSm2PrivateKeyPem(d: string | Uint8Array, pub?: string | Uint8Array): string {
  return bytesToPem(encodeSm2PrivateKeyDer(d, pub), 'PRIVATE KEY');
}

/** 编码 SM2 私钥为 PKCS#8 DER。 */
export function encodeSm2PrivateKeyDer(
  d: string | Uint8Array,
  pub?: string | Uint8Array,
): Uint8Array {
  const scalar = normalizeScalar(d);
  const ecChildren: Asn1Node[] = [
    asn1Int(1),
    asn1Octets(scalar),
    explicit(0, asn1Oid(OID_SM2_CURVE)),
  ];
  if (pub !== undefined) {
    const point = normalizeUncompressed(pub);
    const bits = new Uint8Array(point.length + 1); // 首字节 = 未使用位数 0
    bits.set(point, 1);
    ecChildren.push(explicit(1, bitStringNode(bits)));
  }
  const ec = asn1Seq(ecChildren);
  const pkcs8 = asn1Seq([
    asn1Int(0),
    asn1Seq([asn1Oid(OID_ID_EC_PUBLIC_KEY), asn1Oid(OID_SM2_CURVE)]),
    asn1Octets(ec.raw),
  ]);
  return pkcs8.raw;
}

/**
 * 编码 SM2 公钥为 SPKI PEM（`BEGIN PUBLIC KEY`）。
 *
 * @param pub 64（X || Y）或 65（04 || X || Y）字节公钥。
 */
export function encodeSm2PublicKeyPem(pub: string | Uint8Array): string {
  return bytesToPem(encodeSm2PublicKeyDer(pub), 'PUBLIC KEY');
}

/** 编码 SM2 公钥为 SPKI DER。 */
export function encodeSm2PublicKeyDer(pub: string | Uint8Array): Uint8Array {
  const point = normalizeUncompressed(pub);
  const bits = new Uint8Array(point.length + 1);
  bits.set(point, 1);
  const spki = asn1Seq([
    asn1Seq([asn1Oid(OID_ID_EC_PUBLIC_KEY), asn1Oid(OID_SM2_CURVE)]),
    bitStringNode(bits),
  ]);
  return spki.raw;
}

// ---------- 内部 ----------

function parseOrThrow(der: Uint8Array, where: string): Asn1Node {
  try {
    return parseDer(der);
  } catch (err) {
    throw new InvalidKeyError(`${where}: invalid DER (${(err as Error).message})`);
  }
}

/** 校验 AlgorithmIdentifier / [0]-parameters 的曲线 OID 为 SM2（若无曲线 OID 则放行）。 */
function assertSm2Curve(algIdNode: Asn1Node | undefined, where: string): void {
  const curveOid = curveOidOf(algIdNode);
  if (curveOid !== undefined && curveOid !== OID_SM2_CURVE) {
    throw new InvalidKeyError(`${where}: curve OID ${curveOid} is not SM2 (${OID_SM2_CURVE})`);
  }
}

/** 从 AlgorithmIdentifier（或 [0] EXPLICIT 包装）里取出曲线 OID（无则 undefined）。 */
function curveOidOf(node: Asn1Node | undefined): string | undefined {
  const children = node?.children;
  if (!children) return undefined;
  // AlgorithmIdentifier = SEQUENCE { algorithm OID, parameters OID OPTIONAL }
  // [0] EXPLICIT      = 单个子节点（OID）。
  for (const child of children) {
    if (child.tag === TAG_OID) {
      const oid = safeDecodeOid(child.value);
      // 跳过算法 OID（id-ecPublicKey），参数 OID 才是曲线。
      if (oid !== undefined && oid !== OID_ID_EC_PUBLIC_KEY) return oid;
    }
  }
  return undefined;
}

function safeDecodeOid(bytes: Uint8Array): string | undefined {
  try {
    return decodeOid(bytes);
  } catch {
    return undefined;
  }
}

function padScalarTo32(bytes: Uint8Array, where: string): Uint8Array {
  let b = bytes;
  while (b.length > 32 && b[0] === 0) b = b.subarray(1);
  if (b.length === 0) throw new InvalidKeyError(`${where}: empty private key`);
  if (b.length > 32) throw new InvalidKeyError(`${where}: private key longer than 32 bytes`);
  if (b.length === 32) return new Uint8Array(b);
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

function normalizeScalar(d: string | Uint8Array): Uint8Array {
  const b = typeof d === 'string' ? hexToBytes(d, 'sm2.privateKey') : toBytes(d, 'sm2.privateKey');
  if (b.length !== 32) throw new InvalidKeyError('encodeSm2PrivateKeyPem: d must be 32 bytes');
  return b;
}

function normalizeUncompressed(pub: string | Uint8Array): Uint8Array {
  const b = toBytes(pub, 'sm2.publicKey');
  if (b.length === 64) {
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(b, 1);
    return out;
  }
  if (b.length === 65 && b[0] === 0x04) return b;
  throw new InvalidKeyError('encodeSm2PublicKeyPem: public key must be 64 or 65 bytes');
}

/** 构造 BIT STRING 节点（value 需自带首字节「未使用位数」）。 */
function bitStringNode(value: Uint8Array): Asn1Node {
  const raw = concat([new Uint8Array([TAG_BIT_STRING]), encodeLen(value.length), value]);
  return {
    cls: 0,
    tag: TAG_BIT_STRING,
    constructed: false,
    indefinite: false,
    length: value.length,
    value,
    raw,
  };
}

/** 构造 [n] EXPLICIT 包装节点。 */
function explicit(tagNum: number, inner: Asn1Node): Asn1Node {
  const raw = concat([new Uint8Array([0xa0 | tagNum]), encodeLen(inner.raw.length), inner.raw]);
  return {
    cls: CLS_CONTEXT,
    tag: tagNum,
    constructed: true,
    indefinite: false,
    length: inner.raw.length,
    value: inner.raw,
    children: [inner],
    raw,
  };
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

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

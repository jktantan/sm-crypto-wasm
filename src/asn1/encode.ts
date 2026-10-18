/**
 * ASN.1 DER 编码器与构造器。
 *
 * 规则：
 * - `encode()` 按 `cls + constructed + tag` 重建首字节（修复旧实现丢掉
 *   constructed 位的问题），对 constructed 节点递归编码子节点；
 * - SET OF 按编码字节排序（DER 要求）；
 * - BOOLEAN TRUE 编码为 0xFF；
 * - INTEGER 使用最小补码编码；
 * - 输出始终是 definite-length（BER indefinite 只在解析侧接受）。
 *
 * ASN.1 DER encoder and builders.
 *
 * Rules:
 * - `encode()` rebuilds the leading byte from `cls + constructed + tag` (fixing the
 *   legacy implementation dropping the constructed bit) and recurses into children
 *   of constructed nodes;
 * - SET OF is sorted by encoded bytes (a DER requirement);
 * - BOOLEAN TRUE is encoded as 0xFF;
 * - INTEGER uses minimal two's-complement encoding;
 * - output is always definite-length (BER indefinite is only accepted when parsing).
 */

import { encodeOid } from './oid.js';
import { encodeGeneralizedTime, encodeTime, encodeUtcTime } from './time.js';
import { Asn1Class, Asn1Error, type Asn1Node, UniversalTag } from './types.js';

// ----------------- 基础编码 -----------------
//
// ----------------- Basic encoding -----------------

/**
 * 编码单个节点为 DER 字节。
 *
 * Encodes a single node to DER bytes.
 */
export function encode(node: Asn1Node): Uint8Array {
  const constructed = node.children !== undefined ? true : node.constructed;
  const value = constructed
    ? node.children
      ? concat(node.children.map((child) => encode(child)))
      : node.value
    : node.value;
  const header = concat([encodeTag(node.cls, constructed, node.tag), encodeLength(value.length)]);
  return concat([header, value]);
}

/**
 * `encode` 的旧名（兼容 `src/pem/asn1.ts` 的历史导出）。
 *
 * @deprecated 使用 `encode`。
 *
 * Legacy alias of `encode` (kept for the historical exports of `src/pem/asn1.ts`).
 *
 * @deprecated Use `encode`.
 */
export const encodeDer = encode;

/**
 * 编码 tag 首字节（含高 tag number 的 base128 展开）。
 *
 * Encodes the tag's leading byte (including base128 expansion of high tag numbers).
 */
export function encodeTag(cls: Asn1Class, constructed: boolean, tag: number): Uint8Array {
  if (!Number.isInteger(tag) || tag < 0) {
    throw new Asn1Error(`encodeTag: invalid tag ${tag}`);
  }
  const base = (cls << 6) | (constructed ? 0x20 : 0);
  if (tag < 0x1f) return new Uint8Array([base | tag]);
  const out = [base | 0x1f];
  let v = tag;
  const groups: number[] = [];
  do {
    groups.unshift(v % 128);
    v = Math.floor(v / 128);
  } while (v > 0);
  for (let i = 0; i < groups.length - 1; i++) groups[i] = (groups[i] as number) | 0x80;
  out.push(...groups);
  return new Uint8Array(out);
}

/**
 * 编码 definite-length。
 *
 * Encodes a definite length.
 */
export function encodeLength(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new Asn1Error(`encodeLength: bad length ${length}`);
  }
  if (length < 0x80) return new Uint8Array([length]);
  const bytes: number[] = [];
  let v = length;
  while (v > 0) {
    bytes.unshift(v % 256);
    v = Math.floor(v / 256);
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

// ----------------- 构造器 -----------------
//
// ----------------- Builders -----------------

/**
 * 构造 SEQUENCE。
 *
 * Builds a SEQUENCE.
 */
export function seq(children: readonly Asn1Node[]): Asn1Node {
  return makeConstructed(Asn1Class.Universal, UniversalTag.Sequence, children);
}

/**
 * 构造 SET（保持给定顺序；ASN.1 SET 的排序语义由调用方负责）。
 *
 * Builds a SET, keeping the given order; ordering semantics are the caller's job.
 */
export function set(children: readonly Asn1Node[]): Asn1Node {
  return makeConstructed(Asn1Class.Universal, UniversalTag.Set, children);
}

/**
 * 构造 SET OF（按 DER 编码字节排序）。
 *
 * Builds a SET OF, sorted by encoded DER bytes.
 */
export function setOf(children: readonly Asn1Node[]): Asn1Node {
  const sorted = children
    .map((node) => ({ node, bytes: encode(node) }))
    .sort((a, b) => compareBytes(a.bytes, b.bytes))
    .map((entry) => entry.node);
  return makeConstructed(Asn1Class.Universal, UniversalTag.Set, sorted);
}

/**
 * 构造 `[tag] EXPLICIT` 包装。
 *
 * Builds a `[tag] EXPLICIT` wrapper.
 */
export function explicit(tag: number, inner: Asn1Node): Asn1Node {
  const value = encode(inner);
  return {
    cls: Asn1Class.ContextSpecific,
    tag,
    constructed: true,
    indefinite: false,
    length: value.length,
    value,
    children: [inner],
    raw: concat([
      encodeTag(Asn1Class.ContextSpecific, true, tag),
      encodeLength(value.length),
      value,
    ]),
  };
}

/**
 * 构造 `[tag] IMPLICIT` 包装：只替换外层标签，内容保持不变。
 *
 * Builds a `[tag] IMPLICIT` wrapper: only the outer tag is replaced, the content is
 * kept unchanged.
 */
export function implicit(
  tag: number,
  inner: Asn1Node,
  cls: Asn1Class = Asn1Class.ContextSpecific,
): Asn1Node {
  const constructed = inner.children !== undefined ? true : inner.constructed;
  const value = inner.children ? concat(inner.children.map((child) => encode(child))) : inner.value;
  return {
    cls,
    tag,
    constructed,
    indefinite: false,
    length: value.length,
    value,
    children: inner.children,
    raw: concat([encodeTag(cls, constructed, tag), encodeLength(value.length), value]),
  };
}

/**
 * 构造 BIT STRING。`unusedBits` 为末尾未使用位数（0..7）。
 *
 * Builds a BIT STRING; `unusedBits` is the number of unused trailing bits (0..7).
 */
export function bitString(bytes: Uint8Array, unusedBits = 0): Asn1Node {
  if (!Number.isInteger(unusedBits) || unusedBits < 0 || unusedBits > 7) {
    throw new RangeError(`bitString: unusedBits must be 0..7, got ${unusedBits}`);
  }
  const value = new Uint8Array(bytes.length + 1);
  value[0] = unusedBits;
  value.set(bytes, 1);
  return makePrimitive(UniversalTag.BitString, value);
}

/**
 * 构造 OCTET STRING。
 *
 * Builds an OCTET STRING.
 */
export function octetString(bytes: Uint8Array): Asn1Node {
  return makePrimitive(UniversalTag.OctetString, bytes);
}

/**
 * 构造 BOOLEAN。
 *
 * Builds a BOOLEAN.
 */
export function boolean(value: boolean): Asn1Node {
  return makePrimitive(UniversalTag.Boolean, new Uint8Array([value ? 0xff : 0x00]));
}

/**
 * 构造 NULL。
 *
 * Builds a NULL.
 */
export function nullValue(): Asn1Node {
  return makePrimitive(UniversalTag.Null, new Uint8Array(0));
}

/**
 * 构造 INTEGER（最小补码编码）。
 *
 * Builds an INTEGER (minimal two's-complement encoding).
 */
export function integer(value: bigint | number): Asn1Node {
  const v = typeof value === 'number' ? BigInt(value) : value;
  if (typeof v !== 'bigint') throw new Asn1Error('integer: value must be bigint or number');
  return makePrimitive(UniversalTag.Integer, encodeIntegerValue(v));
}

/**
 * 构造 OBJECT IDENTIFIER。
 *
 * Builds an OBJECT IDENTIFIER.
 */
export function oid(value: string): Asn1Node {
  return makePrimitive(UniversalTag.ObjectIdentifier, encodeOid(value));
}

/**
 * 构造 UTF8String。
 *
 * Builds a UTF8String.
 */
export function utf8String(value: string): Asn1Node {
  return makePrimitive(UniversalTag.Utf8String, new TextEncoder().encode(value));
}

/**
 * 构造 PrintableString（仅允许 A-Z a-z 0-9 与 `'()+,-./:=?` 和空格）。
 *
 * Builds a PrintableString (only A-Z a-z 0-9 and `'()+,-./:=?` plus space allowed).
 */
export function printableString(value: string): Asn1Node {
  if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
    throw new Asn1Error(`printableString: unsupported character in "${value}"`);
  }
  return makePrimitive(UniversalTag.PrintableString, asciiBytes(value));
}

/**
 * 构造 IA5String（仅 ASCII）。
 *
 * Builds an IA5String (ASCII only).
 */
export function ia5String(value: string): Asn1Node {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0x7f) {
      throw new Asn1Error('ia5String: non-ASCII character');
    }
  }
  return makePrimitive(UniversalTag.Ia5String, asciiBytes(value));
}

/**
 * 构造 UTCTime（1950–2049）。
 *
 * Builds a UTCTime (years 1950–2049).
 */
export function utcTime(date: Date): Asn1Node {
  return makePrimitive(UniversalTag.UtcTime, asciiBytes(encodeUtcTime(date)));
}

/**
 * 构造 GeneralizedTime。
 *
 * Builds a GeneralizedTime.
 */
export function generalizedTime(date: Date): Asn1Node {
  return makePrimitive(UniversalTag.GeneralizedTime, asciiBytes(encodeGeneralizedTime(date)));
}

/**
 * 按 RFC 5280 自动选择 UTCTime / GeneralizedTime。
 *
 * Picks UTCTime / GeneralizedTime automatically as RFC 5280 requires.
 */
export function time(date: Date): Asn1Node {
  return makePrimitive(
    isUtcYear(date) ? UniversalTag.UtcTime : UniversalTag.GeneralizedTime,
    asciiBytes(encodeTime(date)),
  );
}

// ----------------- 内部 -----------------
//
// ----------------- Internals -----------------

/**
 * 构造 UNIVERSAL primitive 节点。
 *
 * Builds a UNIVERSAL primitive node.
 */
function makePrimitive(tag: number, value: Uint8Array): Asn1Node {
  return {
    cls: Asn1Class.Universal,
    tag,
    constructed: false,
    indefinite: false,
    length: value.length,
    value,
    raw: concat([encodeTag(Asn1Class.Universal, false, tag), encodeLength(value.length), value]),
  };
}

/**
 * 构造 UNIVERSAL constructed 节点（value 由子节点编码拼接而成）。
 *
 * Builds a UNIVERSAL constructed node whose value is the concatenated encoded
 * children.
 */
function makeConstructed(cls: Asn1Class, tag: number, children: readonly Asn1Node[]): Asn1Node {
  const value = concat(children.map((child) => encode(child)));
  return {
    cls,
    tag,
    constructed: true,
    indefinite: false,
    length: value.length,
    value,
    children,
    raw: concat([encodeTag(cls, true, tag), encodeLength(value.length), value]),
  };
}

/**
 * 判断日期年份是否落在 UTCTime 适用范围（1950–2049）。
 *
 * Whether the year falls in the UTCTime range (1950–2049).
 */
function isUtcYear(date: Date): boolean {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return false;
  const year = date.getUTCFullYear();
  return year >= 1950 && year <= 2049;
}

/**
 * INTEGER 最小补码编码。
 *
 * - 0 → `00`；
 * - 正数：最高位为 1 时前置 `00`；
 * - 负数：选择最少字节数 n 使 `-2^(8n-1) <= v`，按 2^(8n) 取模。
 *
 * Minimal two's-complement INTEGER encoding.
 *
 * - 0 → `00`;
 * - positive: prepend `00` when the top bit would otherwise be set;
 * - negative: pick the fewest bytes n such that `-2^(8n-1) <= v`, then reduce modulo
 *   2^(8n).
 */
export function encodeIntegerValue(v: bigint): Uint8Array {
  if (v === 0n) return new Uint8Array([0]);
  if (v > 0n) {
    let n = 1;
    while (v >= 1n << BigInt(8 * n - 1)) n++;
    const out = new Uint8Array(n);
    let x = v;
    for (let i = n - 1; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }
  let n = 1;
  while (v < -(1n << BigInt(8 * n - 1))) n++;
  let x = (1n << BigInt(8 * n)) + v;
  const out = new Uint8Array(n);
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/**
 * 字符串 → ASCII 字节（高于 0x7f 的码位被截断，调用方负责预先校验）。
 *
 * String to ASCII bytes; code points above 0x7f are truncated, so callers must
 * validate beforehand.
 */
function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0x7f;
  return out;
}

/**
 * 字节字典序比较（DER SET OF 排序依据）。
 *
 * Lexicographic byte comparison, the ordering rule for DER SET OF.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * 拼多个字节数组为一个新数组。
 *
 * Concatenates byte arrays into a new array.
 */
function concat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

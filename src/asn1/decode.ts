/**
 * ASN.1 DER/BER 解析器。
 *
 * 覆盖 X.509 与 CMS 需要的 BER/DER 子集：
 * - definite-length（短/长格式）；
 * - BER indefinite-length（`0x80` + EOC `00 00`），**仅 `parseBer` 允许**；
 * - 高 tag number（`0x1f` + base128）；
 * - constructed / primitive 递归。
 *
 * 严格性：
 * - `parseDer` 拒绝 indefinite、非最小长度编码、EOC、尾部多余字节；
 * - `parseBer` 放宽长度编码并允许 indefinite，但仍拒绝截断与尾部多余字节；
 * - 单对象解析一律拒绝尾部多余字节（红线 #3）。
 *
 * 每个节点保留 `raw`（输入缓冲上的视图），供 CMS 验签与证书 TBS 直接使用。
 *
 * ASN.1 DER/BER parser.
 *
 * Covers the BER/DER subset needed by X.509 and CMS:
 * - definite-length (short and long form);
 * - BER indefinite-length (`0x80` + EOC `00 00`), allowed **only in `parseBer`**;
 * - high tag numbers (`0x1f` + base128);
 * - recursive constructed / primitive handling.
 *
 * Strictness:
 * - `parseDer` rejects indefinite length, non-minimal length encodings, EOC and
 *   trailing bytes;
 * - `parseBer` relaxes length encoding and allows indefinite length, but still
 *   rejects truncation and trailing bytes;
 * - single-object parsing always rejects trailing bytes (red line #3).
 *
 * Every node keeps `raw` (a view onto the input buffer) so that CMS signature
 * verification and certificate TBS hashing can use it directly.
 */

import { decodeOid } from './oid.js';
import { parseTime } from './time.js';
import { Asn1Class, Asn1Error, type Asn1Node, UniversalTag } from './types.js';

/**
 * constructed 嵌套深度上限，防栈溢出与恶意深嵌套。
 *
 * Upper bound on constructed nesting depth, to avoid stack overflow and hostile
 * deeply nested input.
 */
const MAX_DEPTH = 64;

/**
 * 解析选项。
 *
 * Parse options.
 */
export interface ParseOptions {
  /**
   * 允许 BER indefinite-length。仅 CMS 路径应开启。
   *
   * Allow BER indefinite-length; only the CMS path should enable this.
   */
  allowIndefinite?: boolean;
  /**
   * 是否严格校验长度编码的最小形式（DER 默认开启）。
   *
   * Whether to enforce minimal length encoding (on by default for DER).
   */
  strictLength?: boolean;
}

/**
 * 解析单个 DER 对象。
 *
 * @throws Asn1Error 截断、超出深度、非 DER 编码、或根节点后有多余字节。
 *
 * Parses a single DER object.
 *
 * @throws Asn1Error On truncation, excessive depth, non-DER encoding, or trailing
 *   bytes after the root node.
 */
export function parseDer(buf: Uint8Array): Asn1Node {
  return parseSingle(buf, { allowIndefinite: false, strictLength: true }, 'parseDer');
}

/**
 * 解析单个 BER 对象（允许 indefinite-length）。
 *
 * @throws Asn1Error 截断、超出深度、或根节点后有多余字节。
 *
 * Parses a single BER object (indefinite-length allowed).
 *
 * @throws Asn1Error On truncation, excessive depth, or trailing bytes after the
 *   root node.
 */
export function parseBer(buf: Uint8Array): Asn1Node {
  return parseSingle(buf, { allowIndefinite: true, strictLength: false }, 'parseBer');
}

/**
 * 解析连续的多个 DER 对象（证书 bundle / CMS 文件）。
 *
 * 返回按出现顺序排列的节点；允许空输入并返回空数组。
 *
 * Parses a sequence of consecutive DER objects (a certificate bundle or a CMS file).
 *
 * Returns the nodes in order of appearance; empty input is allowed and yields an
 * empty array.
 */
export function parseDerAll(buf: Uint8Array): Asn1Node[] {
  return parseAll(buf, { allowIndefinite: false, strictLength: true }, 'parseDerAll');
}

/**
 * 解析连续的多个 BER 对象（允许 indefinite-length）。
 *
 * Parses a sequence of consecutive BER objects (indefinite-length allowed).
 */
export function parseBerAll(buf: Uint8Array): Asn1Node[] {
  return parseAll(buf, { allowIndefinite: true, strictLength: false }, 'parseBerAll');
}

/**
 * 解析根节点，并要求输入完全被消费。
 *
 * Parses the root node and requires the whole input to be consumed.
 */
function parseSingle(buf: Uint8Array, opts: Required<ParseOptions>, where: string): Asn1Node {
  const reader = new Reader(buf, opts, where);
  const node = reader.readNode(0);
  if (reader.remaining() !== 0) {
    throw new Asn1Error(`${where}: ${reader.remaining()} trailing bytes after root node`);
  }
  return node;
}

/**
 * 解析所有顶层对象，直到输入耗尽。
 *
 * Parses every top-level object until the input is exhausted.
 */
function parseAll(buf: Uint8Array, opts: Required<ParseOptions>, where: string): Asn1Node[] {
  const reader = new Reader(buf, opts, where);
  const nodes: Asn1Node[] = [];
  while (reader.remaining() > 0) {
    nodes.push(reader.readNode(0));
  }
  return nodes;
}

/**
 * 游标式 TLV 读取器（持有单一输入缓冲与位置）。
 *
 * Cursor-style TLV reader over a single input buffer.
 */
class Reader {
  private readonly buf: Uint8Array;
  private readonly opts: Required<ParseOptions>;
  private readonly where: string;
  private pos = 0;

  constructor(buf: Uint8Array, opts: Required<ParseOptions>, where: string) {
    this.buf = buf;
    this.opts = opts;
    this.where = where;
  }

  /**
   * 距输入末尾还剩多少字节。
   *
   * Number of bytes left before the end of the input.
   */
  remaining(): number {
    return this.buf.length - this.pos;
  }

  /**
   * 读取一个字节，越界则报错。
   *
   * Reads one byte, throwing on out-of-bounds.
   */
  private byte(): number {
    if (this.pos >= this.buf.length) {
      throw new Asn1Error(`${this.where}: truncated at offset ${this.pos}`);
    }
    return this.buf[this.pos++] as number;
  }

  /**
   * 读取一个完整 TLV。
   *
   * Reads one complete TLV.
   */
  readNode(depth: number): Asn1Node {
    if (depth > MAX_DEPTH) {
      throw new Asn1Error(`${this.where}: nesting deeper than ${MAX_DEPTH}`);
    }
    const start = this.pos;
    const first = this.byte();
    const cls = ((first >> 6) & 0x03) as Asn1Class;
    const constructed = (first & 0x20) !== 0;
    const tag = (first & 0x1f) === 0x1f ? this.readHighTag() : first & 0x1f;

    // EndOfContent 只能作为 indefinite-length 的结束标记出现。
    //
    // EndOfContent may only appear as the terminator of an indefinite-length value.
    if (cls === Asn1Class.Universal && tag === UniversalTag.EndOfContent && !constructed) {
      const lb = this.byte();
      if (lb !== 0) throw new Asn1Error(`${this.where}: malformed EndOfContent`);
      throw new Asn1Error(`${this.where}: unexpected EndOfContent at offset ${start}`);
    }

    const lb = this.byte();
    let length = 0;
    let indefinite = false;
    if (lb === 0x80) {
      if (!this.opts.allowIndefinite) {
        throw new Asn1Error(`${this.where}: indefinite-length encoding is not allowed`);
      }
      if (!constructed) {
        throw new Asn1Error(`${this.where}: indefinite length on primitive tag ${tag}`);
      }
      indefinite = true;
    } else if (lb < 0x80) {
      length = lb;
    } else {
      length = this.readLongLength(lb & 0x7f);
    }

    const contentStart = this.pos;
    if (indefinite) {
      // indefinite：一直读到 EOC（00 00）。
      //
      // Indefinite: keep reading until the EOC (00 00).
      const children: Asn1Node[] = [];
      for (;;) {
        if (this.remaining() < 2) {
          throw new Asn1Error(`${this.where}: truncated indefinite-length content`);
        }
        if (this.buf[this.pos] === 0 && this.buf[this.pos + 1] === 0) {
          this.pos += 2;
          break;
        }
        children.push(this.readNode(depth + 1));
      }
      const contentEnd = this.pos - 2;
      const value = this.buf.subarray(contentStart, contentEnd);
      return {
        cls,
        tag,
        constructed,
        indefinite,
        length: value.length,
        value,
        children,
        raw: this.buf.subarray(start, this.pos),
      };
    }

    if (this.pos + length > this.buf.length) {
      throw new Asn1Error(
        `${this.where}: truncated value, need ${length} bytes at offset ${this.pos}`,
      );
    }
    this.pos += length;
    const value = this.buf.subarray(contentStart, contentStart + length);

    if (constructed) {
      const inner = new Reader(value, this.opts, this.where);
      const children: Asn1Node[] = [];
      while (inner.remaining() > 0) {
        children.push(inner.readNode(depth + 1));
      }
      return {
        cls,
        tag,
        constructed,
        indefinite,
        length,
        value,
        children,
        raw: this.buf.subarray(start, this.pos),
      };
    }

    return {
      cls,
      tag,
      constructed,
      indefinite,
      length,
      value,
      raw: this.buf.subarray(start, this.pos),
    };
  }

  /**
   * 高 tag number：后续字节 base128。
   *
   * High tag number: subsequent bytes are base128.
   */
  private readHighTag(): number {
    let value = 0;
    let count = 0;
    for (;;) {
      const b = this.byte();
      if (count === 0 && b === 0x80) {
        throw new Asn1Error(`${this.where}: non-minimal high tag number`);
      }
      if (count >= 4) {
        throw new Asn1Error(`${this.where}: tag number too large`);
      }
      value = value * 128 + (b & 0x7f);
      count++;
      if ((b & 0x80) === 0) return value;
    }
  }

  /**
   * 长格式长度（`n` 为 1..4）。
   *
   * Long-form length (`n` is 1..4).
   */
  private readLongLength(n: number): number {
    if (n === 0) throw new Asn1Error(`${this.where}: reserved length encoding 0x80`);
    if (n > 4) throw new Asn1Error(`${this.where}: length of ${n} bytes is not supported`);
    const lengthStart = this.pos;
    let length = 0;
    for (let i = 0; i < n; i++) {
      length = length * 256 + this.byte();
    }
    if (length < 0 || !Number.isSafeInteger(length)) {
      throw new Asn1Error(`${this.where}: length out of range`);
    }
    if (this.opts.strictLength) {
      if (this.buf[lengthStart] === 0) {
        throw new Asn1Error(`${this.where}: non-minimal long-form length (leading zero)`);
      }
      if (length < 0x80) {
        throw new Asn1Error(`${this.where}: non-minimal long-form length ${length}`);
      }
    }
    return length;
  }
}

// ----------------- 常用值读取 -----------------
//
// ----------------- Common value readers -----------------

/**
 * 读取 INTEGER（二进制补码，支持负数）。
 *
 * @throws Asn1Error 节点不是 INTEGER。
 *
 * Reads an INTEGER (two's complement, negative values supported).
 *
 * @throws Asn1Error When the node is not an INTEGER.
 */
export function readInteger(node: Asn1Node, what = 'INTEGER'): bigint {
  if (node.cls !== Asn1Class.Universal || node.tag !== UniversalTag.Integer) {
    throw new Asn1Error(`${what}: expected INTEGER`);
  }
  if (node.value.length === 0) throw new Asn1Error(`${what}: empty INTEGER`);
  let value = 0n;
  for (let i = 0; i < node.value.length; i++) {
    value = (value << 8n) | BigInt(node.value[i] as number);
  }
  if (((node.value[0] as number) & 0x80) !== 0) {
    value -= 1n << BigInt(node.value.length * 8);
  }
  return value;
}

/**
 * 读取 BOOLEAN（DER 中 TRUE 必须为 0xFF）。
 *
 * Reads a BOOLEAN (DER requires TRUE to be 0xFF).
 */
export function readBoolean(node: Asn1Node, what = 'BOOLEAN'): boolean {
  if (node.cls !== Asn1Class.Universal || node.tag !== UniversalTag.Boolean) {
    throw new Asn1Error(`${what}: expected BOOLEAN`);
  }
  if (node.value.length !== 1) throw new Asn1Error(`${what}: BOOLEAN must be 1 byte`);
  return (node.value[0] as number) !== 0;
}

/**
 * BIT STRING 内容。
 *
 * Contents of a BIT STRING.
 */
export interface BitString {
  /**
   * 去掉 unused bits 后的有效字节（尾部未用位保留，由调用方屏蔽）。
   *
   * The payload bytes, with the unused-bits header removed (the trailing unused
   * bits stay in place and must be masked by the caller).
   */
  readonly bytes: Uint8Array;
  /**
   * 末尾未使用位数（0..7）。
   *
   * Number of unused trailing bits (0..7).
   */
  readonly unusedBits: number;
}

/**
 * 读取 BIT STRING。
 *
 * Reads a BIT STRING.
 */
export function readBitString(node: Asn1Node, what = 'BIT STRING'): BitString {
  if (node.cls !== Asn1Class.Universal || node.tag !== UniversalTag.BitString) {
    throw new Asn1Error(`${what}: expected BIT STRING`);
  }
  if (node.value.length === 0) throw new Asn1Error(`${what}: empty BIT STRING`);
  const unusedBits = node.value[0] as number;
  if (unusedBits > 7) throw new Asn1Error(`${what}: invalid unused-bit count ${unusedBits}`);
  return { bytes: node.value.subarray(1), unusedBits };
}

/**
 * 读取 OCTET STRING。
 *
 * Reads an OCTET STRING.
 */
export function readOctetString(node: Asn1Node, what = 'OCTET STRING'): Uint8Array {
  if (node.cls !== Asn1Class.Universal || node.tag !== UniversalTag.OctetString) {
    throw new Asn1Error(`${what}: expected OCTET STRING`);
  }
  return node.value;
}

/**
 * 读取 OBJECT IDENTIFIER。
 *
 * Reads an OBJECT IDENTIFIER.
 */
export function readOid(node: Asn1Node, what = 'OBJECT IDENTIFIER'): string {
  if (node.cls !== Asn1Class.Universal || node.tag !== UniversalTag.ObjectIdentifier) {
    throw new Asn1Error(`${what}: expected OBJECT IDENTIFIER`);
  }
  return decodeOid(node.value);
}

/**
 * 读取 UTCTime / GeneralizedTime。
 *
 * Reads a UTCTime / GeneralizedTime.
 */
export function readTime(node: Asn1Node, what = 'Time'): Date {
  if (node.cls !== Asn1Class.Universal) {
    throw new Asn1Error(`${what}: expected UTCTime or GeneralizedTime`);
  }
  if (node.tag !== UniversalTag.UtcTime && node.tag !== UniversalTag.GeneralizedTime) {
    throw new Asn1Error(`${what}: expected UTCTime or GeneralizedTime`);
  }
  const text = latin1(node.value);
  return parseTime(text);
}

/**
 * 读取 ASN.1 字符串。
 *
 * 支持 UTF8String / PrintableString / IA5String / NumericString /
 * TeletexString / BMPString / UniversalString；其他类型抛 `Asn1Error`。
 *
 * Reads an ASN.1 string.
 *
 * Supports UTF8String / PrintableString / IA5String / NumericString /
 * TeletexString / BMPString / UniversalString; other types throw `Asn1Error`.
 */
export function readString(node: Asn1Node, what = 'string'): string {
  if (node.cls !== Asn1Class.Universal) {
    throw new Asn1Error(`${what}: expected a UNIVERSAL string type`);
  }
  switch (node.tag) {
    case UniversalTag.Utf8String:
      return new TextDecoder('utf-8', { fatal: true }).decode(node.value);
    case UniversalTag.PrintableString:
    case UniversalTag.Ia5String:
    case UniversalTag.NumericString:
    case UniversalTag.TeletexString:
      return latin1(node.value);
    case UniversalTag.BmpString: {
      if (node.value.length % 2 !== 0) throw new Asn1Error(`${what}: odd-length BMPString`);
      let out = '';
      for (let i = 0; i < node.value.length; i += 2) {
        out += String.fromCharCode(
          ((node.value[i] as number) << 8) | (node.value[i + 1] as number),
        );
      }
      return out;
    }
    case UniversalTag.UniversalString: {
      if (node.value.length % 4 !== 0) throw new Asn1Error(`${what}: bad UniversalString`);
      let out = '';
      for (let i = 0; i < node.value.length; i += 4) {
        const cp =
          (node.value[i] as number) * 0x1000000 +
          ((node.value[i + 1] as number) << 16) +
          ((node.value[i + 2] as number) << 8) +
          (node.value[i + 3] as number);
        out += String.fromCodePoint(cp);
      }
      return out;
    }
    default:
      throw new Asn1Error(`${what}: unsupported string tag ${node.tag}`);
  }
}

/**
 * 字节 → 单字节字符（低 8 位），用于 ASCII 类字符串。
 *
 * Bytes to one-code-unit string, used for ASCII-like string types.
 */
function latin1(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i] as number);
  return out;
}

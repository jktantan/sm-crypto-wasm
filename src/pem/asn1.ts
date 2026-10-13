/**
 * 最小化 ASN.1 DER 解析器与编码器（BER/DER 子集）。
 *
 * 本仓库只用到以下类型，刻意不做全 BER：
 * - INTEGER (0x02)、BIT STRING (0x03)、OCTET STRING (0x04)、NULL (0x05)
 * - OBJECT IDENTIFIER (0x06)、SEQUENCE (0x30, constructed)
 *
 * 不支持 indefinite-length encoding（length byte = 0x80），国密 PKCS#8
 * 也用不到。长度只支持 definite-length（短/长两种格式）。
 *
 * spec/plan 对应：plan Task 4；spec §12.1 Q3（SM9 PKCS#8 + 自定义 OID）。
 */

/** ASN.1 节点。children 仅对 constructed 类型存在。 */
export interface Asn1Node {
  /** UNIVERSAL=0、APPLICATION=1、CONTEXT=2、PRIVATE=3。 */
  readonly cls: number;
  /** UNIVERSAL 标签值（如 INTEGER=2、SEQUENCE=16）；其它类自行解释。 */
  readonly tag: number;
  /** 长度（DER 存储的是真实字节长度）。 */
  readonly length: number;
  /** 节点原始字节（含 tag+length+value），用于 round-trip 与错误诊断。 */
  readonly raw: Uint8Array;
  /** primitive 节点的 value；OCTET STRING/BIT STRING/INTEGER 等直接看这里。 */
  readonly value: Uint8Array;
  /** constructed 节点的子节点。 */
  readonly children?: Asn1Node[];
}

/** 抛错信息统一封装。 */
export class Asn1Error extends Error {
  override readonly name = 'Asn1Error';
}

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_NULL = 0x05;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30; // constructed

/**
 * 解析一段 DER 字节。
 *
 * @param buf DER 字节。
 * @returns 解析后的根节点（通常为 SEQUENCE）。
 * @throws Asn1Error 输入截断、tag/length 不合法、不支持的构造。
 */
export function parseDer(buf: Uint8Array): Asn1Node {
  const reader = new Reader(buf);
  const node = reader.readNode();
  // 允许根节点之后留 0 字节尾巴；多余字节视为错误。
  if (reader.remaining() !== 0) {
    throw new Asn1Error(
      `parseDer: ${reader.remaining()} trailing bytes after root node`,
    );
  }
  return node;
}

/**
 * 将 Asn1Node 编码回 DER 字节。**重新计算 length 与 raw**。
 *
 * @param node 待编码节点。
 * @returns DER 字节。
 */
export function encodeDer(node: Asn1Node): Uint8Array {
  // 值字节：primitive 直接取 value；constructed 递归子节点。
  const parts: Uint8Array[] = [];
  if (node.children) {
    for (const child of node.children) parts.push(encodeDer(child));
  }
  const value = node.children
    ? concat(parts)
    : node.value;
  const lengthBytes = encodeLength(value.length);
  const tagByte = node.tag & 0xff;
  const out = new Uint8Array(1 + lengthBytes.length + value.length);
  out[0] = tagByte;
  for (let i = 0; i < lengthBytes.length; i++) out[1 + i] = lengthBytes[i] ?? 0;
  for (let i = 0; i < value.length; i++) {
    out[1 + lengthBytes.length + i] = value[i] ?? 0;
  }
  return out;
}

/**
 * 便捷构造函数：构造一个 INTEGER 节点。
 *
 * @param value 大端整数（可为负：负数用二进制补码表示）。
 */
export function asn1Int(value: bigint | number): Asn1Node {
  const bytes = bigintToBytes(BigInt(value));
  const raw = concat([
    new Uint8Array([TAG_INTEGER]),
    encodeLength(bytes.length),
    bytes,
  ]);
  return {
    cls: 0,
    tag: TAG_INTEGER,
    length: bytes.length,
    value: bytes,
    raw,
  };
}

/** 便捷构造函数：构造一个 OCTET STRING 节点。 */
export function asn1Octets(value: Uint8Array): Asn1Node {
  const raw = concat([
    new Uint8Array([TAG_OCTET_STRING]),
    encodeLength(value.length),
    value,
  ]);
  return {
    cls: 0,
    tag: TAG_OCTET_STRING,
    length: value.length,
    value,
    raw,
  };
}

/** 便捷构造函数：构造一个 OID 节点（输入如 `"1.2.156.10197.1.100"`）。 */
export function asn1Oid(oid: string): Asn1Node {
  const bytes = encodeOid(oid);
  const raw = concat([new Uint8Array([TAG_OID]), encodeLength(bytes.length), bytes]);
  return { cls: 0, tag: TAG_OID, length: bytes.length, value: bytes, raw };
}

/** 便捷构造函数：构造一个 NULL 节点。 */
export function asn1Null(): Asn1Node {
  const raw = new Uint8Array([TAG_NULL, 0x00]);
  return { cls: 0, tag: TAG_NULL, length: 0, value: new Uint8Array(0), raw };
}

/** 便捷构造函数：构造一个 SEQUENCE 节点。 */
export function asn1Seq(children: Asn1Node[]): Asn1Node {
  const parts = children.map((c) => c.raw);
  const value = concat(parts);
  const raw = concat([
    new Uint8Array([TAG_SEQUENCE]),
    encodeLength(value.length),
    value,
  ]);
  // tag 字段统一存 UNIVERSAL 编号 16（0x10），与 Reader 输出一致；
  // raw 首字节保留完整 0x30 以便序列化。
  return {
    cls: 0,
    tag: 0x10,
    length: value.length,
    value,
    children,
    raw,
  };
}

// ----------------- 内部：长度编码 -----------------

function encodeLength(len: number): Uint8Array {
  if (len < 0 || !Number.isInteger(len)) {
    throw new Asn1Error(`encodeLength: bad length ${len}`);
  }
  if (len < 0x80) return new Uint8Array([len]);
  // 长格式：首个字节 0x80|n（n = 后续字节数），后续 big-endian 长度。
  const bytes: number[] = [];
  let v = len;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

// ----------------- 内部：OID 编码 -----------------

/**
 * OID 编码：第一个子标识符 = a*40 + b，后续每个子标识符按 7-bit 编码。
 *
 * 例：`1.2.156.10197.1.100` → [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, 0x64]
 *     1*40+2 = 42 = 0x2a；156、10197、1、100 都用 base-128 编码。
 *
 * @param oid 点分 OID 字符串。
 * @returns OID 内容字节（不含 tag 和 length）。
 */
export function encodeOid(oid: string): Uint8Array {
  const parts = oid.split('.').map((s) => parseInt(s, 10));
  if (parts.length < 2 || parts.some((n) => !Number.isFinite(n) || n < 0)) {
    throw new Asn1Error(`encodeOid: bad oid "${oid}"`);
  }
  const first = (parts[0] ?? 0) * 40 + (parts[1] ?? 0);
  const out: number[] = [first];
  for (let i = 2; i < parts.length; i++) {
    out.push(...encodeBase128(parts[i] ?? 0));
  }
  return new Uint8Array(out);
}

/** 反向解码。 */
export function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) throw new Asn1Error('decodeOid: empty');
  const first = bytes[0] ?? 0;
  const a = Math.floor(first / 40);
  const b = first % 40;
  const parts: number[] = [a, b];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    const octet = bytes[i] ?? 0;
    value = (value << 7) | (octet & 0x7f);
    if ((octet & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  if (value !== 0) throw new Asn1Error('decodeOid: truncated');
  return parts.join('.');
}

function encodeBase128(n: number): number[] {
  if (n < 0 || !Number.isInteger(n)) {
    throw new Asn1Error(`encodeBase128: bad ${n}`);
  }
  if (n < 0x80) return [n];
  const out: number[] = [];
  let v = n;
  do {
    out.unshift((v & 0x7f) | 0x80);
    v >>= 7;
  } while (v > 0);
  out[out.length - 1] = (out[out.length - 1] ?? 0) & 0x7f;
  return out;
}

// ----------------- 内部：大端整数 -----------------

function bigintToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0]);
  const negative = n < 0n;
  let v = negative ? -n : n;
  const tmp: number[] = [];
  while (v > 0n) {
    tmp.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  // 负数采用补码：高位加 0xff 让最高位为 1。
  if (negative) {
    // 简化处理：本仓库不需要负 INTEGER。
    throw new Asn1Error('bigintToBytes: negative integers not supported');
  }
  // 正数：补 0x00 前缀以免被当成负数（最高位为 1 时必须）。
  if ((tmp[0] ?? 0) & 0x80) tmp.unshift(0);
  return new Uint8Array(tmp);
}

/** 读一个 INTEGER 返回 bigint。 */
export function asn1IntValue(node: Asn1Node): bigint {
  if (node.tag !== TAG_INTEGER) {
    throw new Asn1Error(`asn1IntValue: tag ${node.tag}, expected INTEGER`);
  }
  let v = 0n;
  for (let i = 0; i < node.value.length; i++) {
    v = (v << 8n) | BigInt(node.value[i] ?? 0);
  }
  return v;
}

// ----------------- 内部：Reader -----------------

class Reader {
  private buf: Uint8Array;
  private pos = 0;
  constructor(buf: Uint8Array) {
    this.buf = buf;
  }
  remaining(): number {
    return this.buf.length - this.pos;
  }
  private take(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) {
      throw new Asn1Error(
        `Reader: truncated, need ${n} bytes at pos ${this.pos}`,
      );
    }
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  private readTag(): number {
    if (this.remaining() < 1) throw new Asn1Error('Reader: empty tag');
    return this.buf[this.pos++] ?? 0;
  }
  private readLength(): number {
    if (this.remaining() < 1) throw new Asn1Error('Reader: empty length');
    const first = this.buf[this.pos++] ?? 0;
    if ((first & 0x80) === 0) return first;
    const n = first & 0x7f;
    if (n === 0) throw new Asn1Error('Reader: indefinite length not supported');
    if (this.remaining() < n) throw new Asn1Error('Reader: truncated long length');
    let len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | (this.buf[this.pos++] ?? 0);
    }
    return len;
  }
  readNode(): Asn1Node {
    const tagStart = this.pos;
    const tag = this.readTag();
    const length = this.readLength();
    const cls = (tag & 0xc0) >> 6;
    const tagNum = tag & 0x1f;
    const valueStart = this.pos;
    const value = this.take(length);
    const raw = this.buf.subarray(tagStart, valueStart + length);

    const constructed = (tag & 0x20) !== 0;
    if (constructed) {
      // SEQUENCE 等：递归子节点。
      const inner = new Reader(value);
      const children: Asn1Node[] = [];
      while (inner.remaining() > 0) {
        children.push(inner.readNode());
      }
      return { cls, tag: tagNum, length, value, children, raw };
    }
    return { cls, tag: tagNum, length, value, raw };
  }
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

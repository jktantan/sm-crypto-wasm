/**
 * OBJECT IDENTIFIER 编解码。
 *
 * 与旧实现的差异：
 * - 用 `bigint` 累加，不再受 32 位按位运算限制（`1.2.840.113549...` 这类
 *   长组件不会溢出）；
 * - 首个子标识符也走 base128 编码，支持 `2.999` 这类第二组件 ≥ 40 的 OID；
 * - 解码时拒绝截断、空输入与非最小（前导 0x80）编码。
 *
 * OBJECT IDENTIFIER encoding and decoding.
 *
 * Differences from the legacy implementation:
 * - Accumulates in `bigint`, so 32-bit bitwise limits no longer apply (long arcs such
 *   as `1.2.840.113549...` cannot overflow);
 * - The first subidentifier also goes through base128, so OIDs whose second arc is
 *   ≥ 40 (such as `2.999`) are supported;
 * - Decoding rejects truncation, empty input and non-minimal (leading 0x80) encodings.
 */

import { Asn1Error } from './types.js';

/**
 * 点分 OID → 内容字节（不含 tag 与 length）。
 *
 * @param oid 形如 `"1.2.156.10197.1.100"`。
 * @throws Asn1Error 格式非法或组件越界。
 *
 * Dotted OID → content bytes (without tag and length).
 *
 * @param oid Something like `"1.2.156.10197.1.100"`.
 * @throws Asn1Error On malformed syntax or out-of-range components.
 */
export function encodeOid(oid: string): Uint8Array {
  const parts = parseOidComponents(oid);
  const first = (parts[0] as bigint) * 40n + (parts[1] as bigint);
  const out: number[] = encodeBase128(first);
  for (let i = 2; i < parts.length; i++) {
    out.push(...encodeBase128(parts[i] as bigint));
  }
  return new Uint8Array(out);
}

/**
 * 内容字节 → 点分 OID。
 *
 * @throws Asn1Error 空输入、截断或非法 base128 编码。
 *
 * Content bytes → dotted OID.
 *
 * @throws Asn1Error On empty input, truncation, or an invalid base128 encoding.
 */
export function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) throw new Asn1Error('decodeOid: empty');
  const values: bigint[] = [];
  let value = 0n;
  let pending = false;
  for (let i = 0; i < bytes.length; i++) {
    const octet = bytes[i] ?? 0;
    // 每个子标识符的编码不得以 0x80 开头（非最小编码）。
    //
    // A subidentifier's encoding must not start with 0x80 (non-minimal encoding).
    if (!pending && octet === 0x80) {
      throw new Asn1Error('decodeOid: non-minimal base128 encoding');
    }
    value = (value << 7n) | BigInt(octet & 0x7f);
    pending = (octet & 0x80) !== 0;
    if (!pending) {
      values.push(value);
      value = 0n;
    }
  }
  if (pending) throw new Asn1Error('decodeOid: truncated base128 component');
  const first = values[0] as bigint;
  let a: bigint;
  let b: bigint;
  if (first < 40n) {
    a = 0n;
    b = first;
  } else if (first < 80n) {
    a = 1n;
    b = first - 40n;
  } else {
    a = 2n;
    b = first - 80n;
  }
  const parts = [a, b, ...values.slice(1)];
  return parts.map((v) => v.toString(10)).join('.');
}

/**
 * 校验并拆分点分 OID（每个组件为无符号十进制整数）。
 *
 * Validates and splits a dotted OID (each component is an unsigned decimal integer).
 */
function parseOidComponents(oid: string): bigint[] {
  if (typeof oid !== 'string' || oid.length === 0) {
    throw new Asn1Error(`encodeOid: bad oid "${String(oid)}"`);
  }
  const raw = oid.split('.');
  if (raw.length < 2) throw new Asn1Error(`encodeOid: bad oid "${oid}"`);
  const parts: bigint[] = [];
  for (const item of raw) {
    if (!/^(0|[1-9][0-9]*)$/.test(item)) {
      throw new Asn1Error(`encodeOid: bad component "${item}" in "${oid}"`);
    }
    parts.push(BigInt(item));
  }
  const first = parts[0] as bigint;
  const second = parts[1] as bigint;
  if (first > 2n) throw new Asn1Error(`encodeOid: first component must be 0..2, got ${first}`);
  if (first < 2n && second > 39n) {
    throw new Asn1Error(
      `encodeOid: second component must be 0..39 for arc ${first}, got ${second}`,
    );
  }
  return parts;
}

/**
 * 无符号 bigint → base128 字节（高位 bit 为续行标志）。
 *
 * Unsigned bigint → base128 bytes (the high bit marks a continuation).
 */
function encodeBase128(value: bigint): number[] {
  if (value < 0n) throw new Asn1Error(`encodeBase128: negative value ${value}`);
  const groups: number[] = [];
  let v = value;
  do {
    groups.unshift(Number(v & 0x7fn));
    v >>= 7n;
  } while (v > 0n);
  for (let i = 0; i < groups.length - 1; i++) {
    groups[i] = (groups[i] as number) | 0x80;
  }
  return groups;
}

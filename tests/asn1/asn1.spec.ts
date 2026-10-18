/**
 * ASN.1 通用层测试（X.509/CMS plan 阶段 0）。
 *
 * 覆盖：round-trip、BER indefinite-length、高 tag、SET OF 排序、
 * 时间边界（2049/2050）、OID 大组件、畸形输入。
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  Asn1Error,
  type Asn1Node,
  bitString,
  boolean,
  decodeOid,
  encode,
  encodeOid,
  encodeTag,
  explicit,
  generalizedTime,
  ia5String,
  implicit,
  integer,
  nullValue,
  octetString,
  oid,
  parseBer,
  parseDer,
  parseDerAll,
  printableString,
  readBitString,
  readBoolean,
  readInteger,
  readOid,
  readString,
  readTime,
  seq,
  setOf,
  time,
  UniversalTag,
  utcTime,
  utf8String,
} from '@/asn1';
import { bytesToHex, hexToBytes, pemToBytes } from '@/runtime';

const hex = (bytes: Uint8Array): string => bytesToHex(bytes);

function child(node: Asn1Node, index: number): Asn1Node {
  const item = node.children?.[index];
  if (item === undefined) throw new Error(`missing child ${index}`);
  return item;
}

/** 用指定文本构造 UTCTime/GeneralizedTime 节点（用于非规范时间样本）。 */
function rawTimeNode(text: string, tag = UniversalTag.UtcTime): Asn1Node {
  const value = new TextEncoder().encode(text);
  return parseDer(new Uint8Array([tag, value.length, ...value]));
}

describe('ASN.1 round-trip', () => {
  it('round-trips a nested SEQUENCE', () => {
    const node = seq([
      integer(42),
      oid('1.2.156.10197.1.501'),
      seq([utf8String('hello'), boolean(true)]),
      octetString(hexToBytes('deadbeef')),
      bitString(hexToBytes('0102'), 4),
      nullValue(),
    ]);
    const der = encode(node);
    const parsed = parseDer(der);
    expect(hex(encode(parsed))).toBe(hex(der));
    expect(readInteger(child(parsed, 0))).toBe(42n);
    expect(readOid(child(parsed, 1))).toBe('1.2.156.10197.1.501');
    expect(readString(child(child(parsed, 2), 0))).toBe('hello');
    expect(readBoolean(child(child(parsed, 2), 1))).toBe(true);
    const bits = readBitString(child(parsed, 4));
    expect(bits.unusedBits).toBe(4);
    expect(hex(bits.bytes)).toBe('0102');
  });

  it('reconstructs the constructed bit and tag class', () => {
    const node = explicit(3, utf8String('x'));
    const der = encode(node);
    expect(der[0]).toBe(0xa3);
    const parsed = parseDer(der);
    expect(parsed.cls).toBe(2);
    expect(parsed.tag).toBe(3);
    expect(parsed.constructed).toBe(true);
    expect(parsed.indefinite).toBe(false);
    expect(hex(encode(parsed))).toBe(hex(der));
  });

  it('encodes INTEGER with minimal two’s complement', () => {
    const cases: Array<[bigint, string]> = [
      [0n, '00'],
      [1n, '01'],
      [127n, '7f'],
      [128n, '0080'],
      [255n, '00ff'],
      [256n, '0100'],
      [-1n, 'ff'],
      [-128n, '80'],
      [-129n, 'ff7f'],
      [123456789012345678901234567890n, '018ee90ff6c373e0ee4e3f0ad2'],
    ];
    for (const [value, expected] of cases) {
      expect(hex(integer(value).value)).toBe(expected);
      expect(readInteger(parseDer(encode(integer(value))))).toBe(value);
    }
  });

  it('sorts SET OF by encoded bytes', () => {
    const node = setOf([utf8String('b'), utf8String('a'), utf8String('c')]);
    const parsed = parseDer(encode(node));
    expect(parsed.children?.map((c) => readString(c))).toEqual(['a', 'b', 'c']);
    // 已排序输入保持幂等。
    expect(hex(encode(parsed))).toBe(hex(encode(node)));
  });

  it('encodes BOOLEAN TRUE as 0xff', () => {
    expect(hex(boolean(true).value)).toBe('ff');
    expect(hex(boolean(false).value)).toBe('00');
  });
});

describe('ASN.1 BER indefinite-length', () => {
  it('parses indefinite-length SEQUENCE and keeps the raw bytes', () => {
    const der = hexToBytes('30800201010000');
    const node = parseBer(der);
    expect(node.indefinite).toBe(true);
    expect(node.children?.length).toBe(1);
    expect(readInteger(child(node, 0))).toBe(1n);
    expect(hex(node.raw)).toBe('30800201010000');
    // 编码为 DER 后不再有 indefinite 与 EOC。
    expect(hex(encode(node))).toBe('3003020101');
  });

  it('parses nested indefinite-length containers', () => {
    const node = parseBer(hexToBytes('3080308002010100000000'));
    expect(node.indefinite).toBe(true);
    expect(node.children?.[0]?.indefinite).toBe(true);
    expect(hex(encode(node))).toBe('30053003020101');
  });

  it('rejects indefinite-length in DER mode', () => {
    expect(() => parseDer(hexToBytes('30800201010000'))).toThrow(Asn1Error);
  });

  it('rejects indefinite length on primitive types', () => {
    expect(() => parseBer(hexToBytes('0480deadbeef0000'))).toThrow(Asn1Error);
  });

  it('rejects truncated indefinite content', () => {
    expect(() => parseBer(hexToBytes('3080020101'))).toThrow(Asn1Error);
  });
});

describe('ASN.1 tags', () => {
  it('round-trips high tag numbers', () => {
    expect(hex(encodeTag(0, false, 30))).toBe('1e');
    expect(hex(encodeTag(0, false, 31))).toBe('1f1f');
    expect(hex(encodeTag(2, true, 201))).toBe('bf8149');
    const node = implicit(201, octetString(hexToBytes('aa')), 1);
    const parsed = parseDer(encode(node));
    expect(parsed.cls).toBe(1);
    expect(parsed.tag).toBe(201);
    expect(hex(parsed.value)).toBe('aa');
  });

  it('rejects a non-minimal high tag encoding', () => {
    expect(() => parseDer(hexToBytes('1f8000'))).toThrow(Asn1Error);
  });

  it('rejects unexpected EndOfContent', () => {
    expect(() => parseDer(hexToBytes('0000'))).toThrow(Asn1Error);
  });
});

describe('ASN.1 malformed input', () => {
  it('rejects truncated values', () => {
    expect(() => parseDer(hexToBytes('3005020101'))).toThrow(Asn1Error);
  });

  it('rejects trailing bytes for a single object', () => {
    expect(() => parseDer(hexToBytes('050000'))).toThrow(/trailing/);
  });

  it('rejects non-minimal long-form lengths in DER mode', () => {
    expect(() => parseDer(hexToBytes('3081050000'))).toThrow(Asn1Error);
    expect(() => parseDer(hexToBytes('3082008005000000'))).toThrow(Asn1Error);
    // BER 模式放宽长度编码，但仍要内容完整。
    expect(() => parseBer(hexToBytes('3082000205000000'))).toThrow(Asn1Error);
  });

  it('parses multiple DER objects with parseDerAll', () => {
    const der = new Uint8Array([...encode(integer(1)), ...encode(integer(2))]);
    const nodes = parseDerAll(der);
    expect(nodes.map((n) => readInteger(n))).toEqual([1n, 2n]);
    expect(parseDerAll(new Uint8Array(0))).toEqual([]);
    expect(() => parseDer(der)).toThrow(/trailing/);
  });
});

describe('ASN.1 OID', () => {
  it('round-trips common and large OIDs', () => {
    const oids = [
      '1.2.840.113549.1.1.11',
      '1.2.156.10197.1.501',
      '2.5.29.17',
      '2.999.3',
      '1.2.18446744073709551615.1',
      '0.0',
      '2.40.3',
    ];
    for (const value of oids) {
      expect(decodeOid(encodeOid(value))).toBe(value);
    }
  });

  it('encodes the first subidentifier with base128', () => {
    // 2.999.3 → 2*40+999 = 1079 = 0x88 0x37。
    expect(hex(encodeOid('2.999.3'))).toBe('883703');
  });

  it('rejects malformed OIDs', () => {
    expect(() => encodeOid('1')).toThrow(Asn1Error);
    expect(() => encodeOid('3.1')).toThrow(Asn1Error);
    expect(() => encodeOid('1.40')).toThrow(Asn1Error);
    expect(() => encodeOid('1.2.-1')).toThrow(Asn1Error);
    expect(() => decodeOid(new Uint8Array(0))).toThrow(Asn1Error);
    expect(() => decodeOid(hexToBytes('2a86'))).toThrow(Asn1Error);
  });
});

describe('ASN.1 time', () => {
  it('uses UTCTime for 1950–2049 and GeneralizedTime otherwise', () => {
    expect(utcTime(new Date('2024-01-02T03:04:05Z')).value).toEqual(
      new TextEncoder().encode('240102030405Z'),
    );
    expect(time(new Date('2049-12-31T23:59:59Z')).tag).toBe(UniversalTag.UtcTime);
    expect(time(new Date('2050-01-01T00:00:00Z')).tag).toBe(UniversalTag.GeneralizedTime);
    expect(generalizedTime(new Date('2050-01-01T00:00:00Z')).value).toEqual(
      new TextEncoder().encode('20500101000000Z'),
    );
    expect(() => utcTime(new Date('2050-01-01T00:00:00Z'))).toThrow(RangeError);
  });

  it('parses UTCTime boundaries and offsets', () => {
    expect(readTime(utcTime(new Date('1950-01-01T00:00:00Z'))).toISOString()).toBe(
      '1950-01-01T00:00:00.000Z',
    );
    expect(readTime(utcTime(new Date('2049-12-31T23:59:59Z'))).toISOString()).toBe(
      '2049-12-31T23:59:59.000Z',
    );
    // 无秒。
    expect(readTime(rawTimeNode('2401020304Z')).toISOString()).toBe('2024-01-02T03:04:00.000Z');
    // 带 +08:00 偏移。
    expect(readTime(rawTimeNode('240102120000+0800')).toISOString()).toBe(
      '2024-01-02T04:00:00.000Z',
    );
  });

  it('normalizes milliseconds to seconds', () => {
    const date = new Date('2024-01-02T03:04:05.987Z');
    const parsed = readTime(utcTime(date));
    expect(parsed.getUTCMilliseconds()).toBe(0);
    expect(parsed.toISOString()).toBe('2024-01-02T03:04:05.000Z');
  });

  it('rejects invalid dates', () => {
    expect(() => readTime(rawTimeNode('241302030405Z'))).toThrow(Asn1Error);
    expect(() => utcTime(new Date(Number.NaN))).toThrow(RangeError);
  });
});

describe('ASN.1 string types', () => {
  it('encodes UTF8 / Printable / IA5', () => {
    expect(readString(utf8String('国密 SM2'))).toBe('国密 SM2');
    expect(readString(printableString('Test CA'))).toBe('Test CA');
    expect(readString(ia5String('a@example.com'))).toBe('a@example.com');
    expect(() => printableString('国密')).toThrow(Asn1Error);
    expect(() => ia5String('国密')).toThrow(Asn1Error);
  });
});

function hasOpenSsl(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const describeOssl = hasOpenSsl() ? describe : describe.skip;

describeOssl('ASN.1 round-trip against OpenSSL output', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sm-crypto-asn1-'));

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('parse → encode reproduces an OpenSSL SM2 certificate byte-for-byte', () => {
    const key = join(dir, 'ca.key');
    const cert = join(dir, 'ca.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'sm2',
        '-nodes',
        '-keyout',
        key,
        '-out',
        cert,
        '-days',
        '1',
        '-subj',
        '/C=CN/O=SM Crypto/CN=ASN1 Roundtrip CA',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
        '-addext',
        'subjectAltName=DNS:example.test,IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    );
    const der = pemToBytes(readFileSync(cert, 'utf8'));
    const parsed = parseDer(der);
    expect(hex(encode(parsed))).toBe(hex(der));
    expect(parsed.cls).toBe(0);
    expect(parsed.tag).toBe(UniversalTag.Sequence);
  }, 30_000);
});

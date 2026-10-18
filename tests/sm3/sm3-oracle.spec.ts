import { createHash, createHmac } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { ensureLoaded, hash, hmac } from '@/sm3';

/**
 * SM3 与 Node crypto oracle 对比。
 *
 * 注意：本库的 `toBytes` 对 string 走「嗅探」：
 * - `'-----BEGIN'` → PEM
 * - 全 hex 且偶数长度 → hex
 * - 其它 → base64
 *
 * `abc` 长度为 3（奇数）、非 hex → 被当 base64。所以要测「字节序列 abc」
 * 必须传 `Uint8Array`（或 hex `'616263'`）。这里统一传字节。
 */
const oracle = (input: Uint8Array): string =>
  createHash('sm3').update(Buffer.from(input)).digest('hex');

describe('SM3 vs Node crypto oracle', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  const cases: Array<[string, Uint8Array]> = [
    ['one byte 0x00', new Uint8Array([0x00])],
    ['one byte 0x01', new Uint8Array([0x01])],
    ['three bytes "abc"', new Uint8Array([0x61, 0x62, 0x63])],
    ['one byte "a"', new Uint8Array([0x61])],
    ['"hello world"', new Uint8Array(Buffer.from('hello world'))],
    ['64 bytes of 0x00', new Uint8Array(64)],
    ['65 bytes of 0xff', new Uint8Array(65).fill(0xff)],
  ];
  for (const [name, input] of cases) {
    it(`matches oracle for ${name}`, () => {
      expect(hash(input)).toBe(oracle(input));
    });
  }
});

/**
 * SM3 的输入是任意比特串（GM/T 0004-2012），空串（l = 0）落在定义域内：
 * 填充后恰好是一个完整 512 比特块，结果唯一。
 */
describe('SM3 empty message', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  it('hashes the empty message identically for "" and Uint8Array(0)', () => {
    const expected = '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b';
    expect(hash('')).toBe(expected);
    expect(hash(new Uint8Array(0))).toBe(expected);
    expect(oracle(new Uint8Array(0))).toBe(expected);
  });

  it('hmac accepts an empty key and an empty message (cross-checked with Node)', () => {
    const nodeHmac = (k: Buffer, m: Buffer) => createHmac('sm3', k).update(m).digest('hex');
    expect(hmac('', '')).toBe(nodeHmac(Buffer.alloc(0), Buffer.alloc(0)));
    // 用字节输入，避开字符串嗅探：'abc' 是奇数长度、非 hex，会被当成 base64。
    expect(hmac(new Uint8Array(0), new Uint8Array([0x61, 0x62, 0x63]))).toBe(
      nodeHmac(Buffer.alloc(0), Buffer.from('abc')),
    );
  });
});

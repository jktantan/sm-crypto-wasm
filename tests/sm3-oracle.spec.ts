import { describe, expect, it, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { hash, ensureLoaded } from '@/sm3';

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
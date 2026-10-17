import { describe, expect, it } from 'vitest';
import { decodeBase64, encodeBase64 } from '@/runtime/base64.core';

/**
 * 纯 JS base64 兜底（宿主既没有 Buffer、也没有 btoa/atob 时使用）。
 *
 * 关键契约：
 * - 编码输出必须与 Node `Buffer.toString('base64')` 完全一致（含 padding）；
 * - 解码允许空白与缺失 padding，非法字符/长度抛 TypeError；
 * - 任意字节长度都要能往返。
 */
describe('base64 core 编码', () => {
  it('标准向量', () => {
    const vectors: Array<[string, string]> = [
      ['', ''],
      ['f', 'Zg=='],
      ['fo', 'Zm8='],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg=='],
      ['fooba', 'Zm9vYmE='],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [plain, b64] of vectors) {
      const bytes = new TextEncoder().encode(plain);
      expect(encodeBase64(bytes)).toBe(b64);
      expect(decodeBase64(b64)).toEqual(bytes);
    }
  });

  it('与 Node Buffer 编码逐字节一致', () => {
    for (const len of [0, 1, 2, 3, 4, 5, 16, 31, 32, 33, 255, 256, 1024]) {
      const b = new Uint8Array(len).map((_, i) => (i * 37 + 11) & 0xff);
      expect(encodeBase64(b)).toBe(Buffer.from(b).toString('base64'));
    }
  });
});

describe('base64 core 解码', () => {
  it('任意长度往返', () => {
    for (let len = 0; len <= 64; len++) {
      const b = new Uint8Array(len).map((_, i) => (i * 19 + 7) & 0xff);
      expect(decodeBase64(encodeBase64(b))).toEqual(b);
    }
  });

  it('允许空白字符与缺失 padding', () => {
    expect(decodeBase64('Zm9v\nYmFy')).toEqual(new TextEncoder().encode('foobar'));
    expect(decodeBase64('Zg')).toEqual(new TextEncoder().encode('f'));
    expect(decodeBase64('Zm8')).toEqual(new TextEncoder().encode('fo'));
    expect(decodeBase64('Zm9vYg')).toEqual(new TextEncoder().encode('foob'));
  });

  it('非法字符抛 TypeError', () => {
    expect(() => decodeBase64('@@@@')).toThrow(TypeError);
    expect(() => decodeBase64('Zm9v!')).toThrow(TypeError);
  });

  it('非法 padding / 长度抛 TypeError', () => {
    expect(() => decodeBase64('====')).toThrow(TypeError);
    expect(() => decodeBase64('A===')).toThrow(TypeError);
    expect(() => decodeBase64('AA=')).toThrow(TypeError);
    expect(() => decodeBase64('A')).toThrow(TypeError);
  });
});

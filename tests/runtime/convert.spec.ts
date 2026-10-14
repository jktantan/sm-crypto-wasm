import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToPem,
  fromBytes,
  hexToBytes,
  pemToBytes,
  toBytes,
} from '@/runtime/convert';

/**
 * hex / base64 / PEM / Uint8Array 之间互转的嗅探契约。
 *
 * toBytes 必须按 "PEM > hex > base64" 顺序嗅探，且空输入抛 TypeError；
 * fromBytes 必须分别支持 hex / base64 / raw。
 */
describe('toBytes 嗅探顺序', () => {
  it('空字符串抛 TypeError', () => {
    expect(() => toBytes('', 'x')).toThrow(TypeError);
  });

  it('非字符串非 Uint8Array 抛 TypeError', () => {
    expect(() => toBytes(42 as never, 'x')).toThrow(TypeError);
  });

  it('PEM 优先于 hex', () => {
    // body 是 "4162"（"Ab"）的 base64。
    const pem = '-----BEGIN TEST-----\nQWI=\n-----END TEST-----';
    expect(toBytes(pem, 'x')).toEqual(new Uint8Array([0x41, 0x62]));
  });

  it('hex 优先于 base64（无 0x 前缀的偶数 hex）', () => {
    expect(toBytes('4142', 'x')).toEqual(new Uint8Array([0x41, 0x42]));
  });

  it('0x 前缀的 hex', () => {
    expect(toBytes('0x4142', 'x')).toEqual(new Uint8Array([0x41, 0x42]));
  });

  it('hexToBytes 自身：奇数长度抛 TypeError', () => {
    // 直接测 hexToBytes，绕开 toBytes 嗅探；toBytes 嗅探顺序对
    // 短输入的判定受 atob 宽容度影响。
    expect(() => hexToBytes('abc', 'x')).toThrow(TypeError);
  });

  it('base64 真正非合法字符抛错（任意类型即可）', () => {
    // 现代 V8 / Node 的 atob 对非 base64 字符抛 InvalidCharacterError。
    // 契约层只要求"非空输入不能静默通过"，类型不锁死。
    expect(() => toBytes('@@@@', 'x')).toThrow();
  });
});

describe('hex 互转', () => {
  it('非空长度下 bytesToHex / hexToBytes 互逆', () => {
    for (const len of [1, 16, 31, 32, 33, 256]) {
      const b = new Uint8Array(len).map((_, i) => (i * 7) & 0xff);
      expect(hexToBytes(bytesToHex(b), 'x')).toEqual(b);
    }
  });

  it('空字节数组 → 空 hex（不是抛错）', () => {
    expect(bytesToHex(new Uint8Array(0))).toBe('');
  });

  it('hexToBytes 大写不敏感', () => {
    expect(hexToBytes('DEADBEEF', 'x')).toEqual(hexToBytes('deadbeef', 'x'));
  });

  it('空 hex 抛 TypeError（hexToBytes 本身不接受空）', () => {
    expect(() => hexToBytes('', 'x')).toThrow(TypeError);
  });
});

describe('base64 互转', () => {
  it('bytesToBase64 / base64ToBytes 互逆（含 0 字节、1 字节、2 字节尾部）', () => {
    for (const len of [0, 1, 2, 3, 16, 31, 32, 33]) {
      const b = new Uint8Array(len).map((_, i) => (i * 17) & 0xff);
      const enc = bytesToBase64(b);
      expect(base64ToBytes(enc, 'x')).toEqual(b);
    }
  });
});

describe('PEM 互转', () => {
  it('bytesToPem / pemToBytes 互逆', () => {
    const b = new Uint8Array([0xab, 0xcd, 0xef]);
    const pem = bytesToPem(b, 'TEST');
    expect(pemToBytes(pem, 'x')).toEqual(b);
    expect(pem).toMatch(/^-----BEGIN TEST-----/);
    expect(pem).toMatch(/-----END TEST-----\n$/);
  });

  it('PEM body 为空抛 TypeError', () => {
    expect(() => pemToBytes('-----BEGIN X-----\n-----END X-----\n', 'x')).toThrow(TypeError);
  });
});

describe('fromBytes 三种格式', () => {
  it('hex / base64 / raw 三态都工作', () => {
    const b = new Uint8Array([0xde, 0xad]);
    expect(fromBytes(b, 'hex')).toBe('dead');
    expect(fromBytes(b, 'base64')).toBe('3q0=');
    // raw 走 TextDecoder，对非 UTF-8 字节用 'replace' 策略会插入 U+FFFD；只测合法 ASCII。
    expect(fromBytes(new Uint8Array([0x68, 0x69]), 'raw')).toBe('hi');
  });

  it('raw 输入空数组返回 ""', () => {
    expect(fromBytes(new Uint8Array(0), 'raw')).toBe('');
  });

  it('未知 format 抛 TypeError（穷尽性）', () => {
    expect(() => fromBytes(new Uint8Array(1), 'nope' as never)).toThrow(TypeError);
  });
});

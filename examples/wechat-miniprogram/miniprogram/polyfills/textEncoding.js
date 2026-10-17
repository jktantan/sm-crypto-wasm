/**
 * 小程序 TextEncoder / TextDecoder 兜底实现（仅 UTF-8）。
 *
 * 新基础库通常已经提供；老版本缺失时，SM9 和 SM2 密钥交换会报
 * `TextEncoder is not defined`。只在缺失时安装，不覆盖宿主实现。
 */

const g = typeof globalThis !== 'undefined' ? globalThis : global;

function encodeUtf8(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i++;
      }
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return new Uint8Array(out);
}

function decodeUtf8(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input || []);
  let out = '';
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i++];
    if (b < 0x80) {
      out += String.fromCharCode(b);
    } else if (b < 0xe0) {
      out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i++] & 0x3f));
    } else if (b < 0xf0) {
      out += String.fromCharCode(
        ((b & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f),
      );
    } else {
      const cp =
        ((b & 0x07) << 18) |
        ((bytes[i++] & 0x3f) << 12) |
        ((bytes[i++] & 0x3f) << 6) |
        (bytes[i++] & 0x3f);
      const v = cp - 0x10000;
      out += String.fromCharCode(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
    }
  }
  return out;
}

if (typeof g.TextEncoder === 'undefined') {
  g.TextEncoder = class TextEncoder {
    get encoding() {
      return 'utf-8';
    }
    encode(input = '') {
      return encodeUtf8(String(input));
    }
  };
}

if (typeof g.TextDecoder === 'undefined') {
  g.TextDecoder = class TextDecoder {
    get encoding() {
      return 'utf-8';
    }
    decode(input) {
      return decodeUtf8(input);
    }
  };
}

export {};

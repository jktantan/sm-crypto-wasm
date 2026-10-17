/**
 * 小程序 btoa / atob 兜底实现。
 *
 * 小程序没有 `btoa` / `atob`，而库的 base64 / PEM 编解码（SM2、SM9 的密钥
 * 生成与 PEM 解析）会用到它们。缺失时表现为：
 *   ReferenceError: btoa is not defined
 *
 * 只实现标准 base64（不做 URL-safe），与浏览器行为一致：输入只接受 Latin-1
 * 字节串，非法字符抛错。只在宿主缺失时安装。
 */

const g = typeof globalThis !== 'undefined' ? globalThis : global;

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function btoa(input) {
  const str = String(input);
  let out = '';
  for (let i = 0; i < str.length; i += 3) {
    const a = str.charCodeAt(i);
    const hasB = i + 1 < str.length;
    const hasC = i + 2 < str.length;
    const b = hasB ? str.charCodeAt(i + 1) : 0;
    const c = hasC ? str.charCodeAt(i + 2) : 0;
    if (a > 0xff || b > 0xff || c > 0xff) {
      throw new Error('InvalidCharacterError: btoa input must be Latin-1');
    }
    const n = (a << 16) | (b << 8) | c;
    out +=
      B64[(n >> 18) & 63] +
      B64[(n >> 12) & 63] +
      (hasB ? B64[(n >> 6) & 63] : '=') +
      (hasC ? B64[n & 63] : '=');
  }
  return out;
}

function atob(input) {
  const str = String(input).replace(/[\t\n\f\r ]/g, '');
  const body = str.replace(/=+$/, '');
  let out = '';
  let buffer = 0;
  let bits = 0;

  for (let i = 0; i < body.length; i++) {
    const v = B64.indexOf(body[i]);
    if (v < 0) throw new Error('InvalidCharacterError: atob invalid base64');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }

  // 合法 base64 的剩余位数只可能是 0 / 2 / 4；为 6 说明长度非法。
  if (bits >= 6) throw new Error('InvalidCharacterError: atob invalid length');
  return out;
}

if (typeof g.btoa === 'undefined') g.btoa = btoa;
if (typeof g.atob === 'undefined') g.atob = atob;

export {};

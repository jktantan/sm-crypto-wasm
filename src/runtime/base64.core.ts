/**
 * base64 纯 JS 实现（宿主既没有 `Buffer`、也没有 `btoa` / `atob` 时的兜底）。
 *
 * 存在理由：微信小程序等运行时没有 `btoa` / `atob`，而 SM2 / SM9 的 PEM 密钥
 * 生成与解析需要 base64。base64 是确定性编码、不属于密码学原语，因此在库内兜底
 * 不需要像 RNG 那样 fail-closed。
 *
 * 只在 `runtime/convert.ts` 的最后一级回退里使用；Node 有 `Buffer`、浏览器有
 * `btoa` / `atob` 时都不会走到这里。零 `node:*` 引用，可安全进入浏览器/小程序产物。
 */

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** 标准 base64 编码（带 `=` padding）。 */
export function encodeBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const hasB = i + 1 < bytes.length;
    const hasC = i + 2 < bytes.length;
    const b = hasB ? (bytes[i + 1] ?? 0) : 0;
    const c = hasC ? (bytes[i + 2] ?? 0) : 0;
    const n = (a << 16) | (b << 8) | c;
    out += B64.charAt((n >> 18) & 63);
    out += B64.charAt((n >> 12) & 63);
    out += hasB ? B64.charAt((n >> 6) & 63) : '=';
    out += hasC ? B64.charAt(n & 63) : '=';
  }
  return out;
}

/**
 * 标准 base64 解码。
 *
 * 与 `atob` 的宽松度对齐：允许空白字符与缺失 padding；非法字符、非法长度抛
 * `TypeError`（`convert.base64ToBytes` 的契约是失败抛 TypeError）。
 *
 * @param b64 base64 字符串。
 * @param label 错误信息里的字段名。
 */
export function decodeBase64(b64: string, label = 'base64'): Uint8Array {
  const stripped = b64.replace(/[\t\n\f\r ]/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(stripped)) {
    throw new TypeError(`${label}: invalid base64`);
  }

  const pad = stripped.endsWith('==') ? 2 : stripped.endsWith('=') ? 1 : 0;
  if (pad > 0 && stripped.length % 4 !== 0) {
    throw new TypeError(`${label}: invalid base64 padding`);
  }
  const body = pad > 0 ? stripped.slice(0, -pad) : stripped;
  if (body.length % 4 === 1) {
    throw new TypeError(`${label}: invalid base64 length`);
  }

  const out = new Uint8Array(Math.floor((body.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let pos = 0;

  for (let i = 0; i < body.length; i++) {
    const v = B64.indexOf(body.charAt(i));
    if (v < 0) throw new TypeError(`${label}: invalid base64 character at index ${i}`);
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[pos++] = (buffer >> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }

  return out.subarray(0, pos);
}

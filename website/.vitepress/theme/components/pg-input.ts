/**
 * Playground 的输入归一化工具。
 *
 * 库的 `toBytes` 对字符串做编码嗅探（PEM > hex > base64），所以 Playground 让
 * 用户显式选择编码，避免"输入 `abc` 却被当 base64"这类困惑 —— 这本身也是
 * 使用库里最常踩的坑，值得在演示里摆出来。
 */

export type TextEncoding = 'utf8' | 'hex' | 'base64';

/** 把用户输入按选定编码转成库能接受的 `Input`。 */
export function toInput(text: string, encoding: TextEncoding): string | Uint8Array {
  if (encoding === 'utf8') return new TextEncoder().encode(text);
  return text.replace(/\s+/g, '');
}

/** 把库吐出的 hex 明文还原成可读文本（非 UTF-8 时退回 hex，不抛错）。 */
export function hexToText(hex: string): string {
  if (hex.length === 0) return '(空)';
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    // 控制字符原样显示会很乱，这种情况下继续用 hex 表示。
    return /[\u0000-\u0008\u000b-\u001f]/.test(text) ? hex : text;
  } catch {
    return hex;
  }
}

/** 随机 hex（用于"生成随机密钥/IV"按钮）。 */
export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let out = '';
  for (const b of buf) out += b.toString(16).padStart(2, '0');
  return out;
}

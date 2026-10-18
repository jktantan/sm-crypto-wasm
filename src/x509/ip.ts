/**
 * IP 地址解析（用于 SubjectAltName 的 iPAddress）。
 *
 * 输出 4 字节（IPv4）或 16 字节（IPv6）。IPv6 支持 `::` 压缩与
 * 末尾内嵌 IPv4（如 `::ffff:192.168.0.1`）。
 *
 * IP address parsing for the SubjectAltName iPAddress entry.
 *
 * Produces 4 bytes (IPv4) or 16 bytes (IPv6). IPv6 supports `::` compression
 * and a trailing embedded IPv4 address (e.g. `::ffff:192.168.0.1`).
 */

import { CertificateError } from './errors.js';

/**
 * 把 IPv4 / IPv6 文本解析为地址字节。
 *
 * @throws CertificateError 格式非法。
 *
 * Parses IPv4 / IPv6 text into address bytes.
 *
 * @throws CertificateError The text is not a valid address.
 */
export function parseIpAddress(value: string): Uint8Array {
  const text = value.trim();
  if (text.length === 0) throw new CertificateError('subjectAltName: empty IP address');
  if (text.includes(':')) return parseIpv6(text);
  return parseIpv4(text);
}

// 解析 IPv4 文本为 4 字节。
//
// Parses IPv4 text into 4 bytes.
function parseIpv4(text: string): Uint8Array {
  const parts = text.split('.');
  if (parts.length !== 4) throw new CertificateError(`invalid IPv4 address "${text}"`);
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i] as string;
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) {
      throw new CertificateError(`invalid IPv4 address "${text}"`);
    }
    const n = Number(part);
    if (n > 255) throw new CertificateError(`invalid IPv4 address "${text}"`);
    out[i] = n;
  }
  return out;
}

// 解析 IPv6 文本为 16 字节。
//
// Parses IPv6 text into 16 bytes.
function parseIpv6(text: string): Uint8Array {
  const doubleColon = text.indexOf('::');
  let headParts: string[];
  let tailParts: string[];
  let compressed = false;
  if (doubleColon >= 0) {
    if (text.indexOf('::', doubleColon + 2) >= 0) {
      throw new CertificateError(`invalid IPv6 address "${text}"`);
    }
    compressed = true;
    headParts = splitPart(text.slice(0, doubleColon));
    tailParts = splitPart(text.slice(doubleColon + 2));
  } else {
    headParts = splitPart(text);
    tailParts = [];
  }

  const head = groupsOf(headParts, false, text);
  const tail = groupsOf(tailParts, true, text);
  let groups: number[];
  if (!compressed) {
    if (head.length !== 8) throw new CertificateError(`invalid IPv6 address "${text}"`);
    groups = head;
  } else {
    const total = head.length + tail.length;
    if (total > 7) throw new CertificateError(`invalid IPv6 address "${text}"`);
    groups = [...head, ...new Array<number>(8 - total).fill(0), ...tail];
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const group = groups[i] as number;
    out[i * 2] = (group >> 8) & 0xff;
    out[i * 2 + 1] = group & 0xff;
  }
  return out;
}

// 切分 IPv6 的冒号分段。
//
// Splits an IPv6 colon-separated part.
function splitPart(part: string): string[] {
  if (part.length === 0) return [];
  return part.split(':').filter((item) => item !== '');
}

// 把 IPv6 分段转为 16-bit 组。
//
// Converts IPv6 parts to 16-bit groups.
function groupsOf(parts: string[], allowIpv4AtEnd: boolean, text: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] as string;
    if (part.includes('.')) {
      if (!allowIpv4AtEnd || i !== parts.length - 1) {
        throw new CertificateError(`invalid IPv6 address "${text}"`);
      }
      const v4 = parseIpv4(part);
      out.push(((v4[0] as number) << 8) | (v4[1] as number));
      out.push(((v4[2] as number) << 8) | (v4[3] as number));
      continue;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {
      throw new CertificateError(`invalid IPv6 address "${text}"`);
    }
    out.push(Number.parseInt(part, 16));
  }
  return out;
}

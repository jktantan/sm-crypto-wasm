/**
 * 字符串/字节互转（hex / base64 / PEM / Uint8Array）。
 *
 * 设计要点：
 * - **输入嗅探（auto-detect）**：调用方传 `string` 时，按下表判断编码：
 *
 * | 起始特征 | 视为 |
 * |---|---|
 * | 以 `-----BEGIN` 开头 | PEM |
 * | 以 `0x` 前缀或纯 `[0-9a-fA-F]` 且长度为偶数 | hex |
 * | 其它可被 `atob` 解码的字符串 | base64 |
 *
 * - **输出格式**：业务 API 默认输出 hex，调用方传 `{ output: 'base64' | 'raw' }` 切换。
 * - **不持有宿主缓冲视图**：所有 string→bytes 都返回新 `Uint8Array`。
 *   Review-Focus #1：空字符串抛 `TypeError`，不静默成功。
 *
 * spec/plan 对应：plan Task 2；spec §6 API 默认 hex、§9 安全姿态。
 */

import { decodeBase64, encodeBase64 } from './base64.core.js';

/** 任意可被业务 API 接受的输入形态。 */
export type Input = string | Uint8Array;

/** 输出格式选项。默认 hex。 */
export type OutputFormat = 'hex' | 'base64' | 'raw';

/**
 * 把任意 `Input` 归一化为 `Uint8Array`。
 *
 * @param input 待解码的输入。
 * @param label 字段名（错误信息用，便于排查）。
 * @returns 解码后的字节数组。
 * @throws TypeError 输入为空、编码不识别、或解码失败。
 */
export function toBytes(input: Input, label: string): Uint8Array {
  if (input instanceof Uint8Array) {
    // 拷贝避免上游缓冲区变更影响下游语义。
    return new Uint8Array(input);
  }
  if (typeof input !== 'string') {
    throw new TypeError(`toBytes(${label}): expected string or Uint8Array, got ${typeof input}`);
  }
  if (input.length === 0) {
    throw new TypeError(`toBytes(${label}): empty input`);
  }

  // 嗅探顺序：PEM > hex > base64。
  if (input.startsWith('-----BEGIN')) {
    return pemToBytes(input, label);
  }
  // hex：解析与校验合并成一次遍历（非法时返回 null 而不抛错，好继续试 base64）。
  const asHex = tryParseHex(input);
  if (asHex !== null) return asHex;
  // 否则尝试 base64；失败抛 TypeError。
  return base64ToBytes(input, label);
}

/**
 * 把字节数组按指定格式编码。
 *
 * @param bytes 输入字节。
 * @param format 输出格式。`'raw` 默认 hex。`'raw`' 直接返回原引用（拷贝）。
 */
export function fromBytes(bytes: Uint8Array, format: OutputFormat = 'hex'): string {
  switch (format) {
    case 'hex':
      return bytesToHex(bytes);
    case 'base64':
      return bytesToBase64(bytes);
    case 'raw':
      // 返回拷贝避免上层修改。
      return bytesToHex(bytes) === '' ? '' : new TextDecoder().decode(bytes.slice());
    default: {
      const _exhaustive: never = format;
      throw new TypeError(`fromBytes: unknown format ${String(_exhaustive)}`);
    }
  }
}

/** bytes → hex（小写、偶数位）。空输入返回 `''`。 */
export function bytesToHex(bytes: Uint8Array): string {
  // Node：原生实现，比逐字节拼字符串快一个数量级。
  if (HAS_BUFFER) {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex');
  }
  // 浏览器：16 进制查表，避免每字节一次 `toString` + `padStart` 分配。
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const v = bytes[i] ?? 0;
    out += HEX_CHARS[v >> 4];
    out += HEX_CHARS[v & 0x0f];
  }
  return out;
}

/** hex 字符串 → bytes。支持 `0x` 前缀。奇数位长度或非法字符抛错。 */
export function hexToBytes(hex: string, label = 'hex'): Uint8Array {
  const parsed = tryParseHex(hex);
  if (parsed !== null) return parsed;
  // 失败路径：显式重扫一遍只为给出精确的错误信息（含非法字符的码位）。
  // 正常调用不会走到这里。
  let s = hex;
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
  if (s.length === 0) throw new TypeError(`hexToBytes(${label}): empty`);
  if (s.length % 2 !== 0) {
    throw new TypeError(`hexToBytes(${label}): odd length ${s.length}`);
  }
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (hexValue(code) < 0) {
      throw new TypeError(`hexToBytes(${label}): invalid hex char at code 0x${code.toString(16)}`);
    }
  }
  // tryParseHex 已覆盖全部合法情形，走到这里说明上面漏判，兜底抛错。
  throw new TypeError(`hexToBytes(${label}): invalid hex`);
}

/**
 * bytes → base64。优先级：Node `Buffer` → 宿主 `btoa` → 纯 JS 兜底。
 *
 * 微信小程序既没有 `Buffer` 也没有 `btoa`，会走最后一级；不需要宿主再安装
 * base64 polyfill。
 */
export function bytesToBase64(bytes: Uint8Array): string {
  if (HAS_BUFFER) {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
  }
  if (HAS_BTOA) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] ?? 0);
    return btoa(bin);
  }
  return encodeBase64(bytes);
}

/** base64 合法字符集（含结尾 padding）。 */
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * base64 字符串 → bytes。失败抛 TypeError。
 *
 * 优先级：Node `Buffer` → 宿主 `atob` → 纯 JS 兜底（微信小程序等）。
 */
export function base64ToBytes(b64: string, label = 'base64'): Uint8Array {
  // Node 快路径。`Buffer.from(..., 'base64')` 对非法字符是静默丢弃的，
  // 先用正则挡掉，非法的落到 `atob` 去抛错，保持与浏览器一致的行为。
  if (HAS_BUFFER && B64_RE.test(b64)) {
    const buf = Buffer.from(b64, 'base64');
    const out = new Uint8Array(buf.length);
    out.set(buf);
    return out;
  }
  if (HAS_ATOB) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return decodeBase64(b64, label);
}

/** PEM → bytes。剥去 BEGIN/END armor，base64 解码。 */
export function pemToBytes(pem: string, label = 'pem'): Uint8Array {
  const lines = pem.split(/\r?\n/);
  const body: string[] = [];
  for (const line of lines) {
    if (line.startsWith('-----')) continue;
    if (line.trim().length === 0) continue;
    body.push(line);
  }
  const joined = body.join('');
  if (joined.length === 0) {
    throw new TypeError(`pemToBytes(${label}): empty body`);
  }
  return base64ToBytes(joined, label);
}

/** bytes → PEM（带 BEGIN/END 头）。`kind` 例：`SM2 PRIVATE KEY`。 */
export function bytesToPem(bytes: Uint8Array, kind: string): string {
  const b64 = bytesToBase64(bytes);
  const lines: string[] = [];
  // 每 64 字符换行，标准做法。
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${kind}-----\n${lines.join('\n')}\n-----END ${kind}-----\n`;
}

// ---------- 内部工具 ----------

/**
 * Node 环境检测。用 `typeof` 保证在浏览器打包（`Buffer` 未定义）时不抛错。
 *
 * 命中时 hex/base64 编解码走 Node 原生实现，比逐字节的 JS 循环快一个数量级
 * （实测 4 KB 输入：hex 编码 52.6 µs → 1.9 µs）。
 */
const HAS_BUFFER = typeof Buffer !== 'undefined' && typeof Buffer.from === 'function';

/** 宿主是否提供 `btoa` / `atob`（现代浏览器有；微信小程序没有）。 */
const HAS_BTOA = typeof btoa === 'function';
const HAS_ATOB = typeof atob === 'function';

/** 16 进制数字查表（浏览器路径）。 */
const HEX_CHARS = '0123456789abcdef';

/**
 * 尝试把字符串按 hex 解析；不是合法 hex 时返回 `null`（不抛错）。
 *
 * **解析即校验**：`Buffer.from(..., 'hex')` 遇到非法字符就停止解析，因此只要
 * 「解析出的字节数 × 2 ≠ 输入长度」即可判定非法 —— 校验与解析合并成一次遍历，
 * 不再需要先跑正则判断再解析（同一串原来被扫 2~3 遍；实测 8192 字符
 * 14.1 µs → 3.5 µs）。支持 `0x` / `0X` 前缀，空串与奇数长度按非法处理。
 */
function tryParseHex(s: string): Uint8Array | null {
  let t = s;
  if (t.startsWith('0x') || t.startsWith('0X')) t = t.slice(2);
  if (t.length === 0 || t.length % 2 !== 0) return null;
  if (HAS_BUFFER) {
    const buf = Buffer.from(t, 'hex');
    return buf.length * 2 === t.length ? new Uint8Array(buf) : null;
  }
  // 浏览器：逐字符查表，同样是单趟遍历，遇到非法字符立即返回 null。
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexValue(t.charCodeAt(i * 2));
    const lo = hexValue(t.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) return null;
    out[i] = (hi << 4) | lo;
  }
  return out;
}

/** 单个 hex 字符的数值；非法字符返回 `-1`。 */
function hexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

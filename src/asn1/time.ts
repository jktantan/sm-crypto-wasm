/**
 * X.509 时间编码/解析（UTCTime / GeneralizedTime）。
 *
 * 规则（RFC 5280）：
 * - 1950–2049 用 UTCTime（`YYMMDDHHMMSSZ`）；
 * - 其余年份用 GeneralizedTime（`YYYYMMDDHHMMSSZ`）；
 * - 证书时间精度到秒：解析时毫秒一律截断，保证 parse → encode round-trip。
 *
 * 解析刻意宽松（接受无秒、无时区、GeneralizedTime 的小数秒），因为真实现场
 * 存在非规范编码；编码始终输出规范形式。
 */

import { Asn1Error } from './types.js';

/**
 * 编码 UTCTime（仅接受 1950–2049 年）。
 *
 * @throws RangeError 日期无效或年份越界。
 */
export function encodeUtcTime(date: Date): string {
  const { year, month, day, hour, minute, second } = utcParts(date, 'encodeUtcTime');
  if (year < 1950 || year > 2049) {
    throw new RangeError(`encodeUtcTime: year ${year} outside 1950..2049`);
  }
  const yy = year % 100;
  return `${pad2(yy)}${pad2(month)}${pad2(day)}${pad2(hour)}${pad2(minute)}${pad2(second)}Z`;
}

/**
 * 编码 GeneralizedTime。
 *
 * @throws RangeError 日期无效。
 */
export function encodeGeneralizedTime(date: Date): string {
  const { year, month, day, hour, minute, second } = utcParts(date, 'encodeGeneralizedTime');
  return `${pad4(year)}${pad2(month)}${pad2(day)}${pad2(hour)}${pad2(minute)}${pad2(second)}Z`;
}

/**
 * 按 RFC 5280 自动选择 UTCTime（1950–2049）或 GeneralizedTime。
 */
export function encodeTime(date: Date): string {
  const year = utcParts(date, 'encodeTime').year;
  return year >= 1950 && year <= 2049 ? encodeUtcTime(date) : encodeGeneralizedTime(date);
}

/**
 * 解析 UTCTime 或 GeneralizedTime 字符串。
 *
 * 接受：
 * - `YYMMDDHHMMSSZ` / `YYMMDDHHMMZ`（UTCTime，50–99 → 1950–1999，00–49 → 2000–2049）；
 * - `YYYYMMDDHHMMSSZ` / `YYYYMMDDHHMMZ` / `YYYYMMDDHHMMSS.sssZ`（GeneralizedTime）；
 * - 时间部分可带 `+HHMM` / `-HHMM` 偏移；省略时区按 UTC 处理。
 *
 * @returns 毫秒为 0 的 `Date`。
 * @throws Asn1Error 格式或日期分量非法。
 */
export function parseTime(text: string): Date {
  const s = text.trim();
  const m = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?([.,]\d+)?(Z|[+-]\d{4})?$/.exec(s);
  if (!m) throw new Asn1Error(`parseTime: unsupported time syntax "${text}"`);

  const yearToken = m[1] as string;
  const year = yearToken.length === 2 ? utcYear(Number(yearToken)) : Number(yearToken);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = m[5] === undefined ? 0 : Number(m[5]);
  const second = m[6] === undefined ? 0 : Number(m[6]);
  const zone = m[8];

  let offsetMinutes = 0;
  if (zone !== undefined && zone !== 'Z') {
    const sign = zone.startsWith('-') ? -1 : 1;
    const oh = Number(zone.slice(1, 3));
    const om = Number(zone.slice(3, 5));
    if (oh > 23 || om > 59) throw new Asn1Error(`parseTime: bad timezone offset "${zone}"`);
    offsetMinutes = sign * (oh * 60 + om);
  }

  const localMs = Date.UTC(year, month - 1, day, hour, minute, second);
  // 先在「输入的本地分量」上校验日期合法性，再应用时区偏移。
  const local = new Date(localMs);
  if (
    Number.isNaN(local.getTime()) ||
    local.getUTCFullYear() !== year ||
    local.getUTCMonth() !== month - 1 ||
    local.getUTCDate() !== day ||
    local.getUTCHours() !== hour ||
    local.getUTCMinutes() !== minute ||
    local.getUTCSeconds() !== second
  ) {
    throw new Asn1Error(`parseTime: invalid date components in "${text}"`);
  }
  return new Date(localMs - offsetMinutes * 60_000);
}

/** UTCTime 两位年份展开。 */
function utcYear(yy: number): number {
  return yy >= 50 ? 1900 + yy : 2000 + yy;
}

interface TimeParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

function utcParts(date: Date, where: string): TimeParts {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw new RangeError(`${where}: invalid Date`);
  }
  return {
    year: date.getUTCFullYear(),
    month: date.getUTCMonth() + 1,
    day: date.getUTCDate(),
    hour: date.getUTCHours(),
    minute: date.getUTCMinutes(),
    second: date.getUTCSeconds(),
  };
}

function pad2(n: number): string {
  return n.toString(10).padStart(2, '0');
}

function pad4(n: number): string {
  return n.toString(10).padStart(4, '0');
}

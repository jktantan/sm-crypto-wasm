/**
 * 混合加密密文（sealed）的版本化序列化。
 *
 * 布局（全部大端）：
 *
 * ```text
 *   version(1) || klen(1) || encapLen(2) || encapsulation(encapLen)
 *              || iv(12) || tag(16) || ct(rest)
 * ```
 *
 * - `version` 当前为 `1`；未知版本必须拒绝，不能静默按 v1 解析。
 * - `klen` 是 KEM 输出的 DEM 密钥字节数（SM4-128 固定为 16）。
 * - `encapLen` 让解析器能精确切出 KEM 封装段，同时也能识别“长度字段说谎”。
 * - `iv` / `tag` 定长：GCM 推荐 12 字节 IV、16 字节 tag。
 *
 * 对象形态 `SealedObject` 只用于调试 / 自描述场景；线上传输仍建议用单个
 * hex 字符串（`sealedToObject` / `sealedFromObject` 负责互转）。
 *
 * spec/plan 对应：`docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`
 * Task 2。
 *
 * Versioned serialization of the hybrid (sealed) ciphertext.
 *
 * Layout (all big-endian):
 *
 * ```text
 *   version(1) || klen(1) || encapLen(2) || encapsulation(encapLen)
 *              || iv(12) || tag(16) || ct(rest)
 * ```
 *
 * - `version` is currently `1`; an unknown version must be rejected, never silently
 *   parsed as v1.
 * - `klen` is the DEM key size in bytes produced by the KEM (fixed 16 for SM4-128).
 * - `encapLen` lets the parser cut out the KEM encapsulation precisely and also detect
 *   a "lying" length field.
 * - `iv` / `tag` are fixed length: GCM recommends a 12-byte IV and a 16-byte tag.
 *
 * The object form `SealedObject` is only meant for debugging / self-describing
 * scenarios; wire transfer should still use a single hex string (`sealedToObject` /
 * `sealedFromObject` convert between the two).
 *
 * spec/plan: `docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md` Task 2.
 */

import { bytesToHex, hexToBytes, toBytes } from '../runtime/convert.js';
import { InvalidCiphertextError } from '../runtime/errors.js';

/** 当前 sealed 格式版本。
 *
 * The current sealed format version.
 */
export const SEALED_VERSION = 1;

/** GCM IV 长度（字节）。
 *
 * GCM IV length in bytes.
 */
export const SEALED_IV_LEN = 12;

/** GCM tag 长度（字节）。
 *
 * GCM tag length in bytes.
 */
export const SEALED_TAG_LEN = 16;

/** 头部长度：version + klen + encapLen。
 *
 * Header length: version + klen + encapLen.
 */
export const SEALED_HEADER_LEN = 4;

/** DEM 密钥长度：SM4-128 固定 16 字节。
 *
 * DEM key length: fixed at 16 bytes for SM4-128.
 */
export const DEM_KEY_LEN = 16;

/** 解析后的 sealed 各段（字节形态）。
 *
 * The parsed sealed segments (as bytes).
 */
export interface SealedParts {
  /** 格式版本，当前恒为 1。
   *
   * Format version; always 1 today.
   */
  version: number;
  /** KEM 输出的 DEM 密钥字节数。
   *
   * Number of DEM key bytes produced by the KEM.
   */
  klen: number;
  /** KEM 封装段（长度由头部 `encapLen` 界定）。
   *
   * The KEM encapsulation segment (its length is delimited by the header's `encapLen`).
   */
  encapsulation: Uint8Array;
  /** GCM IV（12 字节）。
   *
   * GCM IV (12 bytes).
   */
  iv: Uint8Array;
  /** GCM tag（16 字节）。
   *
   * GCM tag (16 bytes).
   */
  tag: Uint8Array;
  /** GCM 密文（余下全部字节，可为空）。
   *
   * GCM ciphertext (every remaining byte, may be empty).
   */
  ct: Uint8Array;
}

/**
 * sealed 的对象形态（各字段均为 hex）。
 *
 * 适合日志 / 调试 / 与手工 `kemEncrypt + sm4.encryptGCM` 组装互操作。
 *
 * The object form of a sealed ciphertext (every field is hex).
 *
 * Suitable for logging / debugging / interoperating with a hand-assembled
 * `kemEncrypt + sm4.encryptGCM`.
 */
export interface SealedObject {
  /** 格式版本，当前必须为 1。
   *
   * Format version; currently it must be 1.
   */
  v: number;
  /** KEM 输出的 DEM 密钥字节数。
   *
   * Number of DEM key bytes produced by the KEM.
   */
  klen: number;
  /** KEM 封装段。
   *
   * The KEM encapsulation segment.
   */
  encapsulation: string;
  /** GCM IV（12 字节）。
   *
   * GCM IV (12 bytes).
   */
  iv: string;
  /** GCM tag（16 字节）。
   *
   * GCM tag (16 bytes).
   */
  tag: string;
  /** GCM 密文（可为空）。
   *
   * GCM ciphertext (may be empty).
   */
  ct: string;
}

/** 把各段组装成 sealed 字节。
 *
 * Assemble the segments into sealed bytes.
 */
export function encodeSealed(parts: SealedParts): Uint8Array {
  const { version, klen, encapsulation, iv, tag, ct } = parts;
  if (!Number.isInteger(version) || version < 0 || version > 0xff) {
    throw new RangeError(`sealed: version 必须是 [0, 255] 内的整数，实际 ${version}`);
  }
  if (!Number.isInteger(klen) || klen <= 0 || klen > 0xff) {
    throw new RangeError(`sealed: klen 必须是 [1, 255] 内的整数，实际 ${klen}`);
  }
  if (encapsulation.length > 0xffff) {
    throw new RangeError(`sealed: encapsulation 不能超过 65535 字节，实际 ${encapsulation.length}`);
  }
  if (iv.length !== SEALED_IV_LEN) {
    throw new RangeError(`sealed: iv 必须是 ${SEALED_IV_LEN} 字节，实际 ${iv.length}`);
  }
  if (tag.length !== SEALED_TAG_LEN) {
    throw new RangeError(`sealed: tag 必须是 ${SEALED_TAG_LEN} 字节，实际 ${tag.length}`);
  }

  const out = new Uint8Array(
    SEALED_HEADER_LEN + encapsulation.length + SEALED_IV_LEN + SEALED_TAG_LEN + ct.length,
  );
  out[0] = version;
  out[1] = klen;
  out[2] = (encapsulation.length >>> 8) & 0xff;
  out[3] = encapsulation.length & 0xff;
  let off = SEALED_HEADER_LEN;
  out.set(encapsulation, off);
  off += encapsulation.length;
  out.set(iv, off);
  off += SEALED_IV_LEN;
  out.set(tag, off);
  off += SEALED_TAG_LEN;
  out.set(ct, off);
  return out;
}

/** 把输入归一化成 sealed 字节。空输入按密文支错误处理。
 *
 * Normalize the input into sealed bytes. An empty input is handled as a ciphertext-branch
 * error.
 */
function sealedBytes(sealed: string | Uint8Array): Uint8Array {
  if (typeof sealed === 'string' && sealed.length === 0) {
    throw new InvalidCiphertextError('sealed: 密文为空');
  }
  if (sealed instanceof Uint8Array && sealed.length === 0) {
    throw new InvalidCiphertextError('sealed: 密文为空');
  }
  return toBytes(sealed, 'sealed');
}

/**
 * 严格解析 sealed 字节。
 *
 * @throws {InvalidCiphertextError} 版本未知、长度字段与实长不符、任何一段被截断。
 *
 * Strictly parse sealed bytes.
 *
 * @throws {InvalidCiphertextError} Unknown version, a length field that disagrees with
 *   the actual length, or any truncated segment.
 */
export function decodeSealed(sealed: string | Uint8Array): SealedParts {
  const b = sealedBytes(sealed);
  if (b.length < SEALED_HEADER_LEN) {
    throw new InvalidCiphertextError(`sealed: 长度不足（${b.length} 字节，至少需要 4 字节头部）`);
  }
  const version = b[0] ?? 0;
  if (version !== SEALED_VERSION) {
    throw new InvalidCiphertextError(`sealed: 未知版本 ${version}（当前支持 ${SEALED_VERSION}）`);
  }
  const klen = b[1] ?? 0;
  if (klen === 0) {
    throw new InvalidCiphertextError('sealed: klen 不能为 0');
  }
  const encapLen = ((b[2] ?? 0) << 8) | (b[3] ?? 0);
  const fixed = SEALED_HEADER_LEN + encapLen + SEALED_IV_LEN + SEALED_TAG_LEN;
  if (b.length < fixed) {
    throw new InvalidCiphertextError(
      `sealed: 长度字段 encapLen=${encapLen} 与实长 ${b.length} 不符（至少需要 ${fixed} 字节）`,
    );
  }

  let off = SEALED_HEADER_LEN;
  const encapsulation = b.slice(off, off + encapLen);
  off += encapLen;
  const iv = b.slice(off, off + SEALED_IV_LEN);
  off += SEALED_IV_LEN;
  const tag = b.slice(off, off + SEALED_TAG_LEN);
  off += SEALED_TAG_LEN;
  const ct = b.slice(off);
  return { version, klen, encapsulation, iv, tag, ct };
}

/** sealed → 对象形态（各字段 hex）。
 *
 * sealed → object form (every field in hex).
 */
export function sealedToObject(sealed: string | Uint8Array): SealedObject {
  const p = decodeSealed(sealed);
  return {
    v: p.version,
    klen: p.klen,
    encapsulation: bytesToHex(p.encapsulation),
    iv: bytesToHex(p.iv),
    tag: bytesToHex(p.tag),
    ct: bytesToHex(p.ct),
  };
}

/**
 * 对象形态 → sealed hex。
 *
 * 严格校验每个字段：版本、klen、encapsulation 非空、iv/tag 定长。
 * 任何不合法都抛 `InvalidCiphertextError`（对象本身描述的是密文）。
 *
 * Object form → sealed hex.
 *
 * Every field is strictly validated: version, klen, non-empty encapsulation, fixed-length
 * iv/tag. Anything illegal throws `InvalidCiphertextError` (the object itself describes
 * a ciphertext).
 */
export function sealedFromObject(obj: SealedObject): string {
  if (obj === null || typeof obj !== 'object') {
    throw new InvalidCiphertextError(
      'sealed: 对象形态必须是 { v, klen, encapsulation, iv, tag, ct }',
    );
  }
  if (
    typeof obj.v !== 'number' ||
    typeof obj.klen !== 'number' ||
    typeof obj.encapsulation !== 'string' ||
    typeof obj.iv !== 'string' ||
    typeof obj.tag !== 'string' ||
    typeof obj.ct !== 'string'
  ) {
    throw new InvalidCiphertextError(
      'sealed: 对象字段类型必须是 { v:number, klen:number, encapsulation/iv/tag/ct:string }',
    );
  }
  if (obj.v !== SEALED_VERSION) {
    throw new InvalidCiphertextError(
      `sealed: 未知版本 ${String(obj.v)}（当前支持 ${SEALED_VERSION}）`,
    );
  }
  if (!Number.isInteger(obj.klen) || obj.klen <= 0 || obj.klen > 0xff) {
    throw new InvalidCiphertextError(
      `sealed: klen 必须是 [1, 255] 内的整数，实际 ${String(obj.klen)}`,
    );
  }
  const encapsulation = hexToBytes(obj.encapsulation, 'encapsulation');
  const iv = hexToBytes(obj.iv, 'iv');
  const tag = hexToBytes(obj.tag, 'tag');
  const ct = obj.ct.length === 0 ? new Uint8Array(0) : hexToBytes(obj.ct, 'ct');
  if (encapsulation.length === 0) {
    throw new InvalidCiphertextError('sealed: encapsulation 不能为空');
  }
  if (iv.length !== SEALED_IV_LEN) {
    throw new InvalidCiphertextError(`sealed: iv 必须是 ${SEALED_IV_LEN} 字节，实际 ${iv.length}`);
  }
  if (tag.length !== SEALED_TAG_LEN) {
    throw new InvalidCiphertextError(
      `sealed: tag 必须是 ${SEALED_TAG_LEN} 字节，实际 ${tag.length}`,
    );
  }
  return bytesToHex(encodeSealed({ version: obj.v, klen: obj.klen, encapsulation, iv, tag, ct }));
}

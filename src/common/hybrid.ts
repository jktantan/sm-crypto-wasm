/**
 * 混合加密的共享输入约定。
 *
 * 两个 hybrid 模块（SM2 / SM9）对 message 采用**同一套**字符串语义：
 * - `Uint8Array`：原样使用（拷贝）；
 * - `string`：必须是 hex（允许 `0x` 前缀），不再猜 base64 / UTF-8；
 * - 空消息请传 `new Uint8Array(0)`；空字符串按既有 `toBytes` 契约直接拒绝，
 *   避免“空输入静默成功”。
 *
 * IV 同样按 hex / Uint8Array 处理，未提供时由宿主 CSPRNG 生成 12 字节。
 *
 * Shared input conventions for hybrid encryption.
 *
 * The two hybrid modules (SM2 / SM9) apply **the same** string semantics to `message`:
 * - `Uint8Array`: used as is (copied);
 * - `string`: must be hex (a `0x` prefix is allowed); base64 / UTF-8 are no longer
 *   guessed;
 * - pass `new Uint8Array(0)` for an empty message — an empty string is rejected
 *   outright by the existing `toBytes` contract, which avoids "empty input silently
 *   succeeds".
 *
 * The IV is likewise hex / Uint8Array; when omitted, 12 bytes are generated from the
 * host CSPRNG.
 */

import { hexToBytes } from '../runtime/convert.js';
import { randomBytes } from '../runtime/random.js';
import { SEALED_IV_LEN } from './sealed.js';

/**
 * 把 hybrid 的 message 归一化为字节。
 *
 * @param input hex 字符串或字节数组。
 * @param label 错误信息里的字段名。
 * @throws TypeError 空字符串、奇数长度、非 hex 字符或类型不对。
 *
 * Normalize the hybrid `message` into bytes.
 *
 * @param input A hex string or a byte array.
 * @param label Field name used in error messages.
 * @throws TypeError The string is empty or of odd length, contains a non-hex character,
 *   or the value has the wrong type.
 */
export function toMessageBytes(input: string | Uint8Array, label = 'message'): Uint8Array {
  if (input instanceof Uint8Array) return new Uint8Array(input);
  if (typeof input !== 'string') {
    throw new TypeError(`hybrid: ${label} 必须是 hex 字符串或 Uint8Array`);
  }
  if (input.length === 0) {
    throw new TypeError(`hybrid: ${label} 为空；空消息请传 new Uint8Array(0)`);
  }
  return hexToBytes(input, label);
}

/**
 * 归一化 hybrid 的 IV：未提供则新生成 12 字节；提供则必须恰好 12 字节。
 *
 * @throws RangeError 长度不是 12。
 *
 * Normalize the hybrid IV: generate 12 fresh bytes when absent; when supplied it must
 * be exactly 12 bytes.
 *
 * @throws RangeError The length is not 12.
 */
export function resolveIv(iv: string | Uint8Array | undefined): Uint8Array {
  const out =
    iv === undefined
      ? randomBytes(SEALED_IV_LEN)
      : iv instanceof Uint8Array
        ? new Uint8Array(iv)
        : hexToBytes(iv, 'iv');
  if (out.length !== SEALED_IV_LEN) {
    throw new RangeError(`hybrid: iv 必须是 ${SEALED_IV_LEN} 字节，实际 ${out.length}`);
  }
  return out;
}

/**
 * SM2 混合加密（KEM + DEM）：公钥只保护一把短密钥，消息交给 SM4-GCM。
 *
 * 流程：
 * ```
 *   DEK                         = CSPRNG(16)                 // 每次调用新生成
 *   { key, encapsulation }      = kemEncrypt(publicKey, 16)  // SM2 加密 DEK
 *   { ct, tag }                 = SM4-GCM(key, iv, msg, aad = encapsulation)
 *   sealed                      = version || klen || encapLen || encapsulation
 *                                 || iv || tag || ct
 * ```
 *
 * 安全要点（实现时逐条满足）：
 * - **每次调用都新生成 DEK 与 IV**，不跨调用复用；
 * - IV 默认由宿主 CSPRNG 生成 12 字节；
 * - SM2 的 C3 校验先于 GCM 解密，封装被篡改会在 KEM 阶段失败；
 * - AAD 绑定 encapsulation，防止把一份封装配到另一份密文上；
 * - sealed 首字节带版本号，未知版本拒绝解析。
 *
 * `hybridEncrypt` / `hybridDecrypt` 是同步函数（`.wasm` 由
 * `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])` 预热）。
 *
 * spec/plan 对应：`docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`
 * Task 2 / Task 3。
 */

import { resolveIv, toMessageBytes } from '../common/hybrid.js';
import {
  DEM_KEY_LEN,
  decodeSealed,
  encodeSealed,
  SEALED_VERSION,
  sealedFromObject,
  sealedToObject,
} from '../common/sealed.js';
import { bytesToHex, hexToBytes } from '../runtime/convert.js';
import { CiphertextError, InvalidCiphertextError } from '../runtime/errors.js';
import { decryptGCM, encryptGCM } from '../sm4/index.js';
import { kemDecrypt, kemEncrypt } from './kem.js';

export { sealedFromObject, sealedToObject };

/** `hybridEncrypt` 选项。 */
export interface Sm2HybridEncryptOptions {
  /**
   * 显式指定 GCM IV（12 字节 hex / Uint8Array）。
   *
   * 默认由宿主 CSPRNG 生成。**显式复用同一个 IV 配不同消息会破坏 GCM 的机密性**，
   * 该参数只用于测试 / 协议互操作；正常调用不要传。
   */
  iv?: string | Uint8Array;
}

/** `hybridDecrypt` 选项。 */
export interface Sm2HybridDecryptOptions {
  /**
   * 解密失败时返回 `null` 而不抛错。
   *
   * 只覆盖密文支错误（`CiphertextError`：sealed 结构错、KEM C3 校验失败、
   * GCM tag 校验失败）；参数类型错误仍会抛出。
   */
  safeMode?: boolean;
}

/**
 * SM2 混合加密。
 *
 * @param publicKey 64 或 65 字节公钥（hex / Uint8Array / PEM）。
 * @param message 明文（hex / Uint8Array；空消息传 `new Uint8Array(0)`）。
 * @param opts `iv` 可选，默认随机 12 字节。
 * @returns sealed hex（版本化，见模块注释）。
 */
export function hybridEncrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts: Sm2HybridEncryptOptions = {},
): string {
  const iv = resolveIv(opts.iv);
  // 先校验 message，避免非法输入还白耗一次 SM2 公钥运算与随机数。
  const msg = toMessageBytes(message, 'message');
  // DEK 来自宿主 CSPRNG，每次调用都新生成；长度固定为 SM4-128 的 16 字节。
  const { key, encapsulation } = kemEncrypt(publicKey, DEM_KEY_LEN);
  const enc = hexToBytes(encapsulation, 'encapsulation');
  // AAD 绑定 KEM 封装段：换掉封装就无法通过 GCM 认证。
  const { ct, tag } = encryptGCM(key, iv, msg, enc);
  return bytesToHex(
    encodeSealed({
      version: SEALED_VERSION,
      klen: DEM_KEY_LEN,
      encapsulation: enc,
      iv,
      tag: hexToBytes(tag, 'tag'),
      ct: ct.length === 0 ? new Uint8Array(0) : hexToBytes(ct, 'ct'),
    }),
  );
}

/**
 * SM2 混合解密。
 *
 * @param privateKey 32 字节私钥（hex / Uint8Array / PEM）。
 * @param sealed `hybridEncrypt` 的返回值。
 * @param opts `safeMode`：失败时返回 `null`。
 * @returns 明文 hex。
 */
export function hybridDecrypt(
  privateKey: string | Uint8Array,
  sealed: string | Uint8Array,
  opts: Sm2HybridDecryptOptions & { safeMode: true },
): string | null;
export function hybridDecrypt(
  privateKey: string | Uint8Array,
  sealed: string | Uint8Array,
  opts?: Sm2HybridDecryptOptions,
): string;
export function hybridDecrypt(
  privateKey: string | Uint8Array,
  sealed: string | Uint8Array,
  opts: Sm2HybridDecryptOptions = {},
): string | null {
  try {
    const parts = decodeSealed(sealed);
    if (parts.klen !== DEM_KEY_LEN) {
      throw new InvalidCiphertextError(
        `sm2.hybridDecrypt: sealed.klen=${parts.klen}，当前版本只支持 ${DEM_KEY_LEN}`,
      );
    }
    // SM2 KEM 的 encapsulation 是完整 SM2 密文：C1(65) + C3(32) + C2(klen)。
    if (parts.encapsulation.length !== 97 + parts.klen) {
      throw new InvalidCiphertextError(
        `sm2.hybridDecrypt: encapsulation 长度 ${parts.encapsulation.length} 与 klen=${parts.klen} 不符`,
      );
    }
    // KEM 解封装先校验 SM2 C3；失败会抛 DecryptionError，不会进入 GCM。
    const key = kemDecrypt(privateKey, parts.encapsulation, parts.klen);
    return decryptGCM(key, parts.iv, parts.ct, parts.tag, { aad: parts.encapsulation });
  } catch (err) {
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

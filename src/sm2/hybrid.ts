/**
 * SM2 混合加密（KEM + DEM）：公钥只保护一把短密钥，消息交给 SM4-GCM。
 *
 * 流程：
 * ```
 *   DEK                         = CSPRNG(16)                 // 每次调用新生成
 *                                                             // fresh per call
 *   { key, encapsulation }      = kemEncrypt(publicKey, 16)  // SM2 加密 DEK
 *                                                             // SM2-encrypt the DEK
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
 *
 * SM2 hybrid encryption (KEM + DEM): the public key protects only a short key, and the
 * message goes to SM4-GCM.
 *
 * Flow:
 * ```
 *   DEK                         = CSPRNG(16)                 // fresh per call
 *   { key, encapsulation }      = kemEncrypt(publicKey, 16)  // SM2-encrypt the DEK
 *   { ct, tag }                 = SM4-GCM(key, iv, msg, aad = encapsulation)
 *   sealed                      = version || klen || encapLen || encapsulation
 *                                 || iv || tag || ct
 * ```
 *
 * Security requirements (each satisfied by the implementation):
 * - **a fresh DEK and IV are generated on every call**, never reused across calls;
 * - the IV is 12 random bytes from the host CSPRNG by default;
 * - SM2's C3 check runs before GCM decryption, so a tampered encapsulation fails at the
 *   KEM stage;
 * - the AAD binds the encapsulation, so one encapsulation cannot be attached to another
 *   ciphertext;
 * - the first byte of sealed carries the version; unknown versions are rejected.
 *
 * `hybridEncrypt` / `hybridDecrypt` are synchronous (warm the `.wasm` modules with
 * `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])`).
 *
 * Spec/plan: `docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md` Task 2 / Task 3.
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

// 重新导出 sealed 结构的序列化助手，供调用方解析 / 组装载荷。
//
// Re-export the sealed-structure helpers so callers can decode / assemble payloads.
export { sealedFromObject, sealedToObject };

/**
 * `hybridEncrypt` 选项。
 *
 * Options for `hybridEncrypt`.
 */
export interface Sm2HybridEncryptOptions {
  /**
   * 显式指定 GCM IV（12 字节 hex / Uint8Array）。
   *
   * 默认由宿主 CSPRNG 生成。**显式复用同一个 IV 配不同消息会破坏 GCM 的机密性**，
   * 该参数只用于测试 / 协议互操作；正常调用不要传。
   *
   * Pass an explicit GCM IV (12-byte hex / Uint8Array).
   *
   * Generated from the host CSPRNG by default. **Deliberately reusing one IV with
   * different messages destroys GCM confidentiality**; this parameter exists only for
   * tests / protocol interop and should not be passed by normal callers.
   */
  iv?: string | Uint8Array;
}

/**
 * `hybridDecrypt` 选项。
 *
 * Options for `hybridDecrypt`.
 */
export interface Sm2HybridDecryptOptions {
  /**
   * 解密失败时返回 `null` 而不抛错。
   *
   * 只覆盖密文支错误（`CiphertextError`：sealed 结构错、KEM C3 校验失败、
   * GCM tag 校验失败）；参数类型错误仍会抛出。
   *
   * Return `null` instead of throwing when decryption fails.
   *
   * Covers only ciphertext-branch errors (`CiphertextError`: bad sealed structure, KEM C3
   * check failure, GCM tag check failure); argument type errors still throw.
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
 *
 * SM2 hybrid encryption.
 *
 * @param publicKey A 64- or 65-byte public key (hex / Uint8Array / PEM).
 * @param message The plaintext (hex / Uint8Array; pass `new Uint8Array(0)` for an empty
 *   message).
 * @param opts `iv` is optional and defaults to 12 random bytes.
 * @returns The sealed payload as versioned hex (see the module comment).
 */
export function hybridEncrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts: Sm2HybridEncryptOptions = {},
): string {
  const iv = resolveIv(opts.iv);
  // 先校验 message，避免非法输入还白耗一次 SM2 公钥运算与随机数。
  //
  // Validate the message first so invalid input does not waste an SM2 public-key
  // operation and a random draw.
  const msg = toMessageBytes(message, 'message');
  // DEK 来自宿主 CSPRNG，每次调用都新生成；长度固定为 SM4-128 的 16 字节。
  //
  // The DEK comes from the host CSPRNG and is fresh on every call; its length is the
  // fixed 16 bytes of SM4-128.
  const { key, encapsulation } = kemEncrypt(publicKey, DEM_KEY_LEN);
  const enc = hexToBytes(encapsulation, 'encapsulation');
  // AAD 绑定 KEM 封装段：换掉封装就无法通过 GCM 认证。
  //
  // The AAD binds the KEM encapsulation: swapping it breaks GCM authentication.
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
 *
 * SM2 hybrid decryption.
 *
 * @param privateKey The 32-byte private key (hex / Uint8Array / PEM).
 * @param sealed The value returned by `hybridEncrypt`.
 * @param opts `safeMode`: return `null` on failure.
 * @returns The plaintext in hex.
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
    //
    // The KEM encapsulation is a full SM2 ciphertext: C1(65) + C3(32) + C2(klen).
    if (parts.encapsulation.length !== 97 + parts.klen) {
      throw new InvalidCiphertextError(
        `sm2.hybridDecrypt: encapsulation 长度 ${parts.encapsulation.length} 与 klen=${parts.klen} 不符`,
      );
    }
    // KEM 解封装先校验 SM2 C3；失败会抛 DecryptionError，不会进入 GCM。
    //
    // KEM decapsulation checks the SM2 C3 value first; on failure it throws
    // DecryptionError and never reaches GCM.
    const key = kemDecrypt(privateKey, parts.encapsulation, parts.klen);
    return decryptGCM(key, parts.iv, parts.ct, parts.tag, { aad: parts.encapsulation });
  } catch (err) {
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

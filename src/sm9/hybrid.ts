/**
 * SM9 混合加密（KEM + DEM）：主公钥只保护一把短密钥，消息交给 SM4-GCM。
 *
 * 流程：
 * ```
 *   { key, encapsulation } = KEM(masterPublicKey 或 masterPrivateKey, id, 16)
 *   { ct, tag }            = SM4-GCM(key, iv, msg, aad = encapsulation)
 *   sealed                 = version || klen || encapLen || encapsulation
 *                            || iv || tag || ct
 * ```
 *
 * 与 `sm9.encrypt` 一致，第一参数既接受**加密主公钥**（64 字节 / SPKI PEM），
 * 也接受**加密主私钥**（32 字节 / PKCS#8 PEM）；前者是发送方的典型形态。
 *
 * 本模块同时用到 `sm9.wasm` 与 `sm4.wasm`：首次调用前请分别
 * `await sm9.ensureLoaded()` 与 `await sm4.ensureLoaded()`。
 *
 * 完整性边界：SM9 KEM 的 encapsulation 只有 C1（65 字节），本身没有 C3/HMAC；
 * 错误 id / 错误主公钥会得到不同的 K，最终由 GCM tag 认证失败暴露。因此
 * `hybridDecrypt` 对错误 id 抛的是 GCM 的 `DecryptionError`，而不是 KEM 错误。
 *
 * spec/plan 对应：`docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`
 * Task 4。
 *
 * SM9 hybrid encryption (KEM + DEM): the master public key protects only a short
 * key, and the message goes through SM4-GCM.
 *
 * Flow:
 * ```
 *   { key, encapsulation } = KEM(masterPublicKey or masterPrivateKey, id, 16)
 *   { ct, tag }            = SM4-GCM(key, iv, msg, aad = encapsulation)
 *   sealed                 = version || klen || encapLen || encapsulation
 *                            || iv || tag || ct
 * ```
 *
 * As with `sm9.encrypt`, the first parameter accepts either the **encryption master
 * public key** (64 bytes / SPKI PEM) or the **encryption master private key**
 * (32 bytes / PKCS#8 PEM); the former is the sender's typical shape.
 *
 * This module uses both `sm9.wasm` and `sm4.wasm`: call `await sm9.ensureLoaded()`
 * and `await sm4.ensureLoaded()` before the first use.
 *
 * Integrity boundary: the SM9 KEM encapsulation is only C1 (65 bytes) and carries no
 * C3/HMAC of its own; a wrong id or wrong master public key yields a different K,
 * which ultimately surfaces as a GCM tag verification failure. That is why
 * `hybridDecrypt` throws the GCM `DecryptionError` for a wrong id, not a KEM error.
 *
 * Spec / plan: `docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md` Task 4.
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
import { keyArg, toBytes } from './input.js';
import { kemDecrypt, kemEncapsulateWithMasterPublic, kemEncrypt } from './kem.js';

// 转发 sealed 封包与对象形态的互转工具（定义在 `../common/sealed.js`）。
//
// Re-exports the sealed-envelope ↔ object converters (defined in
// `../common/sealed.js`).
export { sealedFromObject, sealedToObject };

/**
 * `hybridEncrypt` 选项。
 *
 * Options for `hybridEncrypt`.
 */
export interface Sm9HybridEncryptOptions {
  /**
   * 显式指定 GCM IV（12 字节 hex / Uint8Array）。
   *
   * 默认由宿主 CSPRNG 生成。**显式复用同一个 IV 配不同消息会破坏 GCM 的机密性**，
   * 该参数只用于测试 / 协议互操作；正常调用不要传。
   *
   * An explicit GCM IV (12 bytes, hex / `Uint8Array`).
   *
   * Generated from the host CSPRNG by default. **Reusing the same IV with different
   * messages breaks GCM confidentiality**, so this parameter exists only for tests /
   * protocol interop; do not pass it in normal calls.
   */
  iv?: string | Uint8Array;
}

/**
 * `hybridDecrypt` 选项。
 *
 * Options for `hybridDecrypt`.
 */
export interface Sm9HybridDecryptOptions {
  /**
   * 解密失败时返回 `null` 而不抛错。
   *
   * 只覆盖密文支错误（`CiphertextError`：sealed 结构错、GCM tag 校验失败）；
   * 参数类型错误 / 密钥格式错误仍会抛出。
   *
   * Return `null` instead of throwing when decryption fails.
   *
   * It covers only ciphertext-branch errors (`CiphertextError`: bad sealed layout,
   * GCM tag verification failure); parameter type errors and key format errors are
   * still thrown.
   */
  safeMode?: boolean;
}

/**
 * SM9 混合加密。
 *
 * @param key 加密主公钥（64 字节 / SPKI PEM）或加密主私钥（32 字节 / PKCS#8 PEM）。
 * @param id 接收方标识。
 * @param message 明文（hex / Uint8Array；空消息传 `new Uint8Array(0)`）。
 * @param opts `iv` 可选，默认随机 12 字节。
 * @returns sealed hex（版本化，与 SM2 hybrid 同一布局）。
 *
 * SM9 hybrid encryption.
 *
 * @param key Encryption master public key (64 bytes / SPKI PEM) or encryption master
 *   private key (32 bytes / PKCS#8 PEM).
 * @param id Receiver identity.
 * @param message Plaintext (hex / `Uint8Array`; pass `new Uint8Array(0)` for an empty
 *   message).
 * @param opts Optional `iv`, 12 random bytes by default.
 * @returns Sealed hex (versioned, same layout as the SM2 hybrid format).
 */
export function hybridEncrypt(
  key: string | Uint8Array,
  id: string | Uint8Array,
  message: string | Uint8Array,
  opts: Sm9HybridEncryptOptions = {},
): string {
  const k = keyArg(key, 64, 'key');
  const idB = toBytes(id, 'id');
  const msg = toMessageBytes(message, 'message');
  const iv = resolveIv(opts.iv);

  // DEK 固定为 SM4-128 的 16 字节；封装方不需要 KGC 的加密主私钥。
  //
  // The DEK is fixed at 16 bytes for SM4-128; the encapsulating side does not need
  // the KGC's encryption master private key.
  const kem =
    k.kind === 'public'
      ? kemEncapsulateWithMasterPublic(k.bytes, idB, DEM_KEY_LEN)
      : kemEncrypt(k.bytes, idB, DEM_KEY_LEN);
  const enc = hexToBytes(kem.encapsulation, 'encapsulation');

  const { ct, tag } = encryptGCM(kem.key, iv, msg, enc);
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
 * SM9 混合解密。
 *
 * @param ke 加密主私钥（32 字节 / PKCS#8 PEM）。
 * @param id 接收方标识；必须与封装时一致。
 * @param sealed `hybridEncrypt` 的返回值。
 * @param opts `safeMode`：失败时返回 `null`。
 * @returns 明文 hex。
 *
 * SM9 hybrid decryption.
 *
 * @param ke Encryption master private key (32 bytes / PKCS#8 PEM).
 * @param id Receiver identity; must match the one used at encapsulation time.
 * @param sealed The value returned by `hybridEncrypt`.
 * @param opts `safeMode`: return `null` on failure.
 * @returns Plaintext as hex.
 */
export function hybridDecrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  sealed: string | Uint8Array,
  opts: Sm9HybridDecryptOptions & { safeMode: true },
): string | null;
export function hybridDecrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  sealed: string | Uint8Array,
  opts?: Sm9HybridDecryptOptions,
): string;
export function hybridDecrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  sealed: string | Uint8Array,
  opts: Sm9HybridDecryptOptions = {},
): string | null {
  try {
    const parts = decodeSealed(sealed);
    if (parts.klen !== DEM_KEY_LEN) {
      throw new InvalidCiphertextError(
        `sm9.hybridDecrypt: sealed.klen=${parts.klen}，当前版本只支持 ${DEM_KEY_LEN}`,
      );
    }
    if (parts.encapsulation.length !== 65) {
      throw new InvalidCiphertextError(
        `sm9.hybridDecrypt: encapsulation 必须是 65 字节，实际 ${parts.encapsulation.length}`,
      );
    }
    // KEM 只算 K；错误 id 不会在这里报错，由下面的 GCM tag 兜底。
    //
    // The KEM only computes K; a wrong id does not fail here — the GCM tag below
    // catches it.
    const key = kemDecrypt(ke, id, parts.encapsulation, parts.klen);
    return decryptGCM(key, parts.iv, parts.ct, parts.tag, { aad: parts.encapsulation });
  } catch (err) {
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

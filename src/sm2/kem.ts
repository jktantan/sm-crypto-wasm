/**
 * SM2 密钥封装（KEM）—— 用 SM2 公钥保护一把随机对称密钥。
 *
 * **注意：这不是国标定义的“SM2-KEM”。** GM/T 0003 只定义了 SM2 公钥加密，
 * 没有定义独立的 KEM 构造；本模块是业界约定俗成的做法：
 *
 *   key           = 宿主 CSPRNG 生成的 `klen` 字节对称密钥
 *   encapsulation = SM2 加密(key)（完整 C1C3C2 密文，自带 C3 完整性校验）
 *
 * 接收方用 `kemDecrypt` 解出同一把 key。它的安全性完全继承自 SM2 公钥加密：
 * - 每次封装都取新的随机数 `k`（由 `sm2.encrypt` 内部完成）；
 * - encapsulation 被篡改时 C3 校验失败，抛 `DecryptionError`；
 * - 错误私钥同样过不了 C3 校验，不会返回垃圾密钥。
 *
 * 若需要“公钥只保护短密钥、数据交给对称算法”的完整用法，直接用
 * `hybridEncrypt` / `hybridDecrypt`（本模块的 KEM + SM4-GCM 组装）。
 *
 * spec/plan 对应：`docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`
 * Task 1。
 *
 * SM2 key encapsulation (KEM) — protect a random symmetric key with an SM2 public key.
 *
 * **Note: this is not the “SM2-KEM” defined by a national standard.** GM/T 0003 only
 * defines SM2 public-key encryption and no standalone KEM construction; this module
 * follows the industry convention:
 *
 *   key           = klen-byte symmetric key from the host CSPRNG
 *   encapsulation = SM2 encrypt(key) (full C1C3C2 ciphertext with its own C3 check)
 *
 * The recipient recovers the same key with `kemDecrypt`. Its security derives entirely
 * from SM2 public-key encryption:
 * - every encapsulation draws a fresh random `k` (handled inside `sm2.encrypt`);
 * - a tampered encapsulation fails the C3 check and raises `DecryptionError`;
 * - a wrong private key also fails C3, so no garbage key is returned.
 *
 * For the complete “public key protects a short key, data goes to a symmetric cipher”
 * pattern, use `hybridEncrypt` / `hybridDecrypt` (this module's KEM plus SM4-GCM).
 *
 * Spec/plan: `docs/design/plans/2026-10-16-sm2-sm9-hybrid-encryption.md` Task 1.
 */

import { bytesToHex } from '../runtime/convert.js';
import { CiphertextError, DecryptionError } from '../runtime/errors.js';
import { randomBytes } from '../runtime/random.js';
import { decrypt, encrypt } from './index.js';

/**
 * KEM 封装结果。
 *
 * The result of a KEM encapsulation.
 */
export interface Sm2KemResult {
  /**
   * 会话密钥（hex，`2*klen` 个字符）。
   *
   * The session key as hex (`2*klen` characters).
   */
  key: string;
  /**
   * SM2 密文（C1C3C2 hex，长度 `97 + klen` 字节）。
   *
   * The SM2 ciphertext (C1C3C2 hex, `97 + klen` bytes long).
   */
  encapsulation: string;
}

/**
 * `kemDecrypt` 选项。
 *
 * Options for `kemDecrypt`.
 */
export interface Sm2KemDecryptOptions {
  /**
   * 解封装失败时返回 `null` 而不抛错。
   *
   * 只覆盖密文支错误（`CiphertextError`：密文结构错 / C3 校验失败）；
   * 参数类型错误（`TypeError` / `RangeError`）仍会抛出。
   *
   * Return `null` instead of throwing when decapsulation fails.
   *
   * Covers only ciphertext-branch errors (`CiphertextError`: bad ciphertext structure /
   * C3 check failure); argument type errors (`TypeError` / `RangeError`) still throw.
   */
  safeMode?: boolean;
}

/**
 * `klen` 必须是正整数，且不超过宿主 CSPRNG 单次取数上限（65536）。
 *
 * `klen` must be a positive integer no larger than the host CSPRNG's single-read cap
 * (65536).
 */
function requireKlen(klen: number): void {
  if (!Number.isInteger(klen) || klen <= 0 || klen > 65_536) {
    throw new RangeError(`sm2.kemEncrypt: klen 必须是 [1, 65536] 内的整数，实际 ${klen}`);
  }
}

/**
 * SM2 密钥封装：生成一把随机会话密钥，并用接收方公钥封装。
 *
 * @param publicKey 64 或 65 字节公钥（hex / Uint8Array / PEM）。
 * @param klen 会话密钥字节长度，默认 32。
 * @returns `{ key, encapsulation }`，均为 hex。
 *
 * SM2 key encapsulation: generate a random session key and encapsulate it to the
 * recipient's public key.
 *
 * @param publicKey A 64- or 65-byte public key (hex / Uint8Array / PEM).
 * @param klen Session-key length in bytes, 32 by default.
 * @returns `{ key, encapsulation }`, both hex.
 */
export function kemEncrypt(publicKey: string | Uint8Array, klen = 32): Sm2KemResult {
  requireKlen(klen);
  const key = randomBytes(klen);
  const encapsulation = encrypt(publicKey, key);
  return { key: bytesToHex(key), encapsulation };
}

/**
 * SM2 密钥解封装：从 encapsulation 恢复会话密钥。
 *
 * @param privateKey 32 字节私钥（hex / Uint8Array / PEM）。
 * @param encapsulation `kemEncrypt` 产出的 SM2 密文。
 * @param klen 会话密钥字节长度，默认 32；必须与封装时一致。
 * @returns 会话密钥 hex。
 * @throws {DecryptionError} C3 校验失败、私钥错误，或解出的长度与 `klen` 不符。
 *
 * SM2 key decapsulation: recover the session key from an encapsulation.
 *
 * @param privateKey The 32-byte private key (hex / Uint8Array / PEM).
 * @param encapsulation The SM2 ciphertext produced by `kemEncrypt`.
 * @param klen Session-key length in bytes, 32 by default; must match encapsulation.
 * @returns The session key in hex.
 * @throws {DecryptionError} When the C3 check fails, the private key is wrong, or the
 *   recovered length does not match `klen`.
 */
export function kemDecrypt(
  privateKey: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen: number,
  opts: Sm2KemDecryptOptions & { safeMode: true },
): string | null;
export function kemDecrypt(
  privateKey: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen?: number,
  opts?: Sm2KemDecryptOptions,
): string;
export function kemDecrypt(
  privateKey: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen = 32,
  opts: Sm2KemDecryptOptions = {},
): string | null {
  requireKlen(klen);
  try {
    const key = decrypt(privateKey, encapsulation);
    if (key.length !== klen * 2) {
      // C3 已通过，说明私钥正确；长度不符通常是调用方把 klen 传错了。
      //
      // C3 already passed, so the private key is correct; a length mismatch usually
      // means the caller passed the wrong klen.
      throw new DecryptionError(
        `sm2.kemDecrypt: 解出的密钥长度为 ${key.length / 2} 字节，与 klen=${klen} 不符`,
      );
    }
    return key;
  } catch (err) {
    if (opts.safeMode && err instanceof CiphertextError) return null;
    throw err;
  }
}

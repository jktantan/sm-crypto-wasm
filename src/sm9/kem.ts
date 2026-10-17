/**
 * SM9 密钥封装（KEM，GM/T 0044.4）。
 *
 * 两种封装入口：
 * - `kemEncrypt(ke, id, klen, r?)`：用加密主私钥派生 Ppub-e（既有已发布接口）。
 * - `kemEncapsulateWithMasterPublic(pub, id, klen, r?)`：直接用加密主公钥
 *   `[ke]P1`（发送方的典型形态；供 `hybrid.ts` 使用，不改变既有 `kemEncrypt`）。
 *
 * 解封装只有 `kemDecrypt(ke, id, encapsulation, klen)`：必须持有加密主私钥。
 *
 * spec/plan 对应：`docs/superpowers/plans/2026-10-16-sm2-sm9-hybrid-encryption.md`
 * Task 4。
 */

import { DecryptionError, InvalidKeyError } from '../runtime/errors.js';
import { getModule } from './core.js';
import {
  masterPrivateBytes,
  masterPublicBytes,
  putBytes,
  randomRHex,
  readHex,
  requireLen,
  toBytes,
} from './input.js';

/** KEM 封装结果。 */
export interface KemResult {
  /** 会话密钥 K（hex，长度为 `2*klen`）。 */
  key: string;
  /** 封装点 C1（65 字节未压缩 G1 点 hex：`04 || x || y`）。 */
  encapsulation: string;
}

function requireKlen(klen: number): void {
  if (!Number.isInteger(klen) || klen <= 0) throw new RangeError('sm9: klen 必须为正整数');
}

/**
 * SM9 密钥封装（GM/T 0044.4）：用接收方 id 与其加密主公钥 [ke]P1 封装一个会话密钥。
 *
 * @param ke   32 字节加密主私钥 hex（用于派生主公钥 [ke]P1）
 * @param id   接收方标识
 * @param klen 会话密钥字节长度（默认 32）
 * @param r    32 字节随机数 hex（可选；不传则由宿主 CSPRNG 提供）
 * @returns    `{ key, encapsulation }`
 */
export function kemEncrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  klen = 32,
  r?: string | Uint8Array,
): KemResult {
  const keB = masterPrivateBytes(ke, 'ke');
  const idB = toBytes(id, 'id');
  const rB = r !== undefined ? toBytes(r, 'r') : toBytes(randomRHex(), 'r');
  requireLen(rB, 32, 'r');
  requireKlen(klen);

  const { exports } = getModule();
  const keP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const rP = exports.alloc(32);
  const c1P = exports.alloc(65);
  const kP = exports.alloc(klen);
  try {
    putBytes(keB, keP);
    putBytes(idB, idP);
    putBytes(rB, rP);
    const rc = exports.sm9KemEncryptOut(keP, idP, idB.length, rP, klen, c1P, kP);
    if (rc !== 1) throw new Error('sm9: kemEncrypt 失败（K 全 0，需换随机数重试）');
    return { key: readHex(kP, klen), encapsulation: readHex(c1P, 65) };
  } finally {
    exports.freeAll();
  }
}

/**
 * 用加密主公钥封装的内部入口（`hybridEncrypt` 使用）。
 *
 * 与 `kemEncrypt` 的区别只在密钥参数：这里不需要 KGC 的加密主私钥。
 *
 * @param masterPublicKey 64 字节加密主公钥 `[ke]P1`（点字节 / SPKI 主公钥 PEM）。
 * @param id 接收方标识。
 * @param klen 会话密钥字节长度（默认 32）。
 * @param r 32 字节随机数 hex（可选）。
 */
export function kemEncapsulateWithMasterPublic(
  masterPublicKey: string | Uint8Array,
  id: string | Uint8Array,
  klen = 32,
  r?: string | Uint8Array,
): KemResult {
  const pub = masterPublicBytes(masterPublicKey, 'masterPublicKey');
  if (pub.length !== 64) {
    throw new InvalidKeyError(`sm9: masterPublicKey 必须是 64 字节加密主公钥，实际 ${pub.length}`);
  }
  const idB = toBytes(id, 'id');
  const rB = r !== undefined ? toBytes(r, 'r') : toBytes(randomRHex(), 'r');
  requireLen(rB, 32, 'r');
  requireKlen(klen);

  const { exports } = getModule();
  const pubP = exports.alloc(64);
  const idP = exports.alloc(idB.length);
  const rP = exports.alloc(32);
  const c1P = exports.alloc(65);
  const kP = exports.alloc(klen);
  try {
    putBytes(pub, pubP);
    putBytes(idB, idP);
    putBytes(rB, rP);
    const rc = exports.sm9KemEncryptPubOut(pubP, idP, idB.length, rP, klen, c1P, kP);
    if (rc !== 1) throw new Error('sm9: kemEncapsulate 失败（K 全 0，需换随机数重试）');
    return { key: readHex(kP, klen), encapsulation: readHex(c1P, 65) };
  } finally {
    exports.freeAll();
  }
}

/**
 * SM9 密钥解封装：用本端加密主私钥 ke 与 id 从封装点 C1 恢复会话密钥。
 *
 * @param encapsulation 65 字节封装点 C1 hex
 * @returns 会话密钥 hex
 */
export function kemDecrypt(
  ke: string | Uint8Array,
  id: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen = 32,
): string {
  const keB = masterPrivateBytes(ke, 'ke');
  const idB = toBytes(id, 'id');
  const c1B = toBytes(encapsulation, 'encapsulation');
  if (c1B.length !== 65)
    throw new RangeError(`sm9: encapsulation 必须是 65 字节，实际 ${c1B.length}`);
  requireKlen(klen);

  const { exports } = getModule();
  const keP = exports.alloc(32);
  const idP = exports.alloc(idB.length);
  const c1P = exports.alloc(65);
  const kP = exports.alloc(klen);
  try {
    putBytes(keB, keP);
    putBytes(idB, idP);
    putBytes(c1B, c1P);
    const rc = exports.sm9KemDecryptOut(keP, idP, idB.length, c1P, klen, kP);
    if (rc !== 1) throw new DecryptionError('sm9: kemDecrypt 失败（封装非法 / K 全 0）');
    return readHex(kP, klen);
  } finally {
    exports.freeAll();
  }
}

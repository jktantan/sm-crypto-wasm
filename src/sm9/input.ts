/**
 * SM9 输入归一化与密钥参数校验。
 *
 * 从 `index.ts` 拆出，供 `kem.ts` / `hybrid.ts` 复用，避免循环依赖。
 *
 * SM9 input normalisation and key-parameter validation.
 *
 * Split out of `index.ts` so `kem.ts` / `hybrid.ts` can reuse it without circular
 * imports.
 */

import { parseSm9PrivateKeyPem, parseSm9PublicKeyPem } from '../pem/sm9.js';
import { bytesToHex, hexToBytes } from '../runtime/convert.js';
import { InvalidCiphertextError, InvalidKeyError } from '../runtime/errors.js';
import { randomScalarBelow } from '../runtime/random.js';
import { mem, N } from './core.js';

/**
 * 通用输入归一化：Uint8Array 拷贝、hex 解码、其它按 UTF-8。
 *
 * **刻意不做 PEM 嗅探** —— PEM 只可能出现在密钥参数上，由 `masterPrivateBytes`
 * 显式处理；这样 id / msg 里出现 `-----BEGIN` 也不会被误吞。
 *
 * Generic input normalisation: copy `Uint8Array`, decode hex, otherwise UTF-8.
 *
 * **PEM sniffing is deliberately omitted** — PEM can only ever appear in key
 * parameters, where `masterPrivateBytes` handles it explicitly; that way an id or
 * msg containing `-----BEGIN` is never swallowed.
 */
export function toBytes(input: string | Uint8Array, label: string): Uint8Array {
  if (input instanceof Uint8Array) return new Uint8Array(input);
  if (typeof input !== 'string') throw new TypeError(`sm9: ${label} 必须是字符串或 Uint8Array`);
  if (input.startsWith('0x') || /^[0-9a-fA-F]+$/.test(input)) {
    const s = input.startsWith('0x') ? input.slice(2) : input;
    if (s.length % 2 !== 0) throw new TypeError(`sm9: ${label} hex 长度必须为偶数`);
    return hexToBytes(s, label);
  }
  return new TextEncoder().encode(input);
}

/**
 * 主私钥参数归一化：接受 32 字节（hex / Uint8Array）或 PKCS#8 私钥 PEM
 * （spec §12.1 Q3，算法 OID `1.2.156.10197.1.100`）。
 *
 * Normalises a master private key argument: accepts 32 bytes (hex / `Uint8Array`)
 * or a PKCS#8 private-key PEM (spec §12.1 Q3, algorithm OID `1.2.156.10197.1.100`).
 */
export function masterPrivateBytes(input: string | Uint8Array, label: string): Uint8Array {
  let bytes: Uint8Array;
  if (typeof input === 'string' && input.includes('-----BEGIN')) {
    const parsed = parseSm9PrivateKeyPem(input);
    if (parsed.length !== 32) {
      throw new InvalidKeyError(`sm9: ${label} 作为 PEM 主私钥应为 32 字节，实际 ${parsed.length}`);
    }
    bytes = parsed;
  } else {
    const b = toBytes(input, label);
    if (b.length !== 32) {
      throw new InvalidKeyError(`sm9: ${label} 必须是 32 字节主私钥，实际 ${b.length}`);
    }
    bytes = b;
  }
  // 标量范围：SM9（GM/T 0044）要求 1 ≤ k ≤ n−1。
  // 越界值不会崩，但 wasm 侧的 addModN → modAdd 只做一次条件减、要求输入已
  // 约化（h1 + k < 2n），k ≥ n 时 k + h1 可能 ≥ 2n 而静默产出错值，故在此显式拒绝。
  //
  // Scalar range: SM9 (GM/T 0044) requires 1 ≤ k ≤ n−1. An out-of-range value does
  // not crash, but the wasm-side addModN → modAdd performs only a single
  // conditional subtraction and requires already-reduced inputs (h1 + k < 2n); with
  // k ≥ n the sum k + h1 can reach 2n and silently produce a wrong value, so it is
  // rejected explicitly here.
  const k = BigInt(`0x${bytesToHex(bytes)}`);
  if (k < 1n || k >= N) {
    throw new InvalidKeyError(`sm9: ${label} 必须在 [1, n−1] 范围内（SM9 主私钥标量）`);
  }
  return bytes;
}

/**
 * 主公钥参数归一化：64（加密 G1）或 128（签名 G2）字节点，或 SPKI 主公钥 PEM。
 *
 * Normalises a master public key argument: 64 bytes (G1, encryption) or 128 bytes
 * (G2, signing), or an SPKI master public key PEM.
 */
export function masterPublicBytes(input: string | Uint8Array, label: string): Uint8Array {
  if (typeof input === 'string' && input.includes('-----BEGIN')) {
    const pub = parseSm9PublicKeyPem(input);
    if (pub.length !== 64 && pub.length !== 128) {
      throw new InvalidKeyError(
        `sm9: ${label} 作为 PEM 主公钥必须是 64 或 128 字节，实际 ${pub.length}`,
      );
    }
    return pub;
  }
  const b = toBytes(input, label);
  if (b.length !== 64 && b.length !== 128) {
    throw new InvalidKeyError(
      `sm9: ${label} 必须是 64（加密）或 128（签名）字节主公钥，实际 ${b.length}`,
    );
  }
  return b;
}

/**
 * `verify` / `encrypt` 第一参数的解析结果。
 *
 * Parsed form of the first argument of `verify` / `encrypt`.
 */
export type KeyArg = { kind: 'secret'; bytes: Uint8Array } | { kind: 'public'; bytes: Uint8Array };

/**
 * 解析 `verify` / `encrypt` 的密钥参数：主私钥（32 字节 / PKCS#8 私钥 PEM）
 * 或主公钥（`publicLen` 字节点 / SPKI 公钥 PEM）。
 *
 * 两者的长度区间不重叠（主私钥恒为 32 字节），因此按长度即可判别。
 *
 * Parses the key argument of `verify` / `encrypt`: a master private key (32 bytes /
 * PKCS#8 private-key PEM) or a master public key (`publicLen` bytes / SPKI public-key
 * PEM).
 *
 * The two length ranges do not overlap (a master private key is always 32 bytes),
 * so the length alone identifies which one it is.
 */
export function keyArg(input: string | Uint8Array, publicLen: 64 | 128, label: string): KeyArg {
  if (typeof input === 'string' && input.includes('-----BEGIN')) {
    if (input.includes('BEGIN PUBLIC KEY')) {
      const pub = parseSm9PublicKeyPem(input);
      if (pub.length !== publicLen) {
        throw new InvalidKeyError(
          `sm9: ${label} 作为 PEM 主公钥应为 ${publicLen} 字节，实际 ${pub.length}`,
        );
      }
      return { kind: 'public', bytes: pub };
    }
    return { kind: 'secret', bytes: masterPrivateBytes(input, label) };
  }
  const b = toBytes(input, label);
  if (b.length === 32) return { kind: 'secret', bytes: b };
  if (b.length === publicLen) return { kind: 'public', bytes: b };
  throw new InvalidKeyError(
    `sm9: ${label} 必须是 32 字节主私钥或 ${publicLen} 字节主公钥，实际 ${b.length}`,
  );
}

/**
 * 校验字节长度。默认按**密钥支**（`InvalidKeyError`）抛错 —— SM9 各入口的参数绝大多数
 * 是主私钥 / 标量；密文、签名、协议消息的调用点显式传 `'cipher'`。
 *
 * Validates a byte length. By default errors come from the **key branch**
 * (`InvalidKeyError`) — almost every SM9 entry-point parameter is a master private
 * key / scalar; call sites handling ciphertexts, signatures, or protocol messages
 * pass `'cipher'` explicitly.
 */
export function requireLen(
  b: Uint8Array,
  n: number,
  label: string,
  kind: 'key' | 'cipher' = 'key',
): void {
  if (b.length === n) return;
  const msg = `sm9: ${label} 必须是 ${n} 字节，实际 ${b.length}`;
  if (kind === 'cipher') throw new InvalidCiphertextError(msg);
  throw new InvalidKeyError(msg);
}

// 把 hex 写入 WASM 线性内存的指定地址。
//
// Writes hex bytes to the given WASM linear-memory address.
export function putHex(hex: string, ptr: number): void {
  mem().set(hexToBytes(hex), ptr);
}

// 把 Uint8Array 写入 WASM 线性内存的指定地址。
//
// Writes a Uint8Array to the given WASM linear-memory address.
export function putBytes(b: Uint8Array, ptr: number): void {
  mem().set(b, ptr);
}

// 从 WASM 线性内存读取 len 字节并编码为小写 hex。
//
// Reads len bytes from WASM memory and returns lowercase hex.
export function readHex(ptr: number, len: number): string {
  return bytesToHex(mem().subarray(ptr, ptr + len));
}

// 生成 [1, n-1] 的随机标量并编码为 64 个 hex 字符（256 位；SM9 签名/加密随机数 r）。
//
// Generates a random scalar in [1, n-1] as 64 hex chars (SM9 nonce r).
export function randomRHex(): string {
  return randomScalarBelow(N).toString(16).padStart(64, '0');
}

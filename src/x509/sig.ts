/**
 * SM2 签名值的两种编码转换：
 * - 裸格式：64 字节 `r ‖ s`（`sm2.sign` 的返回）；
 * - DER 格式：`SEQUENCE { INTEGER r, INTEGER s }`（X.509 / CMS 要求）。
 *
 * 红线 #2：签发给外部系统的证书/CMS 必须是 DER 格式；直接塞裸 `r‖s`
 * 会产出非标准数据。
 *
 * Conversion between the two encodings of an SM2 signature value:
 * - raw form: 64 bytes `r ‖ s` (what `sm2.sign` returns);
 * - DER form: `SEQUENCE { INTEGER r, INTEGER s }` (what X.509 / CMS requires).
 *
 * Red line #2: certificates and CMS data handed to other systems must use the
 * DER form; stuffing raw `r‖s` in produces non-standard output.
 */

import { Asn1Error, integer, parseDer, readInteger, seq } from '../asn1/index.js';
import { CertificateError } from './errors.js';

/**
 * DER `SEQUENCE { r, s }` → 64 字节 `r ‖ s`。
 *
 * @throws CertificateError 结构非法、r/s 为负或超过 32 字节。
 *
 * DER `SEQUENCE { r, s }` to 64 bytes `r ‖ s`.
 *
 * @throws CertificateError Malformed structure, or r/s negative or wider than 32 bytes.
 */
export function derSignatureToRaw(der: Uint8Array, what = 'signature'): Uint8Array {
  let r: bigint;
  let s: bigint;
  try {
    const node = parseDer(der);
    if (node.cls !== 0 || node.tag !== 16 || !node.children || node.children.length !== 2) {
      throw new CertificateError(`${what}: expected SEQUENCE { r, s }`);
    }
    r = readInteger(node.children[0] as never, what);
    s = readInteger(node.children[1] as never, what);
  } catch (err) {
    if (err instanceof CertificateError) throw err;
    throw new CertificateError(`${what}: invalid DER signature`, { cause: err });
  }
  if (r < 0n || s < 0n) throw new CertificateError(`${what}: negative r/s`);
  if (r >= 1n << 256n || s >= 1n << 256n) throw new CertificateError(`${what}: r/s too large`);
  const out = new Uint8Array(64);
  out.set(bigintToBytes(r, 32), 0);
  out.set(bigintToBytes(s, 32), 32);
  return out;
}

/**
 * 64 字节 `r ‖ s` → DER `SEQUENCE { r, s }`。
 *
 * @throws CertificateError 长度不是 64 字节。
 *
 * 64 bytes `r ‖ s` to DER `SEQUENCE { r, s }`.
 *
 * @throws CertificateError The input is not exactly 64 bytes.
 */
export function rawSignatureToDer(raw: Uint8Array, what = 'signature'): Uint8Array {
  if (raw.length !== 64) throw new CertificateError(`${what}: expected 64-byte r||s`);
  const r = bytesToBigint(raw.subarray(0, 32));
  const s = bytesToBigint(raw.subarray(32));
  if (r === 0n || s === 0n) throw new CertificateError(`${what}: r/s must be non-zero`);
  try {
    return seq([integer(r), integer(s)]).raw;
  } catch (err) {
    throw new CertificateError(`${what}: failed to encode DER signature`, { cause: err });
  }
}

/**
 * 把 bigint 写成定长大端字节。
 *
 * Writes a bigint as fixed-length big-endian bytes.
 */
function bigintToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * 把大端字节读成 bigint。
 *
 * Reads big-endian bytes as a bigint.
 */
function bytesToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v = (v << 8n) | BigInt(bytes[i] as number);
  return v;
}

// Asn1Error 仅用于类型导入的副作用检查；保留引用避免 tree-shaker 误判。
//
// Asn1Error is kept only for the type-import side-effect check; holding a
// reference keeps the tree-shaker from misjudging it.
void Asn1Error;

/**
 * 纯 JS SHA-1（仅用于 SubjectKeyIdentifier 的 OpenSSL 兼容选项）。
 *
 * 与 `sha256.ts` 同样的理由：X.509 API 是同步的，不能用 `crypto.subtle`；
 * `node:crypto` 会破坏浏览器构建。SHA-1 在这里只作为 SKI 的哈希选项
 * （`subjectKeyIdentifier: { hash: 'sha1' }`），不用于任何安全判断。
 *
 * A pure-JS SHA-1, used only for the OpenSSL-compatible SubjectKeyIdentifier option.
 *
 * Same reason as `sha256.ts`: the X.509 API is synchronous, so `crypto.subtle`
 * is unavailable, and `node:crypto` would break the browser build. SHA-1 is used
 * here purely as a hash choice for the SKI
 * (`subjectKeyIdentifier: { hash: 'sha1' }`) and never for a security decision.
 */

/**
 * SHA-1 摘要（小写 hex）。
 *
 * SHA-1 digest as lowercase hex.
 */
export function sha1Hex(input: Uint8Array): string {
  const length = input.length;
  const paddedLength = Math.ceil((length + 9) / 64) * 64;
  const buffer = new Uint8Array(paddedLength);
  buffer.set(input);
  buffer[length] = 0x80;
  const view = new DataView(buffer.buffer);
  view.setUint32(paddedLength - 8, Math.floor(length / 0x20000000));
  view.setUint32(paddedLength - 4, (length * 8) >>> 0);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 80; i++) {
      const x =
        (w[i - 3] as number) ^ (w[i - 8] as number) ^ (w[i - 14] as number) ^ (w[i - 16] as number);
      w[i] = rotl(x, 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    // 4 个 20 轮阶段：Ch / Parity / Maj / Parity（FIPS 180-4 §6.1.3）。
    //
    // Four 20-round phases (FIPS 180-4 §6.1.3).
    for (let i = 0; i < 80; i++) {
      let f: number;
      let k: number;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const temp = (rotl(a, 5) + f + e + k + (w[i] as number)) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  return [h0, h1, h2, h3, h4].map((v) => v.toString(16).padStart(8, '0')).join('');
}

// 32-bit 循环左移。
//
// 32-bit rotate left.
function rotl(value: number, shift: number): number {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

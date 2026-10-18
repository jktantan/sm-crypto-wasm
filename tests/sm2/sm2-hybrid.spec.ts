import { beforeAll, describe, expect, it } from 'vitest';
import { DecryptionError, hexToBytes, InvalidCiphertextError } from '@/runtime';
import * as sm2 from '@/sm2';
import * as sm4 from '@/sm4';

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const D2 = '6fcba2e4c3ab5a4d0b5c1e8f7a9d3b2c4e5f60718293a4b5c6d7e8f90a1b2c3d';
const IV = '000102030405060708090a0b';

function fullCipherLength(sealed: string): number {
  const obj = sm2.sealedToObject(sealed);
  return 4 + obj.encapsulation.length / 2 + 12 + 16;
}

describe('SM2 hybrid encryption (KEM + SM4-GCM)', () => {
  let pub: string;

  beforeAll(async () => {
    await sm2.ensureLoaded();
    await sm4.ensureLoaded();
    pub = sm2.getPublicKey(D);
  });

  it('round-trips empty, short and large messages', () => {
    const messages = [
      new Uint8Array(0),
      new Uint8Array([0x42]),
      hexToBytes('00112233445566778899aabbccddeeff'),
      new Uint8Array(10 * 1024).fill(0x5a),
    ];
    for (const msg of messages) {
      const sealed = sm2.hybridEncrypt(pub, msg);
      const pt = sm2.hybridDecrypt(D, sealed);
      expect(pt).toBe(Buffer.from(msg).toString('hex'));
      expect(pt.length / 2).toBe(msg.length);
    }
  });

  it('uses the unified hex message semantics', () => {
    const sealed = sm2.hybridEncrypt(pub, '616263');
    expect(sm2.hybridDecrypt(D, sealed)).toBe('616263');
    // 非 hex 字符串不再按 base64 / UTF-8 猜测。
    expect(() => sm2.hybridEncrypt(pub, 'hello')).toThrow(TypeError);
  });

  it('produces a different sealed value on every call', () => {
    const msg = hexToBytes('aabbcc');
    const a = sm2.hybridEncrypt(pub, msg);
    const b = sm2.hybridEncrypt(pub, msg);
    expect(a).not.toBe(b);
    // DEK 与 IV 都不同：两段 KEM 封装也应不同。
    expect(sm2.sealedToObject(a).encapsulation).not.toBe(sm2.sealedToObject(b).encapsulation);
    expect(sm2.sealedToObject(a).iv).not.toBe(sm2.sealedToObject(b).iv);
  });

  it('accepts an explicit 12-byte IV', () => {
    const sealed = sm2.hybridEncrypt(pub, '00ff', { iv: IV });
    expect(sm2.sealedToObject(sealed).iv).toBe(IV);
    expect(sm2.hybridDecrypt(D, sealed)).toBe('00ff');
  });

  it('rejects an explicitly supplied IV of the wrong length', () => {
    expect(() => sm2.hybridEncrypt(pub, '00', { iv: '0001' })).toThrow(RangeError);
  });

  it('rejects a tampered ciphertext, tag or encapsulation', () => {
    const sealed = sm2.hybridEncrypt(pub, 'deadbeef');
    const obj = sm2.sealedToObject(sealed);

    const flip = (hex: string): string => {
      const last = hex.slice(-2);
      const next =
        last === 'ff' ? '00' : (Number.parseInt(last, 16) + 1).toString(16).padStart(2, '0');
      return hex.slice(0, -2) + next;
    };

    const tampered = [
      sm2.sealedFromObject({ ...obj, ct: flip(obj.ct) }),
      sm2.sealedFromObject({ ...obj, tag: flip(obj.tag) }),
      sm2.sealedFromObject({ ...obj, encapsulation: flip(obj.encapsulation) }),
    ];
    for (const bad of tampered) {
      expect(() => sm2.hybridDecrypt(D, bad)).toThrow(DecryptionError);
    }
  });

  it('rejects the wrong private key instead of returning garbage', () => {
    const sealed = sm2.hybridEncrypt(pub, '010203');
    expect(() => sm2.hybridDecrypt(D2, sealed)).toThrow(DecryptionError);
  });

  it('safeMode returns null for ciphertext-side failures', () => {
    const sealed = sm2.hybridEncrypt(pub, '010203');
    const obj = sm2.sealedToObject(sealed);
    const bad = sm2.sealedFromObject({
      ...obj,
      tag: `${obj.tag.slice(0, -2)}${obj.tag.endsWith('ff') ? '00' : 'ff'}`,
    });
    expect(sm2.hybridDecrypt(D, sealed, { safeMode: true })).toBe('010203');
    expect(sm2.hybridDecrypt(D, bad, { safeMode: true })).toBeNull();
  });

  it('rejects malformed sealed values with a ciphertext-side error', () => {
    const sealed = sm2.hybridEncrypt(pub, 'aabbccdd');
    const raw = hexToBytes(sealed);

    const cases: string[] = [
      '',
      '00',
      // 未知版本
      `02${sealed.slice(2)}`,
      // 长度字段说谎：encapLen 改成 0xffff
      `${sealed.slice(0, 4)}ffff${sealed.slice(8)}`,
      // 截断到 tag 之前
      Buffer.from(raw.slice(0, fullCipherLength(sealed) - 1)).toString('hex'),
    ];
    for (const bad of cases) {
      expect(() => sm2.hybridDecrypt(D, bad)).toThrow(InvalidCiphertextError);
    }

    // 长度字段合法、但 encapsulation 长度与 klen 不符（113 = 65 + 32 + 16）时也必须拒绝。
    const obj = sm2.sealedToObject(sealed);
    const badEncap = sm2.sealedFromObject({
      ...obj,
      encapsulation: obj.encapsulation.slice(0, 200),
    });
    expect(() => sm2.hybridDecrypt(D, badEncap)).toThrow(InvalidCiphertextError);
    expect(sm2.hybridDecrypt(D, badEncap, { safeMode: true })).toBeNull();
  });

  it('interoperates with a manual KEM + SM4-GCM assembly', () => {
    const msg = hexToBytes('0102030405');
    const { key, encapsulation } = sm2.kemEncrypt(pub, 16);
    const { ct, tag } = sm4.encryptGCM(key, IV, msg, hexToBytes(encapsulation));
    const sealed = sm2.sealedFromObject({
      v: 1,
      klen: 16,
      encapsulation,
      iv: IV,
      tag,
      ct,
    });
    expect(sm2.hybridDecrypt(D, sealed)).toBe('0102030405');
  });

  it('exposes the sealed object form symmetrically', () => {
    const sealed = sm2.hybridEncrypt(pub, '00ff00ff', { iv: IV });
    const obj = sm2.sealedToObject(sealed);
    expect(obj.v).toBe(1);
    expect(obj.klen).toBe(16);
    expect(obj.iv).toBe(IV);
    expect(obj.tag).toHaveLength(32);
    expect(sm2.sealedFromObject(obj)).toBe(sealed);
  });
});

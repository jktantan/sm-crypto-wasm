import { beforeAll, describe, expect, it } from 'vitest';
import { DecryptionError, hexToBytes, InvalidCiphertextError } from '@/runtime';
import * as sm4 from '@/sm4';
import * as sm9 from '@/sm9';

/** 固定加密主私钥（合法标量：< n）。 */
const KE = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
/** 另一把合法加密主私钥，用于错误密钥用例。 */
const KE2 = 'a0b0c0d'.padStart(64, '0');
const ID = 'Alice';
const IV = '000102030405060708090a0b';

function fullCipherLength(sealed: string): number {
  const obj = sm9.sealedToObject(sealed);
  return 4 + obj.encapsulation.length / 2 + 12 + 16;
}

describe('SM9 hybrid encryption (KEM + SM4-GCM)', () => {
  let pub: string;

  beforeAll(async () => {
    await sm9.ensureLoaded();
    await sm4.ensureLoaded();
    pub = sm9.getEncPublicKey(KE);
  }, 60_000);

  it('round-trips with a master public key and with a master private key', () => {
    const msg = '616263';
    const viaPublic = sm9.hybridEncrypt(pub, ID, msg);
    const viaPrivate = sm9.hybridEncrypt(KE, ID, msg);
    expect(sm9.hybridDecrypt(KE, ID, viaPublic)).toBe(msg);
    expect(sm9.hybridDecrypt(KE, ID, viaPrivate)).toBe(msg);
  }, 120_000);

  it('round-trips empty and larger messages', () => {
    for (const msg of [new Uint8Array(0), new Uint8Array([0x42]), new Uint8Array(1024).fill(7)]) {
      const sealed = sm9.hybridEncrypt(pub, ID, msg);
      expect(sm9.hybridDecrypt(KE, ID, sealed)).toBe(Buffer.from(msg).toString('hex'));
    }
  }, 120_000);

  it('produces different sealed values on every call', () => {
    const a = sm9.hybridEncrypt(pub, ID, 'aabbcc');
    const b = sm9.hybridEncrypt(pub, ID, 'aabbcc');
    expect(a).not.toBe(b);
    expect(sm9.sealedToObject(a).encapsulation).not.toBe(sm9.sealedToObject(b).encapsulation);
  }, 120_000);

  it('a different identity cannot open the ciphertext', () => {
    const sealed = sm9.hybridEncrypt(pub, ID, 'deadbeef');
    expect(() => sm9.hybridDecrypt(KE, 'Bob', sealed)).toThrow(DecryptionError);
  }, 120_000);

  it('the wrong master private key cannot open the ciphertext', () => {
    const sealed = sm9.hybridEncrypt(pub, ID, 'deadbeef');
    expect(() => sm9.hybridDecrypt(KE2, ID, sealed)).toThrow(DecryptionError);
  }, 120_000);

  it('rejects a tampered ciphertext, tag or encapsulation', () => {
    const sealed = sm9.hybridEncrypt(pub, ID, 'deadbeef');
    const obj = sm9.sealedToObject(sealed);
    const flip = (hex: string): string => {
      const last = hex.slice(-2);
      const next =
        last === 'ff' ? '00' : (Number.parseInt(last, 16) + 1).toString(16).padStart(2, '0');
      return hex.slice(0, -2) + next;
    };
    const tampered = [
      sm9.sealedFromObject({ ...obj, ct: flip(obj.ct) }),
      sm9.sealedFromObject({ ...obj, tag: flip(obj.tag) }),
      sm9.sealedFromObject({ ...obj, encapsulation: flip(obj.encapsulation) }),
    ];
    for (const bad of tampered) {
      expect(() => sm9.hybridDecrypt(KE, ID, bad)).toThrow(DecryptionError);
    }
  }, 120_000);

  it('safeMode returns null for ciphertext-side failures', () => {
    const sealed = sm9.hybridEncrypt(pub, ID, '010203');
    const obj = sm9.sealedToObject(sealed);
    const bad = sm9.sealedFromObject({
      ...obj,
      tag: `${obj.tag.slice(0, -2)}${obj.tag.endsWith('ff') ? '00' : 'ff'}`,
    });
    expect(sm9.hybridDecrypt(KE, ID, sealed, { safeMode: true })).toBe('010203');
    expect(sm9.hybridDecrypt(KE, ID, bad, { safeMode: true })).toBeNull();
  }, 120_000);

  it('rejects malformed sealed values with a ciphertext-side error', () => {
    const sealed = sm9.hybridEncrypt(pub, ID, 'aabbccdd');
    const raw = hexToBytes(sealed);
    const cases = [
      '',
      '00',
      `02${sealed.slice(2)}`,
      `${sealed.slice(0, 4)}ffff${sealed.slice(8)}`,
      Buffer.from(raw.slice(0, fullCipherLength(sealed) - 1)).toString('hex'),
    ];
    for (const bad of cases) {
      expect(() => sm9.hybridDecrypt(KE, ID, bad)).toThrow(InvalidCiphertextError);
    }

    // 长度字段合法、但 encapsulation 不是 65 字节时也必须拒绝。
    const obj = sm9.sealedToObject(sealed);
    const badEncap = sm9.sealedFromObject({
      ...obj,
      encapsulation: obj.encapsulation.slice(0, 128),
    });
    expect(() => sm9.hybridDecrypt(KE, ID, badEncap)).toThrow(InvalidCiphertextError);
    expect(sm9.hybridDecrypt(KE, ID, badEncap, { safeMode: true })).toBeNull();
  }, 120_000);

  it('interoperates with a manual KEM + SM4-GCM assembly', () => {
    const msg = hexToBytes('0102030405');
    const { key, encapsulation } = sm9.kemEncrypt(KE, ID, 16);
    const { ct, tag } = sm4.encryptGCM(key, IV, msg, hexToBytes(encapsulation));
    const sealed = sm9.sealedFromObject({
      v: 1,
      klen: 16,
      encapsulation,
      iv: IV,
      tag,
      ct,
    });
    expect(sm9.hybridDecrypt(KE, ID, sealed)).toBe('0102030405');
  }, 120_000);

  it('uses the unified hex message semantics', () => {
    const sealed = sm9.hybridEncrypt(pub, ID, '616263');
    expect(sm9.hybridDecrypt(KE, ID, sealed)).toBe('616263');
    expect(() => sm9.hybridEncrypt(pub, ID, 'hello')).toThrow(TypeError);
  }, 120_000);
});

import { beforeAll, describe, expect, it } from 'vitest';
import { DecryptionError } from '@/runtime';
import * as sm2 from '@/sm2';

/**
 * SM2 KEM：用 SM2 公钥加密一把随机会话密钥。
 *
 * 注：SM2 没有国标定义的独立 KEM 构造，这里是约定俗成的“加密随机密钥”。
 */
const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const D2 = '6fcba2e4c3ab5a4d0b5c1e8f7a9d3b2c4e5f60718293a4b5c6d7e8f90a1b2c3d';

function flipLastByte(hex: string): string {
  const last = hex.slice(-2);
  const next = last === 'ff' ? '00' : (Number.parseInt(last, 16) + 1).toString(16).padStart(2, '0');
  return hex.slice(0, -2) + next;
}

describe('SM2 KEM', () => {
  let pub: string;

  beforeAll(async () => {
    await sm2.ensureLoaded();
    pub = sm2.getPublicKey(D);
  });

  it('encapsulate → decapsulate yields the same key', () => {
    for (const klen of [16, 32]) {
      const { key, encapsulation } = sm2.kemEncrypt(pub, klen);
      expect(key).toHaveLength(klen * 2);
      expect(encapsulation).toHaveLength((97 + klen) * 2);
      expect(sm2.kemDecrypt(D, encapsulation, klen)).toBe(key);
    }
  });

  it('two encapsulations produce different keys and ciphertexts', () => {
    const a = sm2.kemEncrypt(pub, 16);
    const b = sm2.kemEncrypt(pub, 16);
    expect(a.key).not.toBe(b.key);
    expect(a.encapsulation).not.toBe(b.encapsulation);
  });

  it('a tampered encapsulation fails C3 verification', () => {
    const { encapsulation } = sm2.kemEncrypt(pub, 16);
    const bad = flipLastByte(encapsulation);
    expect(() => sm2.kemDecrypt(D, bad, 16)).toThrow(DecryptionError);
  });

  it('the wrong private key fails instead of returning garbage', () => {
    const { encapsulation } = sm2.kemEncrypt(pub, 16);
    expect(() => sm2.kemDecrypt(D2, encapsulation, 16)).toThrow(DecryptionError);
  });

  it('a mismatched klen is rejected', () => {
    const { encapsulation } = sm2.kemEncrypt(pub, 16);
    expect(() => sm2.kemDecrypt(D, encapsulation, 32)).toThrow(DecryptionError);
  });

  it('safeMode returns null for ciphertext-side failures', () => {
    const { key, encapsulation } = sm2.kemEncrypt(pub, 16);
    expect(sm2.kemDecrypt(D, encapsulation, 16)).toBe(key);
    expect(sm2.kemDecrypt(D, flipLastByte(encapsulation), 16, { safeMode: true })).toBeNull();
  });

  it('rejects invalid klen', () => {
    for (const klen of [0, -1, 1.5, Number.NaN]) {
      expect(() => sm2.kemEncrypt(pub, klen)).toThrow(RangeError);
    }
  });
});

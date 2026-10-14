import { describe, expect, it } from 'vitest';
import * as pkg from '@/index';

/**
 * 聚合出口烟测：验证 facade 导出齐全 + 基本调用。
 */
describe('facade smoke', () => {
  it('exports all algorithm namespaces', () => {
    expect(typeof pkg.sm3.hash).toBe('function');
    expect(typeof pkg.sm4.encryptECB).toBe('function');
    expect(typeof pkg.zuc.zucEncrypt).toBe('function');
    expect(typeof pkg.sm2.encrypt).toBe('function');
  });

  it('exports error types', () => {
    expect(typeof pkg.SmCryptoError).toBe('function');
    expect(typeof pkg.isSmCryptoError).toBe('function');
  });

  it('sm3 hashes after ensureLoaded', async () => {
    await pkg.sm3.ensureLoaded();
    expect(pkg.sm3.hash(new Uint8Array([0x61, 0x62, 0x63]))).toBe(
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
    );
  });

  it('sm4 round-trips after ensureLoaded', async () => {
    await pkg.sm4.ensureLoaded();
    const key = new Uint8Array(16).fill(1);
    const msg = new Uint8Array(16).fill(2);
    const ct = pkg.sm4.encryptECB(key, msg);
    expect(pkg.sm4.decryptECB(key, ct)).toBe(Buffer.from(msg).toString('hex'));
  });

  it('sm2 signs/verifies after ensureLoaded', async () => {
    await pkg.sm2.ensureLoaded();
    const d = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
    const pub = pkg.sm2.getPublicKey(d);
    const sig = pkg.sm2.sign(d, 'facade test');
    expect(pkg.sm2.verify(pub, 'facade test', sig)).toBe(true);
  });
});

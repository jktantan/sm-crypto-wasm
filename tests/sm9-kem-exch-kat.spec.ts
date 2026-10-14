import { beforeAll, describe, expect, it } from 'vitest';
import * as sm9 from '@/sm9';
import v from './vectors/sm9/kem-exch-gmssl.json';

/**
 * SM9 密钥封装 KEM 与密钥交换 KAT：与 GmSSL 生成向量逐字节比对。
 *
 * 向量由 GmSSL 3.3 在固定输入（固定 ke、id、随机数 r）下一次性生成，见
 * `tests/vectors/sm9/kem-exch-gmssl.json`。锚定的是权威 C 实现的行为。
 */
describe('SM9 KEM / key exchange KAT (GmSSL-generated)', () => {
  beforeAll(async () => {
    await sm9.ensureLoaded();
  }, 60_000);

  it('KEM matches GmSSL (fixed r)', () => {
    const { key, encapsulation } = sm9.kemEncrypt(v.ke, v.idB, v.kLen, v.rA);
    expect(encapsulation).toBe(v.KEM_C);
    expect(key).toBe(v.KEM_K);
    expect(sm9.kemDecrypt(v.ke, v.idB, encapsulation, v.kLen)).toBe(v.KEM_K);
  }, 180_000);

  it('key exchange matches GmSSL (fixed rA/rB)', async () => {
    const alice = await sm9.createExchangeInitiator(v.ke, v.idA, v.idB, { ephemeral: v.rA });
    const bob = await sm9.createExchangeResponder(v.ke, v.idB, v.idA, { ephemeral: v.rB });
    const m1 = alice.initiate();
    const m2 = bob.respond(m1);
    const m3 = alice.confirm(m2);

    expect(m1.ephemeral).toBe(v.RA);
    expect(m2.ephemeral).toBe(v.RB);
    expect(m2.confirm).toBe(v.SB);
    expect(m3.confirm).toBe(v.SA);
    expect(alice.getSharedKey(m2, v.kLen)).toBe(v.KA);
    expect(bob.getSharedKey(m3, v.kLen)).toBe(v.KB);
  }, 180_000);
});

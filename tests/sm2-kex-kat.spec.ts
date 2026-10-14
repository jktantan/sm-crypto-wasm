import { describe, it, expect, beforeAll } from 'vitest';
import * as sm2 from '@/sm2';
import vectors from './vectors/sm2/keyexchange.json';

/**
 * SM2 密钥交换 KAT：与 GmSSL 生成向量逐字节比对。
 *
 * 向量由 GmSSL 3.3（`src/sm2_exch.c`）在固定输入下一次性生成，见
 * `tests/vectors/sm2/keyexchange.json`。它锚定的是**权威 C 实现的行为**：
 * 与 `tests/sm2-kex.spec.ts`（自产 BigInt oracle）和
 * `tests/sm2-kex-gmkitx.spec.ts`（第三方 JS 实现）互为独立来源。
 *
 * 注：GmSSL 里没有官方（GB/T 32918.3 附录 A）固定向量——其 `sm2_exchtest.c`
 * 也是随机自洽；此向量为用 GmSSL 实现生成的确定性样本。
 */
describe('SM2 key exchange KAT (GmSSL-generated vector)', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('reproduces the GmSSL vector bit-for-bit', async () => {
    const v = vectors;
    // 对端公钥由私钥派生（getPublicKey 已由 OpenSSL 交叉验证）。
    const pubA = sm2.getPublicKey(v.dA);
    const pubB = sm2.getPublicKey(v.dB);

    const alice = await sm2.createExchangeInitiator(v.dA, pubB, {
      idSelf: v.idA, idPeer: v.idB, ephemeralPrivateKey: v.rA,
    });
    const bob = await sm2.createExchangeResponder(v.dB, pubA, {
      idSelf: v.idB, idPeer: v.idA, ephemeralPrivateKey: v.rB,
    });

    const m1 = alice.initiate();
    const m2 = bob.respond(m1);
    const m3 = alice.confirm(m2);

    expect(m1.ephemeralPub).toBe(v.RA);
    expect(m2.ephemeralPub).toBe(v.RB);
    expect(m2.confirm).toBe(v.SB);
    expect(m3.confirm).toBe(v.SA);
    expect(alice.getSharedKey(m3, 32)).toBe(v.K);
    expect(bob.getSharedKey(m3, 32)).toBe(v.K);
  });
});

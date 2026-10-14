import { describe, it, expect, beforeAll } from 'vitest';
import { keyExchange } from 'gmkitx';
import * as sm2 from '@/sm2';

/**
 * SM2 密钥交换 vs gmkitx（第三方实现 oracle）。
 *
 * 与 `tests/sm2-kex.spec.ts` 里的自产 BigInt oracle 不同，这里用的是**独立第三方
 * 库** gmkitx：双方以完全相同的固定输入（长期/临时私钥 + 双方 ID）各自跑一遍，
 * 比较共享密钥与两个确认值。第三方一致性可排除"实现与自写 oracle 一起错"的风险。
 *
 * 命名差异：gmkitx 的 `s1` 是响应方确认值 S_B、`s2` 是发起方确认值 S_A
 * （与其文档里"己方/对方"的措辞相反）；本库中发起方 `confirm()` 返回 S_A、
 * 响应方 `respond()` 返回 S_B。
 */

interface Vector {
  dA: string;
  dB: string;
  rA: string;
  rB: string;
  idA: string;
  idB: string;
}

const VECTORS: Vector[] = [
  {
    dA: '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8',
    dB: '7a3d1c2b9e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f',
    rA: '0000000000000000000000000000000000000000000000000000000000000003',
    rB: '0000000000000000000000000000000000000000000000000000000000000005',
    idA: 'Alice',
    idB: 'Bob',
  },
  {
    dA: '0000000000000000000000000000000000000000000000000000000000000002',
    dB: '0000000000000000000000000000000000000000000000000000000000000003',
    rA: '0000000000000000000000000000000000000000000000000000000000000007',
    rB: '000000000000000000000000000000000000000000000000000000000000000b',
    idA: 'Bob',
    idB: 'Alice',
  },
];

/** 双方各跑一遍，返回本库与 gmkitx 的成对结果。 */
async function runBoth(v: Vector, kLen: number) {
  const PA = sm2.getPublicKey(v.dA); // 64 字节 x || y
  const PB = sm2.getPublicKey(v.dB);
  const RA = sm2.getPublicKey(v.rA);
  const RB = sm2.getPublicKey(v.rB);

  const gA = keyExchange({
    privateKey: v.dA, peerPublicKey: '04' + PB,
    tempPrivateKey: v.rA, peerTempPublicKey: '04' + RB,
    isInitiator: true, userId: v.idA, peerUserId: v.idB, keyLength: kLen,
  });
  const gB = keyExchange({
    privateKey: v.dB, peerPublicKey: '04' + PA,
    tempPrivateKey: v.rB, peerTempPublicKey: '04' + RA,
    isInitiator: false, userId: v.idB, peerUserId: v.idA, keyLength: kLen,
  });

  const alice = await sm2.createExchangeInitiator(v.dA, PB, {
    idSelf: v.idA, idPeer: v.idB, ephemeralPrivateKey: v.rA,
  });
  const bob = await sm2.createExchangeResponder(v.dB, PA, {
    idSelf: v.idB, idPeer: v.idA, ephemeralPrivateKey: v.rB,
  });
  const m1 = alice.initiate();
  const m2 = bob.respond(m1);
  const m3 = alice.confirm(m2);

  return {
    gA, gB,
    sA: m3.confirm,
    sB: m2.confirm,
    keyA: alice.getSharedKey(m3, kLen),
    keyB: bob.getSharedKey(m3, kLen),
  };
}

describe('SM2 key exchange vs gmkitx (third-party oracle)', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  for (const [i, v] of VECTORS.entries()) {
    it(`agrees on shared key + S_A/S_B (vector ${i + 1}, kLen=32)`, async () => {
      const { gA, gB, sA, sB, keyA, keyB } = await runBoth(v, 32);

      // 双方共享密钥一致，且都与 gmkitx 一致。
      expect(keyA).toBe(keyB);
      expect(gA.sharedKey).toBe(keyA);
      expect(gB.sharedKey).toBe(keyB);

      // 两个确认值都与 gmkitx 一致（gmkitx s1 = S_B、s2 = S_A）。
      expect(gA.s1).toBe(sB);
      expect(gA.s2).toBe(sA);
      expect(gB.s1).toBe(sB);
      expect(gB.s2).toBe(sA);
    });
  }

  it('agrees on a 128-bit shared key (kLen=16)', async () => {
    const v = VECTORS[0] as Vector;
    const { gA, keyA } = await runBoth(v, 16);
    expect(keyA).toHaveLength(32); // 16 字节 hex
    expect(gA.sharedKey).toBe(keyA);
  });
});

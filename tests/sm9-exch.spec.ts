import { describe, it, expect, beforeAll } from 'vitest';
import * as sm9 from '@/sm9';

/**
 * SM9 密钥交换（GM/T 0044.3）。
 *
 * 注意：SM9 密钥交换要求双方属于**同一 KGC**，即共享同一加密主密钥 ke
 * （Ppube 相同）。双方用各自的 id。
 *
 * 覆盖：双方协商出相同共享密钥、确认值 S_A/S_B 互验、篡改确认值被拒、自定义 kLen。
 * 与 GmSSL 的固定向量对拍见 sm9_verify 阶段（编译 GmSSL 生成）。
 */
const KE = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const ID_A = 'Alice';
const ID_B = 'Bob';

function flip(h: string): string {
  const last = h.slice(-2);
  return h.slice(0, -2) + (last === 'ff' ? '00' : 'ff');
}

describe('SM9 key exchange (GM/T 0044.3)', () => {
  beforeAll(async () => {
    await sm9.ensureLoaded();
  }, 60_000);

  it('two parties derive the same shared key and verify confirmations', async () => {
    const alice = await sm9.createExchangeInitiator(KE, ID_A, ID_B);
    const bob = await sm9.createExchangeResponder(KE, ID_B, ID_A);
    const m1 = alice.initiate();
    const m2 = bob.respond(m1);
    const m3 = alice.confirm(m2);
    const kA = alice.getSharedKey(m2, 32);
    const kB = bob.getSharedKey(m3, 32);
    expect(kA).toBe(kB);
    expect(kA).toHaveLength(64);
  }, 180_000);

  it('rejects a tampered responder confirmation (S_B)', async () => {
    const alice = await sm9.createExchangeInitiator(KE, ID_A, ID_B);
    const bob = await sm9.createExchangeResponder(KE, ID_B, ID_A);
    const m1 = alice.initiate();
    const m2 = bob.respond(m1);
    expect(() => alice.confirm({ ...m2, confirm: flip(m2.confirm) })).toThrow(/S_B/);
  }, 180_000);

  it('rejects a tampered initiator confirmation (S_A)', async () => {
    const alice = await sm9.createExchangeInitiator(KE, ID_A, ID_B);
    const bob = await sm9.createExchangeResponder(KE, ID_B, ID_A);
    const m1 = alice.initiate();
    const m2 = bob.respond(m1);
    const m3 = alice.confirm(m2);
    expect(() => bob.getSharedKey({ confirm: flip(m3.confirm) }, 32)).toThrow(/S_A/);
  }, 180_000);

  it('supports a custom key length', async () => {
    const alice = await sm9.createExchangeInitiator(KE, ID_A, ID_B, { kLen: 16 });
    const bob = await sm9.createExchangeResponder(KE, ID_B, ID_A, { kLen: 16 });
    const m1 = alice.initiate();
    const m2 = bob.respond(m1);
    const m3 = alice.confirm(m2);
    const kA = alice.getSharedKey(m2);
    const kB = bob.getSharedKey(m3);
    expect(kA).toBe(kB);
    expect(kA).toHaveLength(32);
  }, 180_000);
});

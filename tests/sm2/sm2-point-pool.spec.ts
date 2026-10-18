/**
 * SM2 签名点池：池命中、耗尽回退、与普通签名互通，以及**结构性防复用**。
 *
 * `sign()` 的 `pointPool` 把"固定基点标量乘 k·G"（实测占单次签名的 56%）提前摊销。
 * 除了快，这套 API 的设计目标是让"绝不复用 k"**不需要调用方操心**：
 * 1) `k` 封在模块内部（WeakMap），外部读不到，因此无法复制或序列化一个点；
 * 2) 取走即从索引删除，同一个实例再喂一次会当场抛错，而不是悄悄复用 k 泄露私钥。
 */
import { beforeAll, describe, expect, it } from 'vitest';
import * as sm2 from '@/sm2';

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const MSG = 'point pool message';
const OTHER = 'another message';

describe('SM2 签名点池', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('池命中的签名可被验签', async () => {
    const pub = sm2.getPublicKey(D);
    const pool = await sm2.createSignaturePointPool(4);
    const sig = sm2.sign(D, MSG, { pointPool: pool });
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
    expect(sm2.verify(pub, MSG, sig)).toBe(true);
  });

  it('每次签名消费一个点，池取空后自动回退到现算', async () => {
    const pub = sm2.getPublicKey(D);
    const pool = await sm2.createSignaturePointPool(2);
    expect(pool).toHaveLength(2);

    const s1 = sm2.sign(D, MSG, { pointPool: pool });
    expect(pool).toHaveLength(1);
    const s2 = sm2.sign(D, MSG, { pointPool: pool });
    expect(pool).toHaveLength(0);
    // 池已空：必须回退到常规路径，且照常签出可验的签名。
    const s3 = sm2.sign(D, MSG, { pointPool: pool });

    for (const s of [s1, s2, s3]) expect(sm2.verify(pub, MSG, s)).toBe(true);
  });

  it('池签名与普通签名互通，且不会串消息', async () => {
    const pub = sm2.getPublicKey(D);
    const pool = await sm2.createSignaturePointPool(1);
    const pooled = sm2.sign(D, MSG, { pointPool: pool });
    const plain = sm2.sign(D, MSG);
    expect(sm2.verify(pub, MSG, pooled)).toBe(true);
    expect(sm2.verify(pub, MSG, plain)).toBe(true);
    expect(sm2.verify(pub, OTHER, pooled)).toBe(false);
  });

  it('不传池时行为不变（向后兼容）', () => {
    const pub = sm2.getPublicKey(D);
    expect(sm2.verify(pub, MSG, sm2.sign(D, MSG))).toBe(true);
  });

  it('签名点只暴露 k·G 的坐标，拿不到 k', async () => {
    const pool = await sm2.createSignaturePointPool(3);
    for (const p of pool) {
      expect(p.point).toMatch(/^[0-9a-f]{128}$/);
      expect(Object.keys(p)).not.toContain('k');
      expect((p as unknown as Record<string, unknown>).k).toBeUndefined();
      // 也不该有任何字段长得像私钥（32 字节 hex）
      for (const v of Object.values(p)) {
        expect(String(v)).not.toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it('同一个点喂两次会抛错（复用 k 在 API 层不可能发生）', async () => {
    const pub = sm2.getPublicKey(D);
    const [point] = await sm2.createSignaturePointPool(1);
    const sig = sm2.sign(D, MSG, { pointPool: [point] });
    expect(sm2.verify(pub, MSG, sig)).toBe(true);
    // 即使调用方把同一个实例再喂一次，也取不到第二个 k
    expect(() => sm2.sign(D, MSG, { pointPool: [point] })).toThrow(/一次性|不可用/);
  });

  it('伪造的 SignaturePoint 无法用于签名', async () => {
    const fake = { point: '0'.repeat(128) } as unknown as sm2.SignaturePoint;
    expect(() => sm2.sign(D, MSG, { pointPool: [fake] })).toThrow(/一次性|不可用/);
  });

  it('池里每个点的 k·G 互不相同', async () => {
    const pool = await sm2.createSignaturePointPool(8);
    expect(new Set(pool.map((p) => p.point)).size).toBe(8);
  });

  it('池大小为 0 时等价于不传池；非法大小抛 RangeError', async () => {
    const pub = sm2.getPublicKey(D);
    const empty = await sm2.createSignaturePointPool(0);
    expect(empty).toEqual([]);
    expect(sm2.verify(pub, MSG, sm2.sign(D, MSG, { pointPool: empty }))).toBe(true);

    await expect(sm2.createSignaturePointPool(-1)).rejects.toThrow(RangeError);
    await expect(sm2.createSignaturePointPool(1.5)).rejects.toThrow(RangeError);
  });
});

/**
 * SM2 签名点池：池命中、耗尽回退、与普通签名互通。
 *
 * `sign()` 的 `pointPool` 是把"固定基点标量乘 k·G"（实测占单次签名的 56%）
 * 提前摊销掉。除了快，正确性上最要紧的两点：
 * 1) 池里每个 k 都一次性使用、互不相同 —— 复用 k 会直接泄露私钥；
 * 2) 池空了以后必须自动回退到现算，不能少签或签错。
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
    // 池已空：必须回退到 常规路径，且照常签出可验的签名。
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

  it('池中的 k 互不相同且格式正确（绝不复用临时私钥）', async () => {
    const pool = await sm2.createSignaturePointPool(8);
    expect(new Set(pool.map((p) => p.k)).size).toBe(8);
    for (const p of pool) {
      expect(p.k).toMatch(/^[0-9a-f]{64}$/);
      expect(p.point).toMatch(/^[0-9a-f]{128}$/);
    }
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

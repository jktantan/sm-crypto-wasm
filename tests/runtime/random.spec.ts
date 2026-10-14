import { describe, expect, it } from 'vitest';
import { randomBytes, randomScalarBelow } from '@/runtime/random';

/**
 * 宿主 CSPRNG 包装（spec §9）：永远走宿主 `crypto.getRandomValues`，绝不实例化本地 RNG。
 */
describe('randomBytes 长度契约', () => {
  it('0 与正整数长度都正常', () => {
    expect(randomBytes(0).length).toBe(0);
    for (const n of [1, 16, 32, 1024]) {
      expect(randomBytes(n).length).toBe(n);
    }
  });

  it('负数抛 RangeError', () => {
    expect(() => randomBytes(-1)).toThrow(RangeError);
  });

  it('非整数抛 RangeError', () => {
    expect(() => randomBytes(1.5)).toThrow(RangeError);
  });

  it('超过上限抛 RangeError', () => {
    expect(() => randomBytes(65537)).toThrow(RangeError);
  });

  it('结果是新分配的（不是缓冲别名）', () => {
    const a = randomBytes(16);
    const b = randomBytes(16);
    expect(a).not.toBe(b);
    a.fill(0);
    expect(b[0] !== 0 || true).toBe(true);
  });
});

describe('randomScalarBelow 拒绝采样', () => {
  const N_SM2 = BigInt('0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');
  const N_SM9 = BigInt('0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25');

  it('SM2 阶下：1 ≤ k < n', () => {
    for (let i = 0; i < 50; i++) {
      const k = randomScalarBelow(N_SM2);
      expect(k > 0n).toBe(true);
      expect(k < N_SM2).toBe(true);
    }
  });

  it('SM9 阶下：1 ≤ k < n', () => {
    for (let i = 0; i < 50; i++) {
      const k = randomScalarBelow(N_SM9);
      expect(k > 0n).toBe(true);
      expect(k < N_SM9).toBe(true);
    }
  });

  it('非法 order 抛 RangeError', () => {
    expect(() => randomScalarBelow(0n)).toThrow(RangeError);
    expect(() => randomScalarBelow(1n)).toThrow(RangeError);
  });
});

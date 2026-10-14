/**
 * SM9 主私钥标量范围校验（[1, n−1]）。
 *
 * 背景：wasm 侧的密钥派生计算 `addModN(h1, k)`，而 `modAdd` 只做**一次**条件减、
 * 依赖「两边都已约化」（k + h1 < 2n）。k ≥ n 时 k + h1 可能 ≥ 2n，减一次不够，
 * 会**静默**产出错值（不崩溃、不报错）。因此在 TS 入口显式拒绝越界标量。
 *
 * 合法密钥（SM9 规范内，1 ≤ k ≤ n−1）不受影响；见 sm9.spec.ts 的 KAT 对拍。
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { ensureLoaded, getEncPublicKey, getSignPublicKey, sign } from '@/sm9';

const N_HEX = 'b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25';
const N = BigInt(`0x${N_HEX}`);

describe('SM9 主私钥标量范围校验', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  it('拒绝越界标量：0、n、2²⁵⁶−1', () => {
    for (const bad of ['00'.repeat(32), N_HEX, 'ff'.repeat(32)]) {
      expect(() => getSignPublicKey(bad), `ks=${bad.slice(0, 8)}…`).toThrow(/范围/);
      expect(() => getEncPublicKey(bad), `ke=${bad.slice(0, 8)}…`).toThrow(/范围/);
    }
  });

  it('边界值 n−1 与 1 被接受', () => {
    const nMinus1 = (N - 1n).toString(16).padStart(64, '0');
    const one = `${'00'.repeat(31)}01`;
    // 签名主公钥是 G2 点（128 字节 = 256 hex）；加密主公钥是 G1 点（64 字节 = 128 hex）
    expect(getSignPublicKey(nMinus1)).toMatch(/^[0-9a-f]{256}$/);
    expect(getSignPublicKey(one)).toMatch(/^[0-9a-f]{256}$/);
    expect(getEncPublicKey(nMinus1)).toMatch(/^[0-9a-f]{128}$/);
  });

  it('校验覆盖其它主私钥入口（sign 同样拒绝）', () => {
    expect(() => sign('ff'.repeat(32), 'a@b', 'msg')).toThrow(/范围/);
    expect(() => sign('00'.repeat(32), 'a@b', 'msg')).toThrow(/范围/);
  });
});

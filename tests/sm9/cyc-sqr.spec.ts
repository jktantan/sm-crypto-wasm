/**
 * cyclotomic 平方（fp12SqrCycTo）的随机输入对拍。
 *
 * hard part 期间元素处于 G_{Φ6(p²)} 子群，专用平方把通用平方的 6 次 fp4Sqr
 * 降到 2 次 fp4Sqr + 1 次 fp4Mul。KAT 只能覆盖具体消息/密钥，这里用 seed
 * 派生的随机 Fp12 送入子群，逐字节比较专用平方与通用平方的结果。
 *
 * wasm 侧实现见 src/sm9/assembly/fp12.ts 的 fp12SqrCycTo 与
 * src/sm9/assembly/pairing.ts 的 sqrCycSelfTest。
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { ensureLoaded, sqrCycSelfTest } from '@/sm9';

describe('SM9 cyclotomic squaring', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  it('随机子群元素上与通用平方逐字节一致', () => {
    for (let seed = 1; seed <= 24; seed++) {
      const s = (seed * 7919) | 0;
      expect(sqrCycSelfTest(s), `seed=${s}`).toBe(1);
    }
  });

  it('覆盖大/小 seed 与边界值', () => {
    for (const s of [1, 0x7fffffff | 0, -1, -2147483648, 123456789]) {
      expect(sqrCycSelfTest(s), `seed=${s}`).toBe(1);
    }
  });
});

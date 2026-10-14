import { beforeAll, describe, expect, it } from 'vitest';
import * as sm9 from '@/sm9';

/**
 * SM9 密钥封装机制 KEM（GM/T 0044.4）。
 *
 * 覆盖：封装→解封装自洽、与 SM9 公钥加密共用同一 C1（同 r 时应逐字节一致）、
 * 自定义 klen、id/主公钥不匹配时得到不同密钥。
 *
 * 注：SM9 pairing 较重，单次 wasm 调用数秒~数十秒，故每个用例给足超时。
 */
const KE = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const ID = 'Alice';

describe('SM9 KEM (GM/T 0044.4)', () => {
  beforeAll(async () => {
    await sm9.ensureLoaded();
  }, 60_000);

  it('encapsulate → decapsulate yields the same key', async () => {
    const { key, encapsulation } = sm9.kemEncrypt(KE, ID, 32);
    expect(key).toHaveLength(64);
    expect(encapsulation).toHaveLength(130); // 65 字节 hex
    expect(encapsulation.slice(0, 2)).toBe('04');
    expect(sm9.kemDecrypt(KE, ID, encapsulation, 32)).toBe(key);
  }, 120_000);

  it('encapsulation C1 equals the SM9 encrypt C1 for the same r', async () => {
    const r = '00'.repeat(31) + '07';
    const { encapsulation } = sm9.kemEncrypt(KE, ID, 32, r);
    // encrypt 返回 C1(65B)||C3(32B)||C2；C1 即前 65 字节。
    const ct = sm9.encrypt(KE, ID, 'hello sm9 kem', r);
    expect(ct.slice(0, 130)).toBe(encapsulation);
  }, 120_000);

  it('supports a custom key length (klen=16)', async () => {
    const { key, encapsulation } = sm9.kemEncrypt(KE, ID, 16);
    expect(key).toHaveLength(32);
    expect(sm9.kemDecrypt(KE, ID, encapsulation, 16)).toBe(key);
  }, 120_000);

  it('a different identity yields a different key (no implicit authentication)', async () => {
    const { key, encapsulation } = sm9.kemEncrypt(KE, ID, 32);
    const other = sm9.kemDecrypt(KE, 'Bob', encapsulation, 32);
    expect(other).not.toBe(key);
  }, 120_000);
});

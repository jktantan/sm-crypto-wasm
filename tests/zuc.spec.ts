import { describe, it, expect, beforeAll } from 'vitest';
import { zucKeystream, zucEncrypt, zucDecrypt, zucMac, ensureLoaded } from '@/zuc';
import { randomBytes } from '@/runtime/random';
import eia3Vectors from './vectors/zuc/eia3.json';

/**
 * ZUC 与独立参考实现（gmkitx, Apache-2.0）对比。
 *
 * 国标向量：key = iv = 全 0 时，密钥流首 16 字节 = 27bede74 018082da ...
 */
const KEY = Buffer.alloc(16);
const IV = Buffer.alloc(16);

/**
 * 按 GmSSL `zuc_set_eia_iv` 的比特布局把 COUNT/BEARER/DIRECTION 组装成 16 字节 IV。
 *
 * EIA3 的 IV 是两段等长的 64-bit 结构：
 *   COUNT(32) || BEARER(5) || DIRECTION(1) || 0(26)
 */
function eia3Iv(count: number, bearer: number, direction: number): Uint8Array {
  const iv = new Uint8Array(16);
  iv[0] = (count >>> 24) & 0xff;
  iv[1] = iv[9] = (count >>> 16) & 0xff;
  iv[2] = iv[10] = (count >>> 8) & 0xff;
  iv[3] = iv[11] = count & 0xff;
  iv[4] = iv[12] = (bearer << 3) & 0xff;
  iv[8] = (iv[0] ?? 0) ^ ((direction << 7) & 0xff);
  iv[14] = (direction << 7) & 0xff;
  return iv;
}

describe('ZUC vs reference (gmkitx)', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  it('keystream first 16 bytes matches GM/T 0001 vector', () => {
    const ks = zucKeystream(KEY, IV, 16);
    expect(Buffer.from(ks).toString('hex')).toBe(
      '27bede74018082da87d4e5b69f18bf66',
    );
  });

  it('keystream 32 bytes matches reference', async () => {
    const { zucKeystream: refKs } = await import('gmkitx');
    // gmkitx 的 zucKeystream 的第三参是「字节长度」，返回小写 hex 字符串。
    const ref = String(refKs(KEY, IV, 32)).toLowerCase();
    const mine = Buffer.from(zucKeystream(KEY, IV, 32)).toString('hex');
    expect(mine).toBe(ref);
  });

  it('encrypt/decrypt round-trips', () => {
    const msg = new Uint8Array(Buffer.from('hello zuc world!!'));
    const ct = zucEncrypt(KEY, IV, msg);
    const pt = zucDecrypt(KEY, IV, ct);
    expect(Buffer.from(pt)).toEqual(Buffer.from(msg));
  });
});

describe('ZUC EIA3 (GM/T 0001.3-2012 official vectors)', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  for (const c of eia3Vectors.cases) {
    it(`matches ${c.name}`, () => {
      const iv = eia3Iv(c.count, c.bearer, c.direction);
      const tag = zucMac(c.key, iv, c.message, c.bitLength);
      expect(Buffer.from(tag).toString('hex')).toBe(c.mac);
    });
  }

  it('defaults bitLength to the full byte length', async () => {
    const { eia3 } = await import('gmkitx');
    const key = 'c9e6cec4607c72db000aefa88385ab0a';
    const msg = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
    const mine = Buffer.from(zucMac(key, eia3Iv(0xa94059da, 0x0a, 1), msg)).toString('hex');
    const ref = String(eia3(key, 0xa94059da, 0x0a, 1, msg)).toLowerCase();
    expect(mine).toBe(ref);
  });

  it('rejects a tag length other than 32 bits', () => {
    expect(() => zucMac(KEY, IV, 'a', 8, 64)).toThrow(RangeError);
  });
});

describe('ZUC (key, iv, counter) reuse guard', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  it('throws when the same (key, iv, counter) encrypts twice', () => {
    const k = randomBytes(16);
    const iv = randomBytes(16);
    zucEncrypt(k, iv, new Uint8Array([1, 2, 3]));
    expect(() => zucEncrypt(k, iv, new Uint8Array([4, 5, 6]))).toThrow(/复用/);
  });

  it('a different counter is accepted', () => {
    const k = randomBytes(16);
    const iv = randomBytes(16);
    expect(() => {
      zucEncrypt(k, iv, new Uint8Array([1]), 0);
      zucEncrypt(k, iv, new Uint8Array([2]), 1);
    }).not.toThrow();
  });

  it('decryption is exempt from the guard', () => {
    const k = randomBytes(16);
    const iv = randomBytes(16);
    const msg = new Uint8Array([1, 2, 3, 4]);
    const ct = zucEncrypt(k, iv, msg);
    expect(Buffer.from(zucDecrypt(k, iv, ct)).toString('hex')).toBe('01020304');
  });

  it('keeps the guard bounded — the oldest entry is evicted, recent ones still protected', () => {
    const k = randomBytes(16);
    const iv = randomBytes(16);
    const one = new Uint8Array([1]);

    zucEncrypt(k, iv, one, 0);
    // 越过上限，把 counter=0 挤出窗口。
    for (let i = 1; i <= 4096; i++) zucEncrypt(k, iv, one, i);

    // 最旧的一条已被淘汰：可再次使用。
    expect(() => zucEncrypt(k, iv, new Uint8Array([2]), 0)).not.toThrow();
    // 最近的一条仍在保护中。
    expect(() => zucEncrypt(k, iv, new Uint8Array([2]), 4096)).toThrow(/复用/);
  });
});

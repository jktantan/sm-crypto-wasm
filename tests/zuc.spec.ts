import { beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from '@/runtime/random';
import {
  configureReuseGuard,
  ensureLoaded,
  zucDecrypt,
  zucEia3Iv,
  zucEncrypt,
  zucKeystream,
  zucMac,
} from '@/zuc';
import eia3Vectors from './vectors/zuc/eia3.json';

/**
 * ZUC 与独立参考实现（gmkitx, Apache-2.0）对比。
 *
 * 国标向量：key = iv = 全 0 时，密钥流首 16 字节 = 27bede74 018082da ...
 */
const KEY = Buffer.alloc(16);
const IV = Buffer.alloc(16);

/**
 * EIA3 的 IV 构造现已由库提供（`zucEia3Iv`）—— 早先这段逻辑只存在于本测试里。
 */
const eia3Iv = zucEia3Iv;

describe('ZUC vs reference (gmkitx)', () => {
  beforeAll(async () => {
    await ensureLoaded();
  });

  it('keystream first 16 bytes matches GM/T 0001 vector', () => {
    const ks = zucKeystream(KEY, IV, 16);
    expect(Buffer.from(ks).toString('hex')).toBe('27bede74018082da87d4e5b69f18bf66');
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

/**
 * API 平滑化：位置参数换成 options 对象也能用；复用保护可关/可调容量；
 * EIA3 的 IV 构造是公共 API 而不是测试私有逻辑。
 */
describe('ZUC API 扩展点', () => {
  const K = new Uint8Array(16).fill(3);
  const V = new Uint8Array(16).fill(5);
  const M = new Uint8Array([1, 2, 3, 4]);

  beforeAll(async () => {
    await ensureLoaded();
  });

  it('zucMac 的位置参数与 options 对象等价', () => {
    const byPos = Buffer.from(zucMac(K, V, M, 32)).toString('hex');
    expect(Buffer.from(zucMac(K, V, M, { bitLength: 32 })).toString('hex')).toBe(byPos);
    expect(Buffer.from(zucMac(K, V, M, { bitLength: 32, tagBits: 32 })).toString('hex')).toBe(
      byPos,
    );
  });

  it('options 形式下非法 tagBits 仍抛 RangeError', () => {
    expect(() => zucMac(K, V, M, { tagBits: 64 })).toThrow(RangeError);
  });

  it('zucEia3Iv 按 3GPP TS 35.221 的布局组装 IV', () => {
    expect(Buffer.from(zucEia3Iv(0x66035492, 0x0f, 0)).toString('hex')).toBe(
      '66035492780000006603549278000000',
    );
    expect(() => zucEia3Iv(-1, 0, 0)).toThrow(RangeError);
    expect(() => zucEia3Iv(0, 32, 0)).toThrow(RangeError);
    expect(() => zucEia3Iv(0, 0, 2)).toThrow(RangeError);
  });

  it('zucEncrypt 可用 reuseGuard: false 显式跳过保护', () => {
    const k = randomBytes(16);
    const iv = randomBytes(16);
    zucEncrypt(k, iv, new Uint8Array([1]));
    expect(() => zucEncrypt(k, iv, new Uint8Array([2]), 0, { reuseGuard: false })).not.toThrow();
  });

  it('configureReuseGuard 可调容量与总开关', () => {
    const k = randomBytes(16);
    const iv = randomBytes(16);
    configureReuseGuard({ capacity: 4 });
    try {
      for (let i = 0; i < 5; i++) zucEncrypt(k, iv, new Uint8Array([1]), i);
      // 容量 4 → counter=0 已被挤出窗口。
      expect(() => zucEncrypt(k, iv, new Uint8Array([2]), 0)).not.toThrow();

      configureReuseGuard({ enabled: false });
      // guard 关闭后，刚用过的 counter=4 也能再用。
      expect(() => zucEncrypt(k, iv, new Uint8Array([3]), 4)).not.toThrow();
    } finally {
      configureReuseGuard({ enabled: true, capacity: 4096 });
    }
  });
});

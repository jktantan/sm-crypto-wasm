import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as sm2 from '@/sm2';

/**
 * SM2 公钥派生缓存的开关与边界。
 *
 * 缓存本身是不可观测的内部状态，所以这里测的是**行为**：无论缓存开、关、
 * 容量多小（触发 FIFO 淘汰），`sign` 的结果都必须自洽（能用对应公钥验签）。
 * 性能收益的证据在 `bench/` 与 `docs/performance-ceiling.md`，不在单测里。
 */
const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
/** 另一个合法私钥（0 < d < n）。 */
const D2 = '6fcba2e4c3ab5a4d0b5c1e8f7a9d3b2c4e5f60718293a4b5c6d7e8f90a1b2c3d';
const MSG = new Uint8Array([1, 2, 3]);

/** 用对应公钥验签一次，返回是否通过。 */
function signAndVerify(d: string): boolean {
  return sm2.verify(sm2.getPublicKey(d), MSG, sm2.sign(d, MSG));
}

describe('sm2 public key cache', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  afterAll(() => {
    // 复位成默认，避免同模块状态泄漏到同文件内后续用例。
    sm2.configurePublicKeyCache({ enabled: true, capacity: 32 });
    sm2.clearPublicKeyCache();
  });

  it('默认（缓存开启）重复签名都自洽', () => {
    const pub = sm2.getPublicKey(D);
    for (let i = 0; i < 3; i++) {
      // 命中缓存不会改变签名结果的正确性（k 仍每次随机，签名每次都不同）。
      expect(sm2.verify(pub, MSG, sm2.sign(D, MSG))).toBe(true);
    }
  });

  it('关闭缓存后仍能正确签名与验签', () => {
    sm2.configurePublicKeyCache({ enabled: false });
    expect(signAndVerify(D)).toBe(true);
    expect(signAndVerify(D2)).toBe(true);
    sm2.configurePublicKeyCache({ enabled: true });
  });

  it('capacity = 1 触发 FIFO 淘汰时不影响正确性', () => {
    sm2.configurePublicKeyCache({ capacity: 1 });
    expect(signAndVerify(D)).toBe(true);
    expect(signAndVerify(D2)).toBe(true);
    expect(signAndVerify(D)).toBe(true);
  });

  it('clearPublicKeyCache 后签名仍正确', () => {
    const pub = sm2.getPublicKey(D);
    const sig = sm2.sign(D, MSG);
    sm2.clearPublicKeyCache();
    expect(sm2.verify(pub, MSG, sig)).toBe(true);
    expect(signAndVerify(D)).toBe(true);
  });

  it('capacity 非正整数抛 RangeError', () => {
    expect(() => sm2.configurePublicKeyCache({ capacity: 0 })).toThrow(RangeError);
    expect(() => sm2.configurePublicKeyCache({ capacity: -1 })).toThrow(RangeError);
    expect(() => sm2.configurePublicKeyCache({ capacity: 1.5 })).toThrow(RangeError);
  });

  it('私钥派生缓存的键只影响 sign，getPublicKey 不在缓存路径上', () => {
    // getPublicKey 每次真算；关掉缓存后再取一次，结果必须与之前一致。
    const before = sm2.getPublicKey(D);
    sm2.configurePublicKeyCache({ enabled: false });
    expect(sm2.getPublicKey(D)).toBe(before);
    sm2.configurePublicKeyCache({ enabled: true });
  });
});

import { describe, expect, it, beforeAll } from 'vitest';
import fc from 'fast-check';
import * as sm2 from '@/sm2';
import * as sm3 from '@/sm3';
import * as sm4 from '@/sm4';
import { hash as nodeSm3 } from 'node:crypto';
import { DecryptionError, InvalidPublicKeyError } from '@/runtime';

/**
 * Wycheproof 风格的 fast-check 模糊用例。
 *
 * 目标：不是验证实现细节，而是把"用错误的输入轮番攻击，看是否出现不该抛的错 / 漏抛的错"。
 * 每个用例都给出**反例**（应当失败的攻击模式被拒绝）或**等价**（双向结果一致）。
 */
describe('Wycheproof 风格 fuzz', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
    await sm3.ensureLoaded();
    await sm4.ensureLoaded();
  });

  it('SM2 encrypt: 随机生成的坏点全部被 InvalidPublicKeyError 拒绝', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 64, maxLength: 64 }).map((b) => new Uint8Array(b)),
        (pub) => {
          expect(() => sm2.encrypt(pub, new Uint8Array([1, 2, 3]))).toThrow(InvalidPublicKeyError);
        },
      ),
      { numRuns: 50 },
    );
  });

  it('SM4 decryptGCM: tag 任一字节被翻转都抛 DecryptionError', () => {
    const key = new Uint8Array(16).fill(1);
    const iv = new Uint8Array(12).fill(2);
    const aad = new Uint8Array([4, 5]);
    const r = sm4.encryptGCM(key, iv, new Uint8Array([1, 2, 3]), aad);

    fc.assert(
      fc.property(fc.integer({ min: 0, max: 31 }), (i) => {
        const badTag = Buffer.from(r.tag, 'hex');
        badTag[i >>> 1] ^= 0x80 >> (4 * (i & 1));
        expect(() => sm4.decryptGCM(key, iv, r.ct, badTag, aad)).toThrow(DecryptionError);
      }),
      { numRuns: 32 },
    );
  });

  it('SM3 hash: 任意 1~256 字节输入都和 Node crypto 对拍', async () => {
    await sm3.ensureLoaded();
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 256 }), async (data) => {
        const ours = sm3.hash(new Uint8Array(data));
        const theirs = nodeSm3(Buffer.from(data)).digest('hex');
        expect(ours).toBe(theirs);
      }),
      { numRuns: 50 },
    );
  });
});

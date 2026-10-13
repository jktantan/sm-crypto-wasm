import { describe, it, expect, beforeAll } from 'vitest';
import { zucKeystream, zucEncrypt, ensureLoaded } from '@/zuc';

/**
 * ZUC 与独立参考实现（gmkitx, Apache-2.0）对比。
 *
 * 国标向量：key = iv = 全 0 时，密钥流首 16 字节 = 27bede74 018082da ...
 */
const KEY = Buffer.alloc(16);
const IV = Buffer.alloc(16);

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
    const pt = zucEncrypt(KEY, IV, ct);
    expect(Buffer.from(pt)).toEqual(Buffer.from(msg));
  });
});
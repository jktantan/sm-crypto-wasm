import { beforeAll, describe, expect, it } from 'vitest';
import * as sm4 from '@/sm4';
import * as zuc from '@/zuc';

/**
 * 方法名别名：现名（cryptCTR / zucEncrypt …）保持为主名，同时提供
 * spec §6 与 plan Task 9/11 里写的方法名，避免调用方按文档写却找不到函数。
 */
describe('方法名别名（文档名 ↔ 现名）', () => {
  beforeAll(async () => {
    await sm4.ensureLoaded();
    await zuc.ensureLoaded();
  });

  it('sm4.encryptCTR / decryptCTR 与 cryptCTR 同实现', () => {
    expect(sm4.encryptCTR).toBe(sm4.cryptCTR);
    expect(sm4.decryptCTR).toBe(sm4.cryptCTR);
  });

  it('sm4.encryptOFB / decryptOFB 与 cryptOFB 同实现', () => {
    expect(sm4.encryptOFB).toBe(sm4.cryptOFB);
    expect(sm4.decryptOFB).toBe(sm4.cryptOFB);
  });

  it('zuc 别名指向同一实现', () => {
    expect(zuc.encrypt).toBe(zuc.zucEncrypt);
    expect(zuc.decrypt).toBe(zuc.zucDecrypt);
    expect(zuc.generateKeystream).toBe(zuc.zucKeystream);
    expect(zuc.mac).toBe(zuc.zucMac);
    expect(zuc.eia3).toBe(zuc.zucMac);
  });

  it('别名在功能层面可用', () => {
    const key = new Uint8Array(16).fill(7);
    const iv = new Uint8Array(16).fill(9);
    const msg = new Uint8Array([1, 2, 3, 4]);

    const ct = sm4.encryptCTR(key, iv, msg);
    expect(sm4.decryptCTR(key, iv, ct)).toBe(Buffer.from(msg).toString('hex'));

    const zct = zuc.encrypt(key, iv, msg);
    expect(Buffer.from(zuc.decrypt(key, iv, zct))).toEqual(Buffer.from(msg));
    expect(zuc.mac(key, iv, msg).length).toBe(4);
  });
});

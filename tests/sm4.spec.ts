import { describe, it, expect, beforeAll } from 'vitest';
import { createCipheriv } from 'node:crypto';
import * as sm4 from '@/sm4';

/**
 * SM4 与 Node crypto oracle 对比。
 * Node 支持 sm4-ecb / sm4-cbc / sm4-ctr / sm4-cfb / sm4-ofb。
 */
const nodeEnc = (algo: string, key: Buffer, iv: Buffer | null, data: Buffer): Buffer => {
  const c = createCipheriv(algo, key, iv as Buffer);
  return Buffer.concat([c.update(data), c.final()]);
};

/** ECB 用：禁止 Node 自动 PKCS#7 填充（我们的 ECB 是裸块）。 */
const nodeEncNoPad = (algo: string, key: Buffer, data: Buffer): Buffer => {
  const c = createCipheriv(algo, key, null as unknown as Buffer);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
};

const KEY = Buffer.from('0123456789abcdeffedcba9876543210', 'hex');
const IV = Buffer.from('00000000000000000000000000000000', 'hex');
// 16 字节整块明文（避开 padding 差异，CBC 用 Node 的自动 padding 对齐 PKCS#7）。
const MSG = Buffer.from('a3b1bac656aa3350677d9197b27022dc', 'hex');

describe('SM4 vs Node crypto oracle', () => {
  beforeAll(async () => {
    await sm4.ensureLoaded();
  });

  it('ECB matches oracle', () => {
    const want = nodeEncNoPad('sm4-ecb', KEY, MSG).toString('hex');
    expect(sm4.encryptECB(KEY, MSG)).toBe(want);
    expect(sm4.decryptECB(KEY, Buffer.from(want, 'hex'))).toBe(MSG.toString('hex'));
  });

  it('CBC matches oracle', () => {
    const want = nodeEnc('sm4-cbc', KEY, IV, MSG).toString('hex');
    expect(sm4.encryptCBC(KEY, IV, MSG)).toBe(want);
    expect(sm4.decryptCBC(KEY, IV, Buffer.from(want, 'hex'))).toBe(MSG.toString('hex'));
  });

  it('CTR matches oracle', () => {
    const want = nodeEnc('sm4-ctr', KEY, IV, MSG).toString('hex');
    expect(sm4.cryptCTR(KEY, IV, MSG)).toBe(want);
  });

  it('OFB matches oracle', () => {
    const want = nodeEnc('sm4-ofb', KEY, IV, MSG).toString('hex');
    expect(sm4.cryptOFB(KEY, IV, MSG)).toBe(want);
  });
});
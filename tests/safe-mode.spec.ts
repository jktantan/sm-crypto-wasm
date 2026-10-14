import { describe, it, expect, beforeAll } from 'vitest';
import * as sm2 from '@/sm2';
import * as sm4 from '@/sm4';
import * as sm9 from '@/sm9';
import { DecryptionError } from '@/runtime';

/**
 * `safeMode`（plan Review Focus #4）：解密失败时返回 `null` 而不是抛错。
 *
 * 返回类型通过重载保持兼容 —— 只有显式写 `{ safeMode: true }` 的调用点才会拿到
 * `string | null`，既有调用点的类型仍是 `string`。
 */
function flipHex(s: string, i: number): string {
  return s.slice(0, i) + (s[i] === 'f' ? '0' : 'f') + s.slice(i + 1);
}

describe('sm2.decrypt safeMode', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('错误私钥 → null；正确私钥 → 明文', async () => {
    const kp = await sm2.generateKeyPair();
    const other = await sm2.generateKeyPair();
    const ct = sm2.encrypt(kp.publicKeyPem, new Uint8Array([1, 2, 3]));

    expect(sm2.decrypt(other.privateKeyPem, ct, { safeMode: true })).toBeNull();
    expect(sm2.decrypt(kp.privateKeyPem, ct, { safeMode: true })).toBe('010203');
    // 不开 safeMode 时照旧抛 DecryptionError。
    expect(() => sm2.decrypt(other.privateKeyPem, ct)).toThrow(DecryptionError);
  });

  it('结构错（密文过短）也归入 safeMode', () => {
    const priv = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
    expect(sm2.decrypt(priv, new Uint8Array(10), { safeMode: true })).toBeNull();
  });

  it('safeMode 与 inputFormat 可同时使用', async () => {
    const kp = await sm2.generateKeyPair();
    const msg = new Uint8Array([7, 7]);
    const c123 = sm2.encrypt(kp.publicKeyPem, msg, { outputFormat: 'C1C2C3' });
    expect(sm2.decrypt(kp.privateKeyPem, c123, { inputFormat: 'C1C2C3', safeMode: true })).toBe(
      '0707',
    );
  });
});

describe('sm9.decrypt safeMode', () => {
  beforeAll(async () => {
    await sm9.ensureLoaded();
  });

  it('篡改密文 → null；完好密文 → 明文', async () => {
    const kp = await sm9.generateKeyPair({ id: 'safe@x.io', purpose: 'enc' });
    const ct = sm9.encrypt(kp.masterPrivatePem, 'safe@x.io', new Uint8Array([1, 2, 3]));

    expect(sm9.decrypt(kp.masterPrivatePem, 'safe@x.io', flipHex(ct, 0), { safeMode: true })).toBeNull();
    expect(sm9.decrypt(kp.masterPrivatePem, 'safe@x.io', ct, { safeMode: true })).toBe('010203');
  });
});

describe('sm4.decryptGCM safeMode', () => {
  beforeAll(async () => {
    await sm4.ensureLoaded();
  });

  it('tag 不匹配 → null；匹配 → 明文 hex', () => {
    const key = new Uint8Array(16).fill(1);
    const iv = new Uint8Array(12).fill(2);
    const r = sm4.encryptGCM(key, iv, new Uint8Array([1, 2, 3]));

    expect(sm4.decryptGCM(key, iv, r.ct, flipHex(r.tag, 0), { safeMode: true })).toBeNull();
    expect(sm4.decryptGCM(key, iv, r.ct, r.tag, { safeMode: true })).toBe('010203');
  });

  it('对象形态仍可携带 aad', () => {
    const key = new Uint8Array(16).fill(1);
    const iv = new Uint8Array(12).fill(2);
    const aad = new Uint8Array([4, 5]);
    const r = sm4.encryptGCM(key, iv, new Uint8Array([1, 2, 3]), aad);
    expect(sm4.decryptGCM(key, iv, r.ct, r.tag, { aad, safeMode: true })).toBe('010203');
    expect(sm4.decryptGCM(key, iv, r.ct, r.tag, { aad: new Uint8Array([9]), safeMode: true })).toBeNull();
  });
});

import { describe, it, expect, beforeAll } from 'vitest';
import * as sm2 from '@/sm2';
import * as sm4 from '@/sm4';
import * as sm9 from '@/sm9';
import { DecryptionError, SmCryptoError, isSmCryptoError } from '@/runtime';

/**
 * "校验失败"类错误的类型契约（spec §9 安全姿态、plan Review Focus #4）。
 *
 * 调用方应能用 `catch (e) { if (e instanceof DecryptionError) ... }` 区分
 * "密文/密钥不对" 与 "参数格式错"，而不是去匹配错误消息文本。
 */
const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';

/** 翻转 hex 串第 i 个字符，保持长度不变。 */
function flipHex(s: string, i: number): string {
  return s.slice(0, i) + (s[i] === 'f' ? '0' : 'f') + s.slice(i + 1);
}

describe('DecryptionError 层级', () => {
  it('is a SmCryptoError subclass and recognisable by the type guard', () => {
    const err = new DecryptionError('x');
    expect(err).toBeInstanceOf(SmCryptoError);
    expect(err).toBeInstanceOf(Error);
    expect(isSmCryptoError(err)).toBe(true);
    expect(err.name).toBe('DecryptionError');
  });
});

describe('解密失败抛 DecryptionError', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
    await sm4.ensureLoaded();
    await sm9.ensureLoaded();
  });

  it('sm2.decrypt — tampered C3', () => {
    const pub = sm2.getPublicKey(D);
    const ct = sm2.encrypt(pub, new Uint8Array([1, 2, 3]));
    // 布局：C1(130 hex) || C3(64 hex) || C2 —— 动 C3 的第一个字符。
    const bad = flipHex(ct, 131);
    expect(() => sm2.decrypt(D, bad)).toThrow(DecryptionError);
  });

  it('sm2.decrypt — wrong private key', async () => {
    const other = await sm2.generateKeyPair();
    const ct = sm2.encrypt(sm2.getPublicKey(D), new Uint8Array([1, 2, 3]));
    expect(() => sm2.decrypt(other.privateKeyPem, ct)).toThrow(DecryptionError);
  });

  it('sm4.decryptGCM — tampered tag', () => {
    const key = new Uint8Array(16).fill(1);
    const iv = new Uint8Array(12).fill(2);
    const aad = new Uint8Array([4, 5]);
    const r = sm4.encryptGCM(key, iv, new Uint8Array([1, 2, 3]), aad);
    expect(() => sm4.decryptGCM(key, iv, r.ct, flipHex(r.tag, 0), aad)).toThrow(
      DecryptionError,
    );
  });

  it('sm9.decrypt — tampered ciphertext', async () => {
    const kp = await sm9.generateKeyPair({ id: 'eve@example.com', purpose: 'enc' });
    const ct = sm9.encrypt(kp.masterPrivatePem, 'eve@example.com', new Uint8Array([1, 2, 3]));
    const bad = flipHex(ct, 0);
    expect(() => sm9.decrypt(kp.masterPrivatePem, 'eve@example.com', bad)).toThrow(
      DecryptionError,
    );
  });

  it('facade re-exports DecryptionError for catch blocks', async () => {
    const pkg = await import('@/index');
    expect(pkg.DecryptionError).toBe(DecryptionError);
  });
});

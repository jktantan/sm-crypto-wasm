import { beforeAll, describe, expect, it } from 'vitest';
import {
  CiphertextError,
  DecryptionError,
  InvalidCiphertextError,
  InvalidKeyError,
  InvalidPublicKeyError,
  isSmCryptoError,
  SmCryptoError,
} from '@/runtime';
import * as sm2 from '@/sm2';
import * as sm4 from '@/sm4';
import * as sm9 from '@/sm9';
import * as zuc from '@/zuc';

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
    expect(() => sm4.decryptGCM(key, iv, r.ct, flipHex(r.tag, 0), aad)).toThrow(DecryptionError);
  });

  it('sm9.decrypt — tampered ciphertext', async () => {
    const kp = await sm9.generateKeyPair({ id: 'eve@example.com', purpose: 'enc' });
    const ct = sm9.encrypt(kp.masterPrivatePem, 'eve@example.com', new Uint8Array([1, 2, 3]));
    const bad = flipHex(ct, 0);
    expect(() => sm9.decrypt(kp.masterPrivatePem, 'eve@example.com', bad)).toThrow(DecryptionError);
  });

  it('facade re-exports DecryptionError for catch blocks', async () => {
    const pkg = await import('@/index');
    expect(pkg.DecryptionError).toBe(DecryptionError);
  });
});

/**
 * 错误体系：**所有**库语义错误都是 `SmCryptoError` 的子类，按"用户修复路径"分两支 ——
 * 密钥支（`InvalidKeyError`）与密文支（`CiphertextError`）。
 * 只有"参数根本不是密码学对象"（类型不对、数字越界）才用宿主原生 `TypeError` / `RangeError`。
 */
describe('错误体系（统一为 SmCryptoError 子类）', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
    await sm4.ensureLoaded();
    await sm9.ensureLoaded();
    await zuc.ensureLoaded();
  });

  it('CiphertextError 是密文支的基类，覆盖结构错与校验失败', () => {
    expect(new InvalidCiphertextError('x')).toBeInstanceOf(CiphertextError);
    expect(new DecryptionError('x')).toBeInstanceOf(CiphertextError);
    expect(new InvalidCiphertextError('x')).toBeInstanceOf(SmCryptoError);
    expect(new DecryptionError('x')).toBeInstanceOf(SmCryptoError);
    expect(new CiphertextError('x')).toBeInstanceOf(SmCryptoError);
  });

  it('InvalidPublicKeyError 仍是 InvalidKeyError 的子类', () => {
    expect(new InvalidPublicKeyError('x')).toBeInstanceOf(InvalidKeyError);
    expect(new InvalidKeyError('x')).toBeInstanceOf(SmCryptoError);
  });

  it('sm2: 短密文 / 错长度签名 → InvalidCiphertextError', () => {
    expect(() => sm2.decrypt(D, new Uint8Array(10))).toThrow(InvalidCiphertextError);
    const pub = sm2.getPublicKey(D);
    expect(() => sm2.verify(pub, new Uint8Array([1]), new Uint8Array(10))).toThrow(
      InvalidCiphertextError,
    );
  });

  it('sm2: 私钥 / 公钥长度错 → InvalidKeyError', () => {
    expect(() => sm2.sign(new Uint8Array(10), new Uint8Array([1]))).toThrow(InvalidKeyError);
    expect(() => sm2.getPublicKey(new Uint8Array(10))).toThrow(InvalidKeyError);
    expect(() => sm2.encrypt(new Uint8Array(10), new Uint8Array([1]))).toThrow(InvalidKeyError);
  });

  it('sm4: key/iv 长度错 → InvalidKeyError；tag 长度错 → InvalidCiphertextError', () => {
    expect(() => sm4.encryptECB(new Uint8Array(10), new Uint8Array(16))).toThrow(InvalidKeyError);
    expect(() =>
      sm4.decryptGCM(new Uint8Array(16), new Uint8Array(12), new Uint8Array(0), new Uint8Array(8)),
    ).toThrow(InvalidCiphertextError);
  });

  it('zuc: key/iv 长度错 → InvalidKeyError', () => {
    expect(() => zuc.zucKeystream(new Uint8Array(10), new Uint8Array(16), 4)).toThrow(
      InvalidKeyError,
    );
    expect(() => zuc.zucKeystream(new Uint8Array(16), new Uint8Array(9), 4)).toThrow(
      InvalidKeyError,
    );
  });

  it('sm9: 主私钥长度错 → InvalidKeyError；密文过短 → InvalidCiphertextError', () => {
    expect(() => sm9.sign(new Uint8Array(10), 'alice', new Uint8Array([1]))).toThrow(
      InvalidKeyError,
    );
    // 主私钥用合法标量（k = 1，范围校验要求 1 ≤ k ≤ n−1），以便走到密文长度校验
    const ks = new Uint8Array(32);
    ks[31] = 1;
    expect(() => sm9.decrypt(ks, 'alice', new Uint8Array(10))).toThrow(InvalidCiphertextError);
  });

  it('普通参数仍然用宿主原生类型（TypeError / RangeError）', () => {
    expect(() => sm2.encrypt(sm2.getPublicKey(D), 'x', { outputFormat: 'nope' as never })).toThrow(
      RangeError,
    );
    expect(() =>
      zuc.zucMac(new Uint8Array(16), new Uint8Array(16), new Uint8Array([1]), 8, 64),
    ).toThrow(RangeError);
  });
});

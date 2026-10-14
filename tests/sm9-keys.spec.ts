import { describe, it, expect, beforeAll } from 'vitest';
import * as sm9 from '@/sm9';
import * as pkg from '@/index';
import {
  SM9_OID,
  encodeSm9PrivateKeyPem,
  parseSm9PrivateKeyPem,
  encodeSm9PublicKeyPem,
  parseSm9PublicKeyPem,
  encodePkcs8PrivateKey,
} from '@/pem';
import { InvalidKeyError } from '@/runtime';

/**
 * SM9 密钥的 PKCS#8 / SPKI 编码（spec §12.1 Q3，OID 1.2.156.10197.1.100）
 * 与 facade 导出。
 */
describe('SM9 key encoding + facade', () => {
  it('facade exposes the sm9 namespace', () => {
    expect(pkg.sm9).toBeDefined();
    expect(typeof pkg.sm9?.generateKeyPair).toBe('function');
    expect(typeof pkg.sm9?.sign).toBe('function');
    expect(typeof pkg.sm9?.verify).toBe('function');
    expect(typeof pkg.sm9?.encrypt).toBe('function');
    expect(typeof pkg.sm9?.decrypt).toBe('function');
  });

  it('private key PEM round-trips under the SM9 OID', () => {
    const priv = new Uint8Array(32).fill(0xab);
    const pem = encodeSm9PrivateKeyPem(priv);
    expect(pem).toContain('BEGIN PRIVATE KEY');
    expect(parseSm9PrivateKeyPem(pem)).toEqual(priv);
  });

  it('public key PEM round-trips under the SM9 OID', () => {
    const pub = new Uint8Array(128).fill(0xcd);
    const pem = encodeSm9PublicKeyPem(pub);
    expect(pem).toContain('BEGIN PUBLIC KEY');
    expect(parseSm9PublicKeyPem(pem)).toEqual(pub);
  });

  it('rejects a PEM whose algorithm OID is not SM9', () => {
    const foreign = encodePkcs8PrivateKey('1.2.156.10197.1.301', new Uint8Array(32));
    expect(() => parseSm9PrivateKeyPem(foreign)).toThrow(InvalidKeyError);
  });

  it('SM9_OID is the custom SM9 algorithm OID', () => {
    expect(SM9_OID).toBe('1.2.156.10197.1.100');
  });
});

describe('SM9 generateKeyPair', () => {
  beforeAll(async () => {
    await sm9.ensureLoaded();
  });

  it('produces PEM master + user keys for the sign purpose', async () => {
    const kp = await sm9.generateKeyPair({ id: 'alice@foo.com' });
    expect(kp.masterPrivatePem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(kp.masterPublicPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(kp.userPrivatePem).toMatch(/^-----BEGIN PRIVATE KEY-----/);

    // 主私钥 32 字节；签名主公钥是 G2 点 128 字节；用户签名私钥是 G1 点 64 字节。
    expect(parseSm9PrivateKeyPem(kp.masterPrivatePem).length).toBe(32);
    expect(parseSm9PublicKeyPem(kp.masterPublicPem).length).toBe(128);
    expect(parseSm9PrivateKeyPem(kp.userPrivatePem).length).toBe(64);
  });

  it('produces G1 master public key for the enc purpose', async () => {
    const kp = await sm9.generateKeyPair({ id: 'bob@bar.com', purpose: 'enc' });
    expect(parseSm9PublicKeyPem(kp.masterPublicPem).length).toBe(64);
    expect(parseSm9PrivateKeyPem(kp.userPrivatePem).length).toBe(128);
  });

  it('sign/verify accept PEM master private keys', async () => {
    const kp = await sm9.generateKeyPair({ id: 'carol@x.io' });
    const msg = new Uint8Array([1, 2, 3]);
    const sig = sm9.sign(kp.masterPrivatePem, 'carol@x.io', msg);
    expect(sm9.verify(kp.masterPrivatePem, 'carol@x.io', msg, sig)).toBe(true);
  });

  it('id 里出现 "-----BEGIN" 不会被误当成 PEM 私钥（PEM 解析只服务于密钥参数）', async () => {
    const kp = await sm9.generateKeyPair({ id: 'dave@x.io' });
    const weirdId = 'dave-----BEGIN-not-a-key';
    const msg = new Uint8Array([1, 2, 3]);
    const sig = sm9.sign(kp.masterPrivatePem, weirdId, msg);
    expect(sm9.verify(kp.masterPrivatePem, weirdId, msg, sig)).toBe(true);
  });
});

/**
 * 主公钥形态：`verify` / `encrypt` 的密钥参数既接受主私钥（沿用旧形态），
 * 也接受主公钥（PEM 或点字节）—— 后者是 spec §6 里写的那一种。
 */
describe('SM9 主公钥支持', () => {
  beforeAll(async () => {
    await sm9.ensureLoaded();
  });

  it('verify 接受主公钥 PEM 与点字节，结果与主私钥一致', async () => {
    const kp = await sm9.generateKeyPair({ id: 'alice@foo.com' });
    const msg = new Uint8Array([1, 2, 3]);
    const sig = sm9.sign(kp.masterPrivatePem, 'alice@foo.com', msg);

    expect(sm9.verify(kp.masterPublicPem, 'alice@foo.com', msg, sig)).toBe(true);
    expect(
      sm9.verify(parseSm9PublicKeyPem(kp.masterPublicPem), 'alice@foo.com', msg, sig),
    ).toBe(true);
  });

  it('verify 用别的密钥对的主公钥返回 false', async () => {
    const a = await sm9.generateKeyPair({ id: 'same@x.io' });
    const b = await sm9.generateKeyPair({ id: 'same@x.io' });
    const msg = new Uint8Array([1]);
    const sig = sm9.sign(a.masterPrivatePem, 'same@x.io', msg);
    expect(sm9.verify(b.masterPublicPem, 'same@x.io', msg, sig)).toBe(false);
  });

  it('encrypt 接受加密主公钥 PEM', async () => {
    const kp = await sm9.generateKeyPair({ id: 'bob@bar.com', purpose: 'enc' });
    const ct = sm9.encrypt(kp.masterPublicPem, 'bob@bar.com', new Uint8Array([9, 9]));
    expect(sm9.decrypt(kp.masterPrivatePem, 'bob@bar.com', ct)).toBe('0909');
  });

  it('generateKeyPair 产出 userPublicPem（签名 G2 128B / 加密 G1 64B）', async () => {
    const signKp = await sm9.generateKeyPair({ id: 'carol@x.io' });
    expect(parseSm9PublicKeyPem(signKp.userPublicPem).length).toBe(128);

    const encKp = await sm9.generateKeyPair({ id: 'carol@x.io', purpose: 'enc' });
    expect(parseSm9PublicKeyPem(encKp.userPublicPem).length).toBe(64);
  });

  it('用户公钥可由第三方从 (id, 主公钥) 复算', async () => {
    const kp = await sm9.generateKeyPair({ id: 'erin@x.io', purpose: 'enc' });
    expect(sm9.getUserPublicKey(kp.masterPublicPem, 'erin@x.io')).toBe(kp.userPublicPem);
  });
});

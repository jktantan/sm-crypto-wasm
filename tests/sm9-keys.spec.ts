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
});

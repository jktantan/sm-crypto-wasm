import { describe, it, expect, beforeAll } from 'vitest';
import { sm2GetPublicKeyFromPrivateKey, sm2Encrypt } from 'gmkitx';
import { encodeSm2PrivateKeyPem, encodeSm2PublicKeyPem } from '@/pem';
import * as sm2 from '@/sm2';

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const MSG = 'hello sm2 interop';

describe('SM2 vs gmkitx oracle', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('public key derivation matches oracle', () => {
    const ours = sm2.getPublicKey(D);
    const ref = String(sm2GetPublicKeyFromPrivateKey(D, false)).toLowerCase();
    // oracle 带 04 前缀。
    expect('04' + ours).toBe(ref);
  });

  it('our signature verifies under ourselves', () => {
    const pub = sm2.getPublicKey(D);
    const sig = sm2.sign(D, MSG);
    expect(sm2.verify(pub, MSG, sig)).toBe(true);
  });

  it('tampered signature fails', () => {
    const pub = sm2.getPublicKey(D);
    const sig = sm2.sign(D, MSG);
    const bad = (sig.slice(0, -2) + (sig.endsWith('ff') ? '00' : 'ff'));
    expect(sm2.verify(pub, MSG, bad)).toBe(false);
  });

  it('oracle-encrypted ciphertext decrypts with our impl', () => {
    const pub = '04' + sm2.getPublicKey(D);
    const ct = String(sm2Encrypt(pub, Buffer.from(MSG, 'utf8'))).toLowerCase();
    const pt = sm2.decrypt(D, ct);
    expect(Buffer.from(pt, 'hex').toString('utf8')).toBe(MSG);
  });

  it('encrypt/decrypt round-trips', () => {
    const pub = sm2.getPublicKey(D);
    const ct = sm2.encrypt(pub, Buffer.from(MSG, 'utf8'));
    const pt = sm2.decrypt(D, ct);
    expect(Buffer.from(pt, 'hex').toString('utf8')).toBe(MSG);
  });

  it('accepts PEM key inputs across the API', () => {
    const pub = sm2.getPublicKey(D);
    const privPem = encodeSm2PrivateKeyPem(D, pub);
    const pubPem = encodeSm2PublicKeyPem(pub);

    // getPublicKey：PEM 私钥与 hex 私钥结果一致。
    expect(sm2.getPublicKey(privPem)).toBe(pub);

    // sign(PEM) → verify(PEM / 裸 hex)。
    const sig = sm2.sign(privPem, MSG);
    expect(sm2.verify(pubPem, MSG, sig)).toBe(true);
    expect(sm2.verify('04' + pub, MSG, sig)).toBe(true);

    // encrypt(PEM 公钥) → decrypt(PEM 私钥)。
    const ct = sm2.encrypt(pubPem, Buffer.from(MSG, 'utf8'));
    const pt = sm2.decrypt(privPem, ct);
    expect(Buffer.from(pt, 'hex').toString('utf8')).toBe(MSG);
  });
});

describe('SM2 key generation & ciphertext ordering', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('generateKeyPair returns a self-consistent PEM key pair', async () => {
    const kp = await sm2.generateKeyPair();
    expect(kp.privateKeyPem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(kp.publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);

    const sig = sm2.sign(kp.privateKeyPem, MSG);
    expect(sm2.verify(kp.publicKeyPem, MSG, sig)).toBe(true);

    const ct = sm2.encrypt(kp.publicKeyPem, Buffer.from(MSG, 'utf8'));
    expect(Buffer.from(sm2.decrypt(kp.privateKeyPem, ct), 'hex').toString('utf8')).toBe(MSG);
  });

  it('generateKeyPair produces a different key pair each call', async () => {
    const [a, b] = await Promise.all([sm2.generateKeyPair(), sm2.generateKeyPair()]);
    expect(a.privateKeyPem).not.toBe(b.privateKeyPem);
    expect(a.publicKeyPem).not.toBe(b.publicKeyPem);
  });

  it('encrypt defaults to C1C3C2 and C1C2C3 only reorders C2/C3', () => {
    const pub = sm2.getPublicKey(D);
    const msg = new Uint8Array([9, 8, 7]);

    // 用同一份密文手工重排，避免两次加密的随机 k 让结果不可比。
    const c132 = Buffer.from(sm2.encrypt(pub, msg), 'hex');
    const n = c132.length - 97;
    const reordered = Buffer.concat([
      c132.subarray(0, 65),
      c132.subarray(97, 97 + n),
      c132.subarray(65, 97),
    ]).toString('hex');

    expect(reordered.length).toBe(c132.length * 2);
    expect(reordered).not.toBe(c132.toString('hex'));

    // 两种顺序都解出同一明文（C1C2C3 走自动识别）。
    expect(Buffer.from(sm2.decrypt(D, c132.toString('hex')), 'hex')).toEqual(Buffer.from(msg));
    expect(Buffer.from(sm2.decrypt(D, reordered), 'hex')).toEqual(Buffer.from(msg));

    // 显式 outputFormat 产出的密文同样能解。
    const c123 = sm2.encrypt(pub, msg, { outputFormat: 'C1C2C3' });
    expect(c123.length).toBe(c132.length * 2);
    expect(Buffer.from(sm2.decrypt(D, c123), 'hex')).toEqual(Buffer.from(msg));
  });

  it('decrypt auto-detects a C1C2C3 ciphertext', () => {
    const pub = sm2.getPublicKey(D);
    const msg = new Uint8Array(Buffer.from(MSG, 'utf8'));
    const c123 = sm2.encrypt(pub, msg, { outputFormat: 'C1C2C3' });
    expect(Buffer.from(sm2.decrypt(D, c123), 'hex').toString('utf8')).toBe(MSG);
  });

  it('both orderings decrypt to the same plaintext', () => {
    const pub = sm2.getPublicKey(D);
    const msg = new Uint8Array(Buffer.from('ordering matters', 'utf8'));
    const c132 = sm2.encrypt(pub, msg);
    const c123 = sm2.encrypt(pub, msg, { outputFormat: 'C1C2C3' });
    expect(sm2.decrypt(D, c132)).toBe(sm2.decrypt(D, c123));
    expect(Buffer.from(sm2.decrypt(D, c132), 'hex').toString('utf8')).toBe('ordering matters');
  });
});
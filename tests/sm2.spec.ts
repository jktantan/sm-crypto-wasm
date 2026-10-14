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
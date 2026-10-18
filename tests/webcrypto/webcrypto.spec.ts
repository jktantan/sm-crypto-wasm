/**
 * WebCrypto 适配层测试（阶段 4）。
 *
 * 覆盖：SM3 digest、HMAC、SM4 六种模式、SM2 签名/验签、密钥导入导出、
 * extractable / usages / 未知算法错误映射，以及与底层 API 的互操作。
 */
import { describe, expect, it } from 'vitest';
import { parseSm2PrivateKeyDer, parseSm2PublicKeyDer } from '@/pem/sm2';
import { bytesToHex, hexToBytes } from '@/runtime';
import * as sm2 from '@/sm2';
import * as sm3 from '@/sm3';
import * as sm4 from '@/sm4';
import type { SmCryptoKeyPair } from '@/webcrypto';
import { type CryptoKey, subtle } from '@/webcrypto';

const MSG = new TextEncoder().encode('hello 国密 webcrypto');
const OTHER = new TextEncoder().encode('hello 国密 webcrypto!');

describe('digest (SM3)', () => {
  it('matches sm3.hash', async () => {
    const digest = new Uint8Array(await subtle.digest('SM3', MSG));
    expect(digest.length).toBe(32);
    expect(bytesToHex(digest)).toBe(sm3.hash(MSG));
  });

  it('accepts algorithm names case-insensitively', async () => {
    const a = new Uint8Array(await subtle.digest('sm3', MSG));
    const b = new Uint8Array(await subtle.digest({ name: 'sm3' }, MSG));
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it('rejects unsupported digests with NotSupportedError', async () => {
    await expect(subtle.digest('SHA-256', MSG)).rejects.toMatchObject({
      name: 'NotSupportedError',
    });
  });
});

describe('HMAC (SM3)', () => {
  const keyBytes = new Uint8Array(32).fill(0x42);

  it('imports raw keys and matches sm3.hmac', async () => {
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SM3' }, true, [
      'sign',
      'verify',
    ]);
    const mac = new Uint8Array(await subtle.sign({ name: 'HMAC' }, key, MSG));
    expect(bytesToHex(mac)).toBe(sm3.hmac(keyBytes, MSG));
    expect(await subtle.verify({ name: 'HMAC' }, key, mac, MSG)).toBe(true);
    expect(await subtle.verify({ name: 'HMAC' }, key, mac, OTHER)).toBe(false);
  });

  it('generates HMAC keys', async () => {
    const key = (await subtle.generateKey({ name: 'HMAC', hash: 'SM3', length: 256 }, true, [
      'sign',
      'verify',
    ])) as CryptoKey;
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('HMAC');
    expect((key.algorithm.hash as { name: string }).name).toBe('SM3');
    expect(new Uint8Array(await subtle.exportKey('raw', key)).length).toBe(32);
  });

  it('enforces usages', async () => {
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SM3' }, true, [
      'verify',
    ]);
    await expect(subtle.sign({ name: 'HMAC' }, key, MSG)).rejects.toMatchObject({
      name: 'InvalidAccessError',
    });
  });
});

describe('SM4 modes', () => {
  const keyBytes = hexToBytes('0123456789abcdeffedcba9876543210');
  const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const aad = new TextEncoder().encode('aad');

  async function importSm4(name: string, usages: string[] = ['encrypt', 'decrypt']) {
    return subtle.importKey('raw', keyBytes, { name }, true, usages);
  }

  it('SM4-GCM encrypts to ciphertext || tag and decrypts', async () => {
    const key = await importSm4('SM4-GCM');
    const ct = new Uint8Array(
      await subtle.encrypt({ name: 'SM4-GCM', iv, additionalData: aad }, key, MSG),
    );
    const expected = sm4.encryptGCM(keyBytes, iv, MSG, aad);
    expect(bytesToHex(ct)).toBe(expected.ct + expected.tag);

    const plain = new Uint8Array(
      await subtle.decrypt({ name: 'SM4-GCM', iv, additionalData: aad }, key, ct),
    );
    expect(plain).toEqual(MSG);

    // tag 被篡改 → OperationError
    const tampered = new Uint8Array(ct);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 0x01;
    await expect(
      subtle.decrypt({ name: 'SM4-GCM', iv, additionalData: aad }, key, tampered),
    ).rejects.toMatchObject({ name: 'OperationError' });
  });

  it('SM4-GCM only supports a 128-bit tag', async () => {
    const key = await importSm4('SM4-GCM');
    await expect(
      subtle.encrypt({ name: 'SM4-GCM', iv, tagLength: 96 }, key, MSG),
    ).rejects.toMatchObject({ name: 'NotSupportedError' });
  });

  it('SM4-CBC matches encryptCBC/decryptCBC', async () => {
    const key = await importSm4('SM4-CBC');
    const ct = new Uint8Array(await subtle.encrypt({ name: 'SM4-CBC', iv }, key, MSG));
    expect(bytesToHex(ct)).toBe(sm4.encryptCBC(keyBytes, iv, MSG));
    const plain = new Uint8Array(await subtle.decrypt({ name: 'SM4-CBC', iv }, key, ct));
    expect(plain).toEqual(MSG);
  });

  it('SM4-CTR matches cryptCTR and only supports 128-bit counters', async () => {
    const key = await importSm4('SM4-CTR');
    const ct = new Uint8Array(await subtle.encrypt({ name: 'SM4-CTR', iv, length: 128 }, key, MSG));
    expect(bytesToHex(ct)).toBe(sm4.cryptCTR(keyBytes, iv, MSG));
    const plain = new Uint8Array(
      await subtle.decrypt({ name: 'SM4-CTR', iv, length: 128 }, key, ct),
    );
    expect(plain).toEqual(MSG);
    await expect(
      subtle.encrypt({ name: 'SM4-CTR', iv, length: 64 }, key, MSG),
    ).rejects.toMatchObject({ name: 'NotSupportedError' });
  });

  it('SM4-ECB matches encryptECB/decryptECB', async () => {
    const key = await importSm4('SM4-ECB');
    const data = new Uint8Array(32).fill(0x5a);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'SM4-ECB' }, key, data));
    expect(bytesToHex(ct)).toBe(sm4.encryptECB(keyBytes, data));
    const plain = new Uint8Array(await subtle.decrypt({ name: 'SM4-ECB' }, key, ct));
    expect(plain).toEqual(data);
  });

  it('SM4-CFB / SM4-OFB match the primitives', async () => {
    const cfbKey = await importSm4('SM4-CFB');
    const cfb = new Uint8Array(await subtle.encrypt({ name: 'SM4-CFB', iv }, cfbKey, MSG));
    expect(bytesToHex(cfb)).toBe(sm4.encryptCFB(keyBytes, iv, MSG));
    expect(new Uint8Array(await subtle.decrypt({ name: 'SM4-CFB', iv }, cfbKey, cfb))).toEqual(MSG);

    const ofbKey = await importSm4('SM4-OFB');
    const ofb = new Uint8Array(await subtle.encrypt({ name: 'SM4-OFB', iv }, ofbKey, MSG));
    expect(bytesToHex(ofb)).toBe(sm4.cryptOFB(keyBytes, iv, MSG));
    expect(new Uint8Array(await subtle.decrypt({ name: 'SM4-OFB', iv }, ofbKey, ofb))).toEqual(MSG);
  });

  it('generates 128-bit SM4 keys', async () => {
    const key = (await subtle.generateKey({ name: 'SM4-GCM', length: 128 }, false, [
      'encrypt',
      'decrypt',
    ])) as CryptoKey;
    expect(key.type).toBe('secret');
    expect(key.algorithm).toMatchObject({ name: 'SM4-GCM', length: 128 });
    await expect(subtle.exportKey('raw', key)).rejects.toMatchObject({
      name: 'InvalidAccessError',
    });
  });

  it('rejects non-16-byte raw keys and incompatible usages', async () => {
    await expect(
      subtle.importKey('raw', new Uint8Array(15), { name: 'SM4-CBC' }, true, ['encrypt']),
    ).rejects.toMatchObject({ name: 'DataError' });
    await expect(
      subtle.importKey('raw', keyBytes, { name: 'SM4-CBC' }, true, ['sign']),
    ).rejects.toMatchObject({ name: 'SyntaxError' });
  });
});

describe('SM2', () => {
  it('generates, signs, verifies and interoperates with sm2.sign/verify', async () => {
    const pair = (await subtle.generateKey({ name: 'SM2' }, true, [
      'sign',
      'verify',
      'encrypt',
      'decrypt',
    ])) as SmCryptoKeyPair;
    expect(pair.privateKey.type).toBe('private');
    expect(pair.publicKey.type).toBe('public');
    expect(pair.privateKey.usages).toEqual(['sign', 'decrypt']);
    expect(pair.publicKey.usages).toEqual(['verify', 'encrypt']);

    const signature = new Uint8Array(await subtle.sign({ name: 'SM2' }, pair.privateKey, MSG));
    expect(signature.length).toBe(64);
    expect(await subtle.verify({ name: 'SM2' }, pair.publicKey, signature, MSG)).toBe(true);
    expect(await subtle.verify({ name: 'SM2' }, pair.publicKey, signature, OTHER)).toBe(false);

    // webcrypto 签名 → 底层 sm2.verify
    const privateDer = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
    const privateKey = parseSm2PrivateKeyDer(privateDer);
    expect(sm2.verify(sm2.getPublicKey(privateKey), MSG, signature)).toBe(true);

    // 底层 sm2.sign → webcrypto verify
    const backendSignature = hexToBytes(sm2.sign(privateKey, MSG));
    expect(await subtle.verify({ name: 'SM2' }, pair.publicKey, backendSignature, MSG)).toBe(true);
  });

  it('imports and exports pkcs8 / spki', async () => {
    const pair = (await subtle.generateKey({ name: 'SM2' }, true, [
      'sign',
      'verify',
    ])) as SmCryptoKeyPair;
    const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
    const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
    expect(parseSm2PrivateKeyDer(pkcs8).length).toBe(32);
    expect(parseSm2PublicKeyDer(spki).length).toBe(65);

    const importedPrivate = await subtle.importKey('pkcs8', pkcs8, { name: 'SM2' }, true, ['sign']);
    const importedPublic = await subtle.importKey('spki', spki, { name: 'SM2' }, true, ['verify']);
    const signature = new Uint8Array(await subtle.sign({ name: 'SM2' }, importedPrivate, MSG));
    expect(await subtle.verify({ name: 'SM2' }, importedPublic, signature, MSG)).toBe(true);
  });

  it('supports a custom user id', async () => {
    const pair = (await subtle.generateKey({ name: 'SM2' }, true, [
      'sign',
      'verify',
    ])) as SmCryptoKeyPair;
    const userID = new TextEncoder().encode('custom-user-id');
    const signature = new Uint8Array(
      await subtle.sign({ name: 'SM2', userID }, pair.privateKey, MSG),
    );
    expect(await subtle.verify({ name: 'SM2', userID }, pair.publicKey, signature, MSG)).toBe(true);
    expect(await subtle.verify({ name: 'SM2' }, pair.publicKey, signature, MSG)).toBe(false);
  });

  it('enforces extractable and usages', async () => {
    const pair = (await subtle.generateKey({ name: 'SM2' }, false, [
      'sign',
      'verify',
    ])) as SmCryptoKeyPair;
    await expect(subtle.exportKey('pkcs8', pair.privateKey)).rejects.toMatchObject({
      name: 'InvalidAccessError',
    });

    const verifyOnly = (await subtle.generateKey({ name: 'SM2' }, true, [
      'verify',
    ])) as SmCryptoKeyPair;
    await expect(subtle.sign({ name: 'SM2' }, verifyOnly.privateKey, MSG)).rejects.toMatchObject({
      name: 'InvalidAccessError',
    });
    await expect(
      subtle.verify({ name: 'SM2' }, verifyOnly.privateKey, new Uint8Array(64), MSG),
    ).rejects.toMatchObject({ name: 'InvalidAccessError' });

    const encryptOnly = (await subtle.generateKey({ name: 'SM2' }, true, [
      'encrypt',
    ])) as SmCryptoKeyPair;
    expect(encryptOnly.publicKey.usages).toEqual(['encrypt']);
    expect(encryptOnly.privateKey.usages).toEqual([]);
  });

  it('rejects unsupported key formats', async () => {
    await expect(
      subtle.importKey('jwk', {}, { name: 'SM2' }, true, ['sign']),
    ).rejects.toMatchObject({ name: 'NotSupportedError' });
  });
});

describe('error mapping', () => {
  it('maps invalid SM4-CBC padding to OperationError', async () => {
    const keyBytes = new Uint8Array(16).fill(0x11);
    const key = await subtle.importKey('raw', keyBytes, { name: 'SM4-CBC' }, true, ['decrypt']);
    const iv = new Uint8Array(16);
    const bogus = new Uint8Array(16).fill(0);
    await expect(subtle.decrypt({ name: 'SM4-CBC', iv }, key, bogus)).rejects.toMatchObject({
      name: 'OperationError',
    });
  });

  it('uses the key algorithm, not the requested one', async () => {
    const keyBytes = new Uint8Array(16).fill(0x22);
    const key = await subtle.importKey('raw', keyBytes, { name: 'SM4-CBC' }, true, ['encrypt']);
    const iv = new Uint8Array(16);
    await expect(subtle.encrypt({ name: 'SM4-CTR', iv }, key, MSG)).rejects.toMatchObject({
      name: 'InvalidAccessError',
    });
  });

  it('requires an IV', async () => {
    const keyBytes = new Uint8Array(16).fill(0x33);
    const key = await subtle.importKey('raw', keyBytes, { name: 'SM4-CBC' }, true, ['encrypt']);
    await expect(subtle.encrypt({ name: 'SM4-CBC' }, key, MSG)).rejects.toMatchObject({
      name: 'DataError',
    });
  });
});

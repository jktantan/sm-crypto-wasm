/**
 * CMS SignedData 测试（阶段 3）。
 *
 * 覆盖：detached / attached、原始 signedAttrs 验签、篡改检测、
 * 证书缺失、GM/T 用户标识，以及与 OpenSSL 的双向互操作。
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { explicit, oid, parseBer, seq } from '@/asn1';
import { parseSignedData, signData, verifySignedData } from '@/cms';
import { OID_CMS_SIGNED_DATA } from '@/cms/oids';
import * as sm2 from '@/sm2';
import * as sm3 from '@/sm3';
import { DEFAULT_SM2_USER_ID } from '@/x509';

const VECTOR_DIR = new URL('../vectors/x509/', import.meta.url);
const CMS_VECTOR_DIR = new URL('../vectors/cms/', import.meta.url);

function readPem(name: string): string {
  return readFileSync(new URL(name, VECTOR_DIR), 'utf8');
}

function hasOpenSsl(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * 探测 OpenSSL 是否支持用 SM2 私钥生成 CMS 签名。
 *
 * Ubuntu CI 自带的 OpenSSL 3.0.x 会报
 * `cms_sd_asn1_ctrl:not supported for this key type`；这类环境只跳过
 * 动态互操作用例，固定 DER 向量仍由本库验签。
 */
function hasOpenSslCmsSm2(): boolean {
  let dir: string | undefined;
  try {
    dir = mkdtempSync(join(tmpdir(), 'sm-crypto-cms-probe-'));
    const dataPath = join(dir, 'data.bin');
    const certPath = join(dir, 'cert.pem');
    const keyPath = join(dir, 'key.pem');
    writeFileSync(dataPath, Buffer.from(DATA));
    writeFileSync(certPath, CERT_PEM);
    writeFileSync(keyPath, KEY_PEM);
    execFileSync(
      'openssl',
      [
        'cms',
        '-sign',
        '-in',
        dataPath,
        '-signer',
        certPath,
        '-inkey',
        keyPath,
        '-outform',
        'DER',
        '-md',
        'sm3',
        '-binary',
        '-nodetach',
        '-out',
        join(dir, 'probe.der'),
      ],
      { stdio: 'ignore' },
    );
    return true;
  } catch {
    return false;
  } finally {
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  }
}

const CERT_PEM = readPem('root-ca.pem');
const KEY_PEM = readPem('root-ca.key');
const DATA = new TextEncoder().encode('hello 国密 CMS');

beforeAll(async () => {
  await sm2.ensureLoaded();
  await sm3.ensureLoaded();
});

describe('fixed OpenSSL vectors', () => {
  it('verifies attached, detached and BER indefinite-length samples', () => {
    const data = new Uint8Array(readFileSync(new URL('data.bin', CMS_VECTOR_DIR)));
    const dataBer = new Uint8Array(readFileSync(new URL('data-ber.bin', CMS_VECTOR_DIR)));
    const attached = new Uint8Array(readFileSync(new URL('ossl-attached.der', CMS_VECTOR_DIR)));
    const detached = new Uint8Array(readFileSync(new URL('ossl-detached.der', CMS_VECTOR_DIR)));
    const ber = new Uint8Array(readFileSync(new URL('ossl-ber-indefinite.der', CMS_VECTOR_DIR)));

    expect(verifySignedData(attached).valid).toBe(true);
    expect(verifySignedData(detached, { detachedData: data }).valid).toBe(true);
    expect(verifySignedData(ber, { detachedData: dataBer }).valid).toBe(true);

    // BER 样本的外层确实是 indefinite-length。
    expect(ber[0]).toBe(0x30);
    expect(ber[1]).toBe(0x80);
    expect(parseSignedData(ber).signerInfos[0]?.signedAttrs?.raw[0]).toBe(0x31);
  });
});

describe('signData / verifySignedData', () => {
  it('round-trips a detached signature', () => {
    const signed = signData({
      data: DATA,
      privateKey: KEY_PEM,
      certificate: CERT_PEM,
    });
    expect(signed.der.length).toBeGreaterThan(100);
    expect(signed.pem).toContain('-----BEGIN CMS-----');
    expect(signed.base64.length).toBeGreaterThan(0);

    const result = verifySignedData(signed.der, { detachedData: DATA });
    expect(result.valid).toBe(true);
    expect(result.signers).toHaveLength(1);
    expect(result.signers[0]?.valid).toBe(true);
    expect(result.signers[0]?.certificate?.subject.commonName).toBe('SM Crypto Root CA');
    expect(result.signers[0]?.signingTime).toBeInstanceOf(Date);
  });

  it('round-trips an attached signature without detachedData', () => {
    const signed = signData({
      data: DATA,
      privateKey: KEY_PEM,
      certificate: CERT_PEM,
      detached: false,
    });
    const parsed = parseSignedData(signed.der);
    expect(parsed.eContent).toEqual(DATA);
    expect(parsed.certificates).toHaveLength(1);
    expect(parsed.signerInfos[0]?.signedAttrs?.attributes.map((a) => a.oid)).toContain(
      '1.2.840.113549.1.9.4',
    );

    const result = verifySignedData(signed.der);
    expect(result.valid).toBe(true);
  });

  it('accepts PEM and base64 inputs', () => {
    const signed = signData({ data: 'text', privateKey: KEY_PEM, certificate: CERT_PEM });
    expect(verifySignedData(signed.pem, { detachedData: 'text' }).valid).toBe(true);
    expect(verifySignedData(signed.base64, { detachedData: 'text' }).valid).toBe(true);
  });

  it('keeps signingTime optional', () => {
    const signed = signData({
      data: DATA,
      privateKey: KEY_PEM,
      certificate: CERT_PEM,
      signingTime: false,
    });
    const result = verifySignedData(signed.der, { detachedData: DATA });
    expect(result.valid).toBe(true);
    expect(result.signers[0]?.signingTime).toBeUndefined();
  });

  it('detects a modified detached payload (DIGEST_MISMATCH)', () => {
    const signed = signData({ data: DATA, privateKey: KEY_PEM, certificate: CERT_PEM });
    const result = verifySignedData(signed.der, {
      detachedData: new TextEncoder().encode('hello 国密 CMS!'),
    });
    expect(result.valid).toBe(false);
    expect(result.signers[0]?.errorCode).toBe('DIGEST_MISMATCH');
    expect(result.signers[0]?.error).toBeTruthy();
  });

  it('detects a modified signature (SIGNATURE_INVALID)', () => {
    const signed = signData({ data: DATA, privateKey: KEY_PEM, certificate: CERT_PEM });
    const tampered = new Uint8Array(signed.der);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] as number) ^ 0x01;
    const result = verifySignedData(tampered, { detachedData: DATA });
    expect(result.valid).toBe(false);
    expect(result.signers[0]?.errorCode).toBe('SIGNATURE_INVALID');
  });

  it('reports NO_CERTIFICATE when the signer certificate is absent', () => {
    const signed = signData({ data: DATA, privateKey: KEY_PEM, certificate: CERT_PEM });
    const withoutCertificates = stripCertificates(signed.der);
    const result = verifySignedData(withoutCertificates, { detachedData: DATA });
    expect(result.valid).toBe(false);
    expect(result.signers[0]?.errorCode).toBe('NO_CERTIFICATE');

    // 调用方补上证书后可以通过。
    const withProvided = verifySignedData(withoutCertificates, {
      detachedData: DATA,
      certificates: [CERT_PEM],
    });
    expect(withProvided.valid).toBe(true);
  });

  it('returns MALFORMED instead of throwing for garbage input', () => {
    const result = verifySignedData(new Uint8Array([0x30, 0x01, 0x00]));
    expect(result.valid).toBe(false);
    expect(result.signers[0]?.errorCode).toBe('MALFORMED');
  });

  it('supports an explicit GM/T user id', () => {
    const signed = signData({
      data: DATA,
      privateKey: KEY_PEM,
      certificate: CERT_PEM,
      userID: DEFAULT_SM2_USER_ID,
    });
    expect(verifySignedData(signed.der, { detachedData: DATA }).valid).toBe(true);
    expect(
      verifySignedData(signed.der, {
        detachedData: DATA,
        userID: DEFAULT_SM2_USER_ID,
      }).valid,
    ).toBe(true);
    expect(
      verifySignedData(signed.der, {
        detachedData: DATA,
        userID: new Uint8Array(0),
      }).valid,
    ).toBe(false);
  });

  it('rejects non-ASCII-insensitive data correctly (UTF-8 semantics)', () => {
    const signed = signData({ data: '国密', privateKey: KEY_PEM, certificate: CERT_PEM });
    expect(verifySignedData(signed.der, { detachedData: '国密' }).valid).toBe(true);
    expect(verifySignedData(signed.der, { detachedData: '国' }).valid).toBe(false);
  });
});

/** 去掉 SignedData 的 [0] certificates，用于测试 NO_CERTIFICATE。 */
function stripCertificates(der: Uint8Array): Uint8Array {
  const top = parseBer(der);
  const contentInfo = top.children ?? [];
  const signedData = contentInfo[1]?.children?.[0];
  expect(signedData).toBeDefined();
  const children = (signedData?.children ?? []).filter(
    (child) => !(child.cls === 2 && child.tag === 0),
  );
  return seq([oid(OID_CMS_SIGNED_DATA), explicit(0, seq(children))]).raw;
}

const describeOssl = hasOpenSsl() && hasOpenSslCmsSm2() ? describe : describe.skip;

describeOssl('OpenSSL interop', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sm-crypto-cms-'));
  const dataPath = join(dir, 'data.bin');
  const certPath = join(dir, 'cert.pem');
  const keyPath = join(dir, 'key.pem');

  beforeAll(() => {
    writeFileSync(dataPath, Buffer.from(DATA));
    writeFileSync(certPath, CERT_PEM);
    writeFileSync(keyPath, KEY_PEM);
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('openssl cms -verify accepts our detached signature', () => {
    const signed = signData({ data: DATA, privateKey: KEY_PEM, certificate: CERT_PEM });
    const cmsPath = join(dir, 'ours-detached.der');
    const outPath = join(dir, 'ours-detached.out');
    writeFileSync(cmsPath, Buffer.from(signed.der));
    execFileSync('openssl', [
      'cms',
      '-verify',
      '-inform',
      'DER',
      '-in',
      cmsPath,
      '-content',
      dataPath,
      '-noverify',
      '-binary',
      '-out',
      outPath,
    ]);
    expect(readFileSync(outPath)).toEqual(Buffer.from(DATA));
  });

  it('openssl cms -verify accepts our attached signature', () => {
    const signed = signData({
      data: DATA,
      privateKey: KEY_PEM,
      certificate: CERT_PEM,
      detached: false,
    });
    const cmsPath = join(dir, 'ours-attached.der');
    const outPath = join(dir, 'ours-attached.out');
    writeFileSync(cmsPath, Buffer.from(signed.der));
    execFileSync('openssl', [
      'cms',
      '-verify',
      '-inform',
      'DER',
      '-in',
      cmsPath,
      '-noverify',
      '-binary',
      '-out',
      outPath,
    ]);
    expect(readFileSync(outPath)).toEqual(Buffer.from(DATA));
  });

  it('verifies an OpenSSL attached signature', () => {
    const cmsPath = join(dir, 'ossl-attached.der');
    execFileSync('openssl', [
      'cms',
      '-sign',
      '-in',
      dataPath,
      '-signer',
      certPath,
      '-inkey',
      keyPath,
      '-outform',
      'DER',
      '-md',
      'sm3',
      '-binary',
      '-nodetach',
      '-out',
      cmsPath,
    ]);
    const result = verifySignedData(new Uint8Array(readFileSync(cmsPath)));
    expect(result.valid).toBe(true);
    expect(result.signers[0]?.certificate?.subject.commonName).toBe('SM Crypto Root CA');
  });

  it('verifies an OpenSSL detached signature', () => {
    const cmsPath = join(dir, 'ossl-detached.der');
    execFileSync('openssl', [
      'cms',
      '-sign',
      '-in',
      dataPath,
      '-signer',
      certPath,
      '-inkey',
      keyPath,
      '-outform',
      'DER',
      '-md',
      'sm3',
      '-binary',
      '-out',
      cmsPath,
    ]);
    const result = verifySignedData(new Uint8Array(readFileSync(cmsPath)), {
      detachedData: DATA,
    });
    expect(result.valid).toBe(true);
  });

  it('rejects a one-byte modification of an OpenSSL signature', () => {
    const cmsPath = join(dir, 'ossl-tampered.der');
    execFileSync('openssl', [
      'cms',
      '-sign',
      '-in',
      dataPath,
      '-signer',
      certPath,
      '-inkey',
      keyPath,
      '-outform',
      'DER',
      '-md',
      'sm3',
      '-binary',
      '-nodetach',
      '-out',
      cmsPath,
    ]);
    const der = new Uint8Array(readFileSync(cmsPath));
    der[der.length - 1] = (der[der.length - 1] as number) ^ 0x01;
    const result = verifySignedData(der);
    expect(result.valid).toBe(false);
    expect(['SIGNATURE_INVALID', 'MALFORMED']).toContain(result.signers[0]?.errorCode);
  });
});

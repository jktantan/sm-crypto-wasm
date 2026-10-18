/**
 * X.509 签发测试（阶段 2）。
 *
 * 覆盖：自签 CA、CA 签发终端证书、扩展编码、输入校验、SM2 用户标识，
 * 以及 OpenSSL 交叉验证（环境无 openssl 时跳过）。
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '@/runtime';
import * as sm2 from '@/sm2';
import * as sm3 from '@/sm3';
import {
  CertificateError,
  createSelfSignedCertificate,
  DEFAULT_SM2_USER_ID,
  issueCertificate,
  parseCertificate,
  parseDistinguishedName,
} from '@/x509';

function uncompressedPublicKey(privateKey: string): Uint8Array {
  const raw = hexToBytes(sm2.getPublicKey(privateKey), 'publicKey');
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(raw, 1);
  return out;
}

function hasOpenSsl(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const NOT_AFTER = new Date('2035-01-01T00:00:00Z');

beforeAll(async () => {
  await sm2.ensureLoaded();
  await sm3.ensureLoaded();
});

describe('createSelfSignedCertificate', () => {
  it('issues a v3 CA certificate with extensions', async () => {
    const keys = await sm2.generateKeyPair();
    const subject = parseDistinguishedName('C=CN,O=SM Crypto Test,OU=PKI,CN=Issued Root CA');
    const result = createSelfSignedCertificate({
      subject,
      privateKey: keys.privateKeyPem,
      serialNumber: 0x123456789abcdef0n,
      notAfter: NOT_AFTER,
      basicConstraints: { ca: true, pathLen: 1 },
      keyUsage: ['keyCertSign', 'cRLSign'],
    });

    const cert = result.certificate;
    expect(cert.version).toBe(3);
    expect(cert.serialNumber).toBe(0x123456789abcdef0n);
    expect(cert.serialNumberHex).toBe('123456789abcdef0');
    expect(cert.subject.toString()).toBe('C=CN,O=SM Crypto Test,OU=PKI,CN=Issued Root CA');
    expect(cert.issuer.toString()).toBe(cert.subject.toString());
    expect(cert.basicConstraints).toEqual({ ca: true, pathLen: 1 });
    expect(cert.keyUsage?.keyCertSign).toBe(true);
    expect(cert.keyUsage?.cRLSign).toBe(true);
    expect(cert.publicKeyAlgorithm).toBe('SM2');
    expect(cert.supported).toBe(true);
    expect(cert.subjectPublicKey).toEqual(uncompressedPublicKey(keys.privateKeyPem));
    expect(cert.verifySignature(cert)).toBe(true);

    // SKI = SM3(公钥) 前 20 字节；AKI 自签时等于 SKI。
    const expectedSki = hexToBytes(sm3.hash(cert.subjectPublicKey), 'ski').slice(0, 20);
    expect(cert.subjectKeyIdentifier).toEqual(expectedSki);
    expect(cert.authorityKeyIdentifier?.keyIdentifier).toEqual(expectedSki);

    // 解析与 PEM/DER 一致。
    expect(parseCertificate(result.pem).raw).toEqual(result.der);
  });

  it('supports SHA-1 SKI for OpenSSL compatibility', async () => {
    const keys = await sm2.generateKeyPair();
    const cert = createSelfSignedCertificate({
      subject: { commonName: 'SHA1 SKI CA' },
      privateKey: keys.privateKeyPem,
      notAfter: NOT_AFTER,
      basicConstraints: { ca: true },
      keyUsage: ['keyCertSign'],
      subjectKeyIdentifier: { hash: 'sha1' },
    }).certificate;

    const expected = createHash('sha1')
      .update(Buffer.from(cert.subjectPublicKey))
      .digest()
      .subarray(0, 20);
    expect(cert.subjectKeyIdentifier).toEqual(new Uint8Array(expected));
  });

  it('signs with the OpenSSL-compatible empty user id by default', async () => {
    const keys = await sm2.generateKeyPair();
    const cert = createSelfSignedCertificate({
      subject: { commonName: 'OpenSSL ID CA' },
      privateKey: keys.privateKeyPem,
      notAfter: NOT_AFTER,
    }).certificate;
    expect(cert.verifySignature(cert)).toBe(true);
    expect(cert.verifySignature(cert, { userID: new Uint8Array(0) })).toBe(true);
    expect(cert.verifySignature(cert, { userID: DEFAULT_SM2_USER_ID })).toBe(false);
  });

  it('can sign with the GM/T default user id', async () => {
    const keys = await sm2.generateKeyPair();
    const cert = createSelfSignedCertificate({
      subject: { commonName: 'GM/T ID CA' },
      privateKey: keys.privateKeyPem,
      notAfter: NOT_AFTER,
      userID: DEFAULT_SM2_USER_ID,
    }).certificate;
    expect(cert.verifySignature(cert, { userID: DEFAULT_SM2_USER_ID })).toBe(true);
    expect(cert.verifySignature(cert, { userID: new Uint8Array(0) })).toBe(false);
    // 省略 userID 时先默认标识、再回退空标识。
    expect(cert.verifySignature(cert)).toBe(true);
  });
});

describe('issueCertificate (CA → leaf)', () => {
  it('issues a leaf certificate that chains to the CA', async () => {
    const caKeys = await sm2.generateKeyPair();
    const ca = createSelfSignedCertificate({
      subject: parseDistinguishedName('C=CN,O=SM Crypto Test,CN=Issued CA'),
      privateKey: caKeys.privateKeyPem,
      notAfter: NOT_AFTER,
      basicConstraints: { ca: true, pathLen: 0 },
      keyUsage: ['keyCertSign', 'cRLSign'],
    });

    const leafKeys = await sm2.generateKeyPair();
    const leaf = issueCertificate({
      subject: parseDistinguishedName('C=CN,O=SM Crypto Test,OU=Servers,CN=issued.example.test'),
      notAfter: NOT_AFTER,
      basicConstraints: { ca: false },
      keyUsage: ['digitalSignature', 'keyEncipherment'],
      extendedKeyUsage: ['1.3.6.1.5.5.7.3.1'],
      subjectAltNames: [
        { type: 'dns', value: 'issued.example.test' },
        { type: 'dns', value: 'alt.example.test' },
        { type: 'ip', value: '127.0.0.1' },
        { type: 'ip', value: '2001:db8::1' },
        { type: 'email', value: 'admin@example.test' },
        { type: 'uri', value: 'https://example.test/' },
      ],
      subjectPublicKey: leafKeys.publicKeyPem,
      signer: { privateKey: caKeys.privateKeyPem, certificate: ca.certificate },
    });

    const cert = leaf.certificate;
    expect(cert.issuer.toString()).toBe(ca.certificate.subject.toString());
    expect(cert.subject.toString()).toBe('C=CN,O=SM Crypto Test,OU=Servers,CN=issued.example.test');
    expect(cert.basicConstraints).toEqual({ ca: false });
    expect(cert.keyUsage?.digitalSignature).toBe(true);
    expect(cert.keyUsage?.keyCertSign).toBe(false);
    expect(cert.extendedKeyUsage).toEqual(['1.3.6.1.5.5.7.3.1']);
    expect(cert.subjectAltNames.map((n) => `${n.type}:${n.value}`)).toEqual([
      'dns:issued.example.test',
      'dns:alt.example.test',
      'ip:127.0.0.1',
      'ip:2001:db8::1',
      'email:admin@example.test',
      'uri:https://example.test/',
    ]);
    expect(cert.verifySignature(ca.certificate)).toBe(true);
    expect(cert.authorityKeyIdentifier?.keyIdentifier).toEqual(ca.certificate.subjectKeyIdentifier);
    // 被签证书的公钥来自 leaf 私钥，而不是 CA。
    expect(cert.subjectPublicKey).toEqual(uncompressedPublicKey(leafKeys.privateKeyPem));
  });
});

describe('input validation', () => {
  it('rejects invalid serial numbers, validity and DN input', async () => {
    const keys = await sm2.generateKeyPair();
    const base = {
      subject: { commonName: 'Validation' },
      privateKey: keys.privateKeyPem,
      notAfter: NOT_AFTER,
    };
    expect(() => createSelfSignedCertificate({ ...base, serialNumber: 0n })).toThrow(RangeError);
    expect(() => createSelfSignedCertificate({ ...base, serialNumber: -1n })).toThrow(RangeError);
    expect(() =>
      createSelfSignedCertificate({
        ...base,
        notAfter: new Date('2020-01-01T00:00:00Z'),
        notBefore: new Date('2021-01-01T00:00:00Z'),
      }),
    ).toThrow(RangeError);
    expect(() =>
      createSelfSignedCertificate({ ...base, subject: { commonName: '', country: 'CN' } }),
    ).toThrow(CertificateError);
    expect(() =>
      createSelfSignedCertificate({ ...base, subject: { commonName: 'X', country: 'CHN' } }),
    ).toThrow(CertificateError);
  });

  it('enforces CA / keyUsage constraints', async () => {
    const keys = await sm2.generateKeyPair();
    const base = {
      subject: { commonName: 'Constraints' },
      privateKey: keys.privateKeyPem,
      notAfter: NOT_AFTER,
    };
    expect(() =>
      createSelfSignedCertificate({
        ...base,
        basicConstraints: { ca: false },
        keyUsage: ['keyCertSign'],
      }),
    ).toThrow(CertificateError);
    expect(() =>
      createSelfSignedCertificate({
        ...base,
        basicConstraints: { ca: true },
        keyUsage: ['digitalSignature'],
      }),
    ).toThrow(CertificateError);
    expect(() =>
      createSelfSignedCertificate({ ...base, basicConstraints: { ca: false, pathLen: 1 } }),
    ).toThrow(RangeError);

    // 非 CA 证书不能作为签发者。
    const leafKeys = await sm2.generateKeyPair();
    const nonCa = createSelfSignedCertificate({
      subject: { commonName: 'Not a CA' },
      privateKey: leafKeys.privateKeyPem,
      notAfter: NOT_AFTER,
      basicConstraints: { ca: false },
      keyUsage: ['digitalSignature'],
    });
    const childKeys = await sm2.generateKeyPair();
    expect(() =>
      issueCertificate({
        subject: { commonName: 'Child' },
        notAfter: NOT_AFTER,
        signer: {
          privateKey: caKeysForTest.privateKeyPem,
          certificate: nonCa.certificate,
        },
      }),
    ).toThrow(CertificateError);
    void childKeys;
  });

  it('rejects invalid SAN values', async () => {
    const keys = await sm2.generateKeyPair();
    const base = {
      subject: { commonName: 'SAN validation' },
      privateKey: keys.privateKeyPem,
      notAfter: NOT_AFTER,
    };
    expect(() =>
      createSelfSignedCertificate({
        ...base,
        subjectAltNames: [{ type: 'ip', value: '999.1.1.1' }],
      }),
    ).toThrow(CertificateError);
    expect(() =>
      createSelfSignedCertificate({
        ...base,
        subjectAltNames: [{ type: 'ip', value: '2001:db8::zz' }],
      }),
    ).toThrow(CertificateError);
    expect(() =>
      createSelfSignedCertificate({
        ...base,
        subjectAltNames: [{ type: 'dns', value: '国密.example' }],
      }),
    ).toThrow(CertificateError);
  });
});

describe('parseDistinguishedName', () => {
  it('parses and unescapes attributes', () => {
    expect(parseDistinguishedName('C=CN,O=Example,OU=PKI,CN=Test CA')).toEqual({
      commonName: 'Test CA',
      organization: 'Example',
      organizationalUnit: 'PKI',
      country: 'CN',
    });
    expect(parseDistinguishedName('CN=Plain')).toEqual({ commonName: 'Plain' });
    expect(parseDistinguishedName('CN=Smith\\, John,O=ACME')).toEqual({
      commonName: 'Smith, John',
      organization: 'ACME',
    });
    expect(parseDistinguishedName('2.5.4.3=By OID')).toEqual({ commonName: 'By OID' });
    expect(() => parseDistinguishedName('O=Missing CN')).toThrow(CertificateError);
    expect(() => parseDistinguishedName('X=Unknown')).toThrow(CertificateError);
  });
});

// 供 “非 CA 不能签发” 测试使用的密钥（在测试体内 await 生成）。
let caKeysForTest: { privateKeyPem: string; publicKeyPem: string };

beforeAll(async () => {
  caKeysForTest = await sm2.generateKeyPair();
});

const describeOssl = hasOpenSsl() ? describe : describe.skip;

describeOssl('OpenSSL interop', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sm-crypto-x509-issue-'));

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('passes openssl verify for self-signed and CA-issued certificates', async () => {
    const caKeys = await sm2.generateKeyPair();
    const ca = createSelfSignedCertificate({
      subject: parseDistinguishedName('C=CN,O=SM Crypto Test,CN=Interop CA'),
      privateKey: caKeys.privateKeyPem,
      notAfter: NOT_AFTER,
      basicConstraints: { ca: true, pathLen: 0 },
      keyUsage: ['keyCertSign', 'cRLSign'],
    });

    const leafKeys = await sm2.generateKeyPair();
    const leaf = issueCertificate({
      subject: parseDistinguishedName('C=CN,O=SM Crypto Test,CN=interop.example.test'),
      notAfter: NOT_AFTER,
      basicConstraints: { ca: false },
      keyUsage: ['digitalSignature', 'keyEncipherment'],
      extendedKeyUsage: ['1.3.6.1.5.5.7.3.1'],
      subjectAltNames: [{ type: 'dns', value: 'interop.example.test' }],
      subjectPublicKey: leafKeys.publicKeyPem,
      signer: { privateKey: caKeys.privateKeyPem, certificate: ca.certificate },
    });

    const caPath = join(dir, 'ca.pem');
    const leafPath = join(dir, 'leaf.pem');
    writeFileSync(caPath, ca.pem);
    writeFileSync(leafPath, leaf.pem);

    expect(
      execFileSync('openssl', ['verify', '-CAfile', caPath, caPath], { encoding: 'utf8' }),
    ).toContain('OK');
    expect(
      execFileSync('openssl', ['verify', '-CAfile', caPath, leafPath], { encoding: 'utf8' }),
    ).toContain('OK');

    // `openssl x509 -text` 能识别版本、算法与扩展。
    const text = execFileSync('openssl', ['x509', '-in', leafPath, '-noout', '-text'], {
      encoding: 'utf8',
    });
    expect(text).toContain('Version: 3');
    expect(text).toContain('Signature Algorithm: SM2-with-SM3');
    expect(text).toContain('CA:FALSE');
    expect(text).toContain('DNS:interop.example.test');
    expect(text).toContain('TLS Web Server Authentication');
  });

  it('keeps the raw DER parse → encode round-trip stable', async () => {
    const keys = await sm2.generateKeyPair();
    const result = createSelfSignedCertificate({
      subject: parseDistinguishedName('C=CN,CN=Roundtrip'),
      privateKey: keys.privateKeyPem,
      notAfter: NOT_AFTER,
      basicConstraints: { ca: true },
      keyUsage: ['keyCertSign'],
      subjectAltNames: [{ type: 'ip', value: '10.0.0.1' }],
    });
    const path = join(dir, 'roundtrip.pem');
    writeFileSync(path, result.pem);
    const der = new Uint8Array(
      execFileSync('openssl', ['x509', '-in', path, '-outform', 'DER'], {
        stdio: ['ignore', 'pipe', 'ignore'],
      }),
    );
    expect(bytesToHex(der)).toBe(bytesToHex(result.der));
  });
});

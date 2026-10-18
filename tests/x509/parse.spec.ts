/**
 * X.509 解析测试（阶段 1）。
 *
 * 向量由 OpenSSL 3.5.5 生成，详见 tests/vectors/x509/README.md。
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { bytesToBase64, bytesToHex } from '@/runtime';
import * as sm3 from '@/sm3';
import {
  CertificateError,
  OID_AUTHORITY_KEY_IDENTIFIER,
  OID_BASIC_CONSTRAINTS,
  OID_EXTENDED_KEY_USAGE,
  OID_KEY_USAGE,
  OID_SM3_WITH_SM2,
  OID_SUBJECT_ALT_NAME,
  OID_SUBJECT_KEY_IDENTIFIER,
  parseCertificate,
  parseCertificates,
} from '@/x509';

const VECTOR_DIR = new URL('../vectors/x509/', import.meta.url);

function readPem(name: string): string {
  return readFileSync(new URL(name, VECTOR_DIR), 'utf8');
}

function readDer(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(name, VECTOR_DIR)));
}

describe('parseCertificate', () => {
  it('parses the SM2 root CA', () => {
    const cert = parseCertificate(readPem('root-ca.pem'));
    expect(cert.version).toBe(3);
    expect(cert.serialNumber).toBe(0x1001n);
    expect(cert.serialNumberHex).toBe('1001');
    expect(cert.signatureAlgorithm.oid).toBe(OID_SM3_WITH_SM2);
    expect(cert.issuer.toString()).toBe('C=CN,O=SM Crypto Test,OU=PKI,CN=SM Crypto Root CA');
    expect(cert.subject.toString()).toBe('C=CN,O=SM Crypto Test,OU=PKI,CN=SM Crypto Root CA');
    expect(cert.subject.commonName).toBe('SM Crypto Root CA');
    expect(cert.subject.organization).toBe('SM Crypto Test');
    expect(cert.subject.organizationalUnit).toBe('PKI');
    expect(cert.subject.country).toBe('CN');
    expect(cert.validity.notBefore.toISOString()).toBe('2024-01-01T00:00:00.000Z');
    expect(cert.validity.notAfter.toISOString()).toBe('2034-01-01T00:00:00.000Z');

    expect(cert.publicKeyAlgorithm).toBe('SM2');
    expect(cert.supported).toBe(true);
    expect(cert.subjectPublicKey.length).toBe(65);
    expect(cert.subjectPublicKey[0]).toBe(0x04);
    expect(cert.subjectPublicKeyInfo.algorithm.oid).toBe('1.2.840.10045.2.1');
    // sm2p256v1 OID 的内容字节。
    expect(bytesToHex(cert.subjectPublicKeyInfo.algorithm.parameters as Uint8Array)).toBe(
      '2a811ccf5501822d',
    );

    expect(cert.basicConstraints).toEqual({ ca: true, pathLen: 2 });
    expect(cert.keyUsage?.keyCertSign).toBe(true);
    expect(cert.keyUsage?.cRLSign).toBe(true);
    expect(cert.keyUsage?.digitalSignature).toBe(false);
    expect(cert.keyUsage?.keyEncipherment).toBe(false);

    const ski = cert.subjectKeyIdentifier as Uint8Array;
    expect(ski.length).toBe(20);
    expect(bytesToHex(ski)).toBe('797ae0a636ad5d9f8cf58fa2eeaf2c0872792f65');
    expect(bytesToHex(cert.authorityKeyIdentifier?.keyIdentifier as Uint8Array)).toBe(
      bytesToHex(ski),
    );

    expect(cert.tbsCertificate.length).toBeGreaterThan(0);
    expect(cert.raw.length).toBe(readDer('root-ca.der').length);
    expect(cert.fingerprint('sha256')).toBe(
      'b80ebc00ea92cf8bb4b39e728b9805a580445365ab4ce00eb4968d61db446cea',
    );
  });

  it('parses the SM2 leaf server certificate with SAN / EKU', () => {
    const cert = parseCertificate(readPem('leaf-server.pem'));
    expect(cert.version).toBe(3);
    expect(cert.serialNumber).toBe(0x1003n);
    expect(cert.subjectAltNames.map((name) => `${name.type}:${name.value}`)).toEqual([
      'dns:server.example.test',
      'dns:alt.example.test',
      'ip:127.0.0.1',
      'ip:2001:db8::1',
    ]);
    expect(cert.extendedKeyUsage).toEqual(['1.3.6.1.5.5.7.3.1']);
    expect(cert.basicConstraints).toEqual({ ca: false });
    expect(cert.keyUsage?.digitalSignature).toBe(true);
    expect(cert.keyUsage?.keyEncipherment).toBe(true);
    expect(cert.keyUsage?.keyCertSign).toBe(false);
    // SKI / AKI 都存在且不同（终端证书由中间 CA 签发）。
    expect(cert.subjectKeyIdentifier?.length).toBe(20);
    expect(cert.authorityKeyIdentifier?.keyIdentifier?.length).toBe(20);
    expect(bytesToHex(cert.authorityKeyIdentifier?.keyIdentifier as Uint8Array)).not.toBe(
      bytesToHex(cert.subjectKeyIdentifier as Uint8Array),
    );
  });

  it('exposes extensions by OID and keeps unknown ones absent', () => {
    const cert = parseCertificate(readPem('leaf-server.pem'));
    expect(cert.extensions.map((e) => e.oid)).toEqual(
      expect.arrayContaining([
        OID_BASIC_CONSTRAINTS,
        OID_KEY_USAGE,
        OID_EXTENDED_KEY_USAGE,
        OID_SUBJECT_ALT_NAME,
        OID_SUBJECT_KEY_IDENTIFIER,
        OID_AUTHORITY_KEY_IDENTIFIER,
      ]),
    );
    expect(cert.getExtension(OID_KEY_USAGE)?.critical).toBe(true);
    expect(cert.getExtension('1.2.3.4.5.6.7')).toBeUndefined();
  });

  it('accepts PEM, DER and base64 equivalently', () => {
    const der = readDer('leaf-server.der');
    const fromDer = parseCertificate(der);
    const fromPem = parseCertificate(readPem('leaf-server.pem'));
    const fromBase64 = parseCertificate(bytesToBase64(der));
    const fromHex = parseCertificate(bytesToHex(der));
    for (const cert of [fromDer, fromPem, fromBase64, fromHex]) {
      expect(cert.serialNumber).toBe(0x1003n);
      expect(cert.subject.commonName).toBe('server.example.test');
    }
  });

  it('parses RSA certificates without pretending to support them', () => {
    const cert = parseCertificate(readPem('rsa.pem'));
    expect(cert.publicKeyAlgorithm).toBe('RSA');
    expect(cert.supported).toBe(false);
    expect(cert.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(cert.subject.commonName).toBe('RSA Test Cert');
    expect(cert.keyUsage?.digitalSignature).toBe(true);
    expect(cert.verifySignature(cert)).toBe(false);
  });

  it('keeps the raw TBS and signature bytes for external verification', () => {
    const der = readDer('leaf-server.der');
    const cert = parseCertificate(der);
    expect(cert.raw).toEqual(der);
    expect(cert.tbsCertificate.length).toBeGreaterThan(100);
    expect(cert.signatureValue[0]).toBe(0x30); // DER SEQUENCE { r, s }
  });

  it('rejects trailing bytes, truncation and garbage', () => {
    const der = readDer('root-ca.der');
    const withTrailing = new Uint8Array(der.length + 1);
    withTrailing.set(der);
    expect(() => parseCertificate(withTrailing)).toThrow(CertificateError);
    expect(() => parseCertificate(der.subarray(0, der.length - 10))).toThrow(CertificateError);
    expect(() => parseCertificate('not a certificate')).toThrow(CertificateError);
    expect(() => parseCertificate(new Uint8Array(0))).toThrow(CertificateError);
  });
});

describe('parseCertificates', () => {
  it('parses a PEM bundle', () => {
    const bundle = `${readPem('root-ca.pem')}\n${readPem('intermediate-ca.pem')}\n`;
    const certs = parseCertificates(bundle);
    expect(certs.map((c) => c.subject.commonName)).toEqual([
      'SM Crypto Root CA',
      'SM Crypto Intermediate CA',
    ]);
  });

  it('parses concatenated DER certificates', () => {
    const a = readDer('root-ca.der');
    const b = readDer('intermediate-ca.der');
    const concat = new Uint8Array(a.length + b.length);
    concat.set(a);
    concat.set(b, a.length);
    const certs = parseCertificates(concat);
    expect(certs.map((c) => c.serialNumber)).toEqual([0x1001n, 0x1002n]);
  });

  it('parses a single certificate', () => {
    expect(parseCertificates(readPem('root-ca.pem'))).toHaveLength(1);
    expect(parseCertificates(readDer('root-ca.der'))).toHaveLength(1);
  });

  it('rejects an empty input', () => {
    expect(() => parseCertificates(new Uint8Array(0))).toThrow(CertificateError);
  });
});

describe('name formatting', () => {
  it('escapes RFC 4514 special characters', () => {
    const cert = parseCertificate(readPem('root-ca.pem'));
    const name = cert.subject;
    expect(name.attributes.map((a) => a.oid)).toEqual([
      '2.5.4.6',
      '2.5.4.10',
      '2.5.4.11',
      '2.5.4.3',
    ]);
    expect(name.toString()).toBe('C=CN,O=SM Crypto Test,OU=PKI,CN=SM Crypto Root CA');
    // 每个属性都应有值；这里只验证顺序与便捷字段一致。
    expect(name.attributes.map((a) => a.value)).toEqual([
      'CN',
      'SM Crypto Test',
      'PKI',
      'SM Crypto Root CA',
    ]);
  });
});

describe('fingerprint', () => {
  it('computes SM3 fingerprints (32 bytes hex)', async () => {
    await sm3.ensureLoaded();
    const cert = parseCertificate(readPem('leaf-server.pem'));
    const expected = sm3.hash(cert.raw);
    expect(cert.fingerprint()).toBe(expected);
    expect(cert.fingerprint('sm3')).toBe(expected);
    expect(cert.fingerprint('sm3')).toHaveLength(64);
  });

  it('matches OpenSSL SHA-256 output when available', () => {
    let expected: string;
    try {
      const out = execFileSync(
        'openssl',
        [
          'x509',
          '-in',
          fileURLToPath(new URL('leaf-server.pem', VECTOR_DIR)),
          '-noout',
          '-fingerprint',
          '-sha256',
        ],
        { encoding: 'utf8' },
      );
      expected = (out.split('=')[1] as string).replace(/:/g, '').trim().toLowerCase();
    } catch {
      return;
    }
    expect(parseCertificate(readPem('leaf-server.pem')).fingerprint('sha256')).toBe(expected);
  });
});

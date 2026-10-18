/**
 * X.509 签名验证 / 有效期测试（阶段 1）。
 */
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { parseDer } from '@/asn1';
import * as sm2 from '@/sm2';
import { parseCertificate } from '@/x509';

const VECTOR_DIR = new URL('../vectors/x509/', import.meta.url);

function readPem(name: string): string {
  return readFileSync(new URL(name, VECTOR_DIR), 'utf8');
}

function readDer(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(name, VECTOR_DIR)));
}

beforeAll(async () => {
  await sm2.ensureLoaded();
});

describe('verifySignature', () => {
  it('verifies the self-signed root CA', () => {
    const root = parseCertificate(readPem('root-ca.pem'));
    expect(root.verifySignature(root)).toBe(true);
  });

  it('verifies an intermediate CA and a leaf certificate', () => {
    const root = parseCertificate(readPem('root-ca.pem'));
    const intermediate = parseCertificate(readPem('intermediate-ca.pem'));
    const leaf = parseCertificate(readPem('leaf-server.pem'));
    expect(intermediate.verifySignature(root)).toBe(true);
    expect(leaf.verifySignature(intermediate)).toBe(true);
    // 用错签发者必须失败，而不是抛错。
    expect(leaf.verifySignature(root)).toBe(false);
    expect(intermediate.verifySignature(leaf)).toBe(false);
  });

  it('accepts issuer DER and raw public key inputs', () => {
    const intermediate = parseCertificate(readPem('intermediate-ca.pem'));
    const leaf = parseCertificate(readPem('leaf-server.pem'));
    expect(leaf.verifySignature(readDer('intermediate-ca.der'))).toBe(true);
    expect(leaf.verifySignature(intermediate.subjectPublicKey)).toBe(true);
    // 裸公钥 64 字节（去掉 04 前缀）也接受。
    expect(leaf.verifySignature(intermediate.subjectPublicKey.subarray(1))).toBe(true);
  });

  it('rejects a tampered TBS while still parsing the certificate', () => {
    const der = readDer('leaf-server.der');
    const tampered = new Uint8Array(der);
    const top = parseDer(der);
    const tbs = top.children?.[0];
    const spki = tbs?.children?.[6];
    const bitString = spki?.children?.[1];
    expect(bitString).toBeDefined();
    const value = (bitString as { value: Uint8Array }).value;
    const offset = value.byteOffset + value.length - 1;
    tampered[offset] = (tampered[offset] as number) ^ 0x01;

    const intermediate = parseCertificate(readPem('intermediate-ca.pem'));
    const cert = parseCertificate(tampered);
    expect(cert.supported).toBe(true);
    expect(cert.verifySignature(intermediate)).toBe(false);
  });

  it('rejects a tampered signature value', () => {
    const der = readDer('root-ca.der');
    const tampered = new Uint8Array(der);
    const top = parseDer(der);
    const signature = top.children?.[2];
    expect(signature).toBeDefined();
    const value = (signature as { value: Uint8Array }).value;
    tampered[value.byteOffset + value.length - 1] =
      (tampered[value.byteOffset + value.length - 1] as number) ^ 0x01;

    const cert = parseCertificate(tampered);
    expect(cert.verifySignature(cert)).toBe(false);
  });

  it('returns false for RSA certificates', () => {
    const rsa = parseCertificate(readPem('rsa.pem'));
    expect(rsa.verifySignature(rsa)).toBe(false);
  });

  it('honours an explicit SM2 userID (default vs OpenSSL empty id)', () => {
    const root = parseCertificate(readPem('root-ca.pem'));
    // 显式传入错误标识 → 验签失败，但不抛错。
    expect(
      root.verifySignature(root, { userID: new TextEncoder().encode('another-user-id') }),
    ).toBe(false);
    // 显式传入与签名时一致的标识 → 成功。
    expect(
      root.verifySignature(root, { userID: new TextEncoder().encode('1234567812345678') }),
    ).toBe(true);
    expect(root.verifySignature(root, { userID: new Uint8Array(0) })).toBe(false);
    // 省略 userID：先默认标识，失败后回退 OpenSSL 空标识。
    expect(root.verifySignature(root)).toBe(true);
  });

  it('verifies a GM/T-default-id certificate (openssl -sigopt distid)', () => {
    const cert = parseCertificate(readPem('root-ca-openssl-default.pem'));
    expect(cert.verifySignature(cert)).toBe(true);
    expect(cert.verifySignature(cert, { userID: new Uint8Array(0) })).toBe(true);
    expect(
      cert.verifySignature(cert, { userID: new TextEncoder().encode('1234567812345678') }),
    ).toBe(false);
  });
});

describe('checkValidity', () => {
  it('handles valid, expired and not-yet-valid certificates', () => {
    const leaf = parseCertificate(readPem('leaf-server.pem'));
    expect(leaf.checkValidity(new Date('2026-10-18T00:00:00Z'))).toBe(true);
    expect(leaf.checkValidity(new Date('2023-12-31T23:59:59Z'))).toBe(false);
    expect(leaf.checkValidity(new Date('2030-01-01T00:00:01Z'))).toBe(false);

    const expired = parseCertificate(readPem('expired.pem'));
    expect(expired.validity.notBefore.toISOString()).toBe('2020-01-01T00:00:00.000Z');
    expect(expired.validity.notAfter.toISOString()).toBe('2021-01-01T00:00:00.000Z');
    expect(expired.checkValidity(new Date('2026-10-18T00:00:00Z'))).toBe(false);

    const future = parseCertificate(readPem('future.pem'));
    expect(future.checkValidity(new Date('2026-10-18T00:00:00Z'))).toBe(false);
    expect(future.checkValidity(new Date('2030-06-01T00:00:00Z'))).toBe(true);
  });

  it('returns false for an invalid Date', () => {
    const root = parseCertificate(readPem('root-ca.pem'));
    expect(root.checkValidity(new Date(Number.NaN))).toBe(false);
  });
});

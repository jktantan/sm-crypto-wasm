/**
 * X.509 解析器 fuzz（plan「测试与向量策略」）。
 *
 * 目标：任意随机字节只能让解析器抛 `CertificateError`，不崩溃、不泄漏其它异常。
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { CertificateError, parseCertificate, parseCertificates } from '@/x509';

describe('X.509 parser fuzz', () => {
  it('parseCertificate only throws CertificateError', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 2048 }), (bytes) => {
        try {
          parseCertificate(new Uint8Array(bytes));
        } catch (err) {
          expect(err).toBeInstanceOf(CertificateError);
        }
      }),
      { numRuns: 200 },
    );
  });

  it('parseCertificates only throws CertificateError', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 2048 }), (bytes) => {
        try {
          parseCertificates(new Uint8Array(bytes));
        } catch (err) {
          expect(err).toBeInstanceOf(CertificateError);
        }
      }),
      { numRuns: 200 },
    );
  });
});

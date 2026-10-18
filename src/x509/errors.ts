/**
 * X.509 错误类型。
 *
 * 所有证书结构/校验错误都是 `CertificateError`（`SmCryptoError` 的子类），
 * 便于调用方与其它库错误一起捕获。
 */

import { SmCryptoError } from '../runtime/errors.js';

/** 证书解析或校验失败。 */
export class CertificateError extends SmCryptoError {
  override readonly name: string = 'CertificateError';

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

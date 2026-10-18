/**
 * X.509 错误类型。
 *
 * 所有证书结构/校验错误都是 `CertificateError`（`SmCryptoError` 的子类），
 * 便于调用方与其它库错误一起捕获。
 *
 * X.509 error types.
 *
 * Every certificate structural/validation error is a `CertificateError`
 * (a subclass of `SmCryptoError`), so callers can catch it together with the
 * rest of the library's errors.
 */

import { SmCryptoError } from '../runtime/errors.js';

/**
 * 证书解析或校验失败。
 *
 * Certificate parsing or validation failure.
 */
export class CertificateError extends SmCryptoError {
  override readonly name: string = 'CertificateError';

  /**
   * 构造证书错误；`options.cause` 保留底层异常。
   *
   * Builds a certificate error; `options.cause` keeps the underlying error.
   */
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * CMS（PKCS#7 SignedData）错误类型。
 */

import { SmCryptoError } from '../runtime/errors.js';

/** CMS 解析/签名/验签失败。 */
export class CmsError extends SmCryptoError {
  override readonly name: string = 'CmsError';

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** `verifySignedData` 的结构化失败原因。 */
export type CmsVerifyErrorCode =
  | 'NO_CERTIFICATE'
  | 'DIGEST_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'UNSUPPORTED_ALGORITHM'
  | 'MALFORMED';

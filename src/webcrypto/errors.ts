/**
 * WebCrypto 适配层的错误映射。
 *
 * 对外的所有失败都映射为 `DOMException`（WebCrypto 的约定）：
 * - `NotSupportedError`：未知算法/格式/不支持的参数；
 * - `InvalidAccessError`：密钥用途或 `extractable` 不允许；
 * - `DataError`：密钥/数据格式非法；
 * - `OperationError`：加解密/验签失败。
 */

import {
  CiphertextError,
  DecryptionError,
  InvalidKeyError,
  NotImplementedError,
  SmCryptoError,
} from '../runtime/errors.js';

/** 构造 `DOMException` 的便捷函数。 */
export function notSupported(message: string): DOMException {
  return new DOMException(message, 'NotSupportedError');
}

/** 构造 `InvalidAccessError`。 */
export function invalidAccess(message: string): DOMException {
  return new DOMException(message, 'InvalidAccessError');
}

/** 构造 `DataError`。 */
export function dataError(message: string): DOMException {
  return new DOMException(message, 'DataError');
}

/** 构造 `OperationError`。 */
export function operationError(message: string): DOMException {
  return new DOMException(message, 'OperationError');
}

/** 把库内错误映射为 `DOMException`；已经是 `DOMException` 时原样返回。 */
export function toDOMException(
  err: unknown,
  fallback: 'OperationError' | 'DataError' = 'OperationError',
): DOMException {
  if (err instanceof DOMException) return err;
  const message = err instanceof Error ? err.message : String(err);
  if (err instanceof NotImplementedError) return notSupported(message);
  if (err instanceof DecryptionError) return operationError(message);
  if (err instanceof InvalidKeyError) return dataError(message);
  if (err instanceof CiphertextError) return dataError(message);
  if (err instanceof SmCryptoError) return operationError(message);
  if (err instanceof TypeError || err instanceof RangeError) return dataError(message);
  return new DOMException(message, fallback);
}

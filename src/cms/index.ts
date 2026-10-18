/**
 * CMS SignedData 子模块（`sm-crypto-wasm/cms`）。
 *
 * 只做签名/验签，不建立信任链；证书有效期/用途/链校验由调用方负责。
 *
 * CMS SignedData submodule (`sm-crypto-wasm/cms`).
 *
 * Signing/verification only, no trust chain building: certificate validity, key usage
 * and chain validation are the caller's responsibility.
 */

export { CmsError, type CmsVerifyErrorCode } from './errors.js';
export * from './oids.js';
// 公共类型导出：属性、签名者、解析结果、选项与结果类型。
//
// Public type re-exports: attributes, signers, parse results, options and results.
export type {
  CmsAttribute,
  CmsSignerIdentifier,
  CmsSignerInfo,
  ParsedSignedData,
} from './parse.js';
export { parseSignedData } from './parse.js';
export type { SignDataOptions, SignDataResult } from './sign.js';
export { signData } from './sign.js';
export type {
  VerifySignedDataOptions,
  VerifySignedDataResult,
  VerifySignerResult,
} from './verify.js';
export { signerIdentifierHex, verifySignedData } from './verify.js';

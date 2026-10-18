/**
 * X.509 子模块（`sm-crypto-wasm/x509`）。
 *
 * 范围：证书解析、单证书签名验证、自签/CA 签发。**不做证书链路径校验**、
 * 不拉 CRL/OCSP；调用方需要按 issuer 逐级调用 `verifySignature`。
 *
 * The X.509 submodule (`sm-crypto-wasm/x509`).
 *
 * Scope: certificate parsing, single-certificate signature verification, and
 * self-signed / CA issuance. **No certification path validation** and no
 * CRL/OCSP fetching; callers walk the chain themselves by calling
 * `verifySignature` against each issuer in turn.
 */

// 证书错误类型。
//
// The certificate error class.
export { CertificateError } from './errors.js';

// 自签证书选项类型。
//
// Options type for self-signed certificates.
export type { SelfSignedCertificateOptions } from './issue.js';

// 证书签发与 DN 解析入口。
//
// Certificate issuance and DN parsing entry points.
export {
  createSelfSignedCertificate,
  issueCertificate,
  parseDistinguishedName,
} from './issue.js';

// OID 常量。
//
// OID constants.
export * from './oids.js';

// 证书解析入口。
//
// Certificate parsing entry points.
export { parseCertificate, parseCertificates } from './parse.js';

// 公共类型导出（证书、DN、扩展、选项与结果类型）。
//
// Public type re-exports (certificates, DNs, extensions, options and results).
export type {
  AlgorithmIdentifier,
  AuthorityKeyIdentifier,
  BasicConstraints,
  BasicConstraintsInput,
  Certificate,
  CertificateInput,
  CertificateSigner,
  DistinguishedNameInput,
  Extension,
  GeneralName,
  IssueCertificateOptions,
  IssueCertificateResult,
  KeyUsage,
  KeyUsageName,
  Name,
  NameAttribute,
  SubjectAltNameInput,
  SubjectPublicKeyInfo,
  Validity,
} from './types.js';

// 验签选项与验签工具。
//
// Signature verification options and helpers.
export type { VerifySignatureOptions } from './verify.js';
export { DEFAULT_SM2_USER_ID, isWithinValidity, verifyCertificateSignature } from './verify.js';

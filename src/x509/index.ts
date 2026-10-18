/**
 * X.509 子模块（`sm-crypto-wasm/x509`）。
 *
 * 范围：证书解析、单证书签名验证、自签/CA 签发。**不做证书链路径校验**、
 * 不拉 CRL/OCSP；调用方需要按 issuer 逐级调用 `verifySignature`。
 */

export { CertificateError } from './errors.js';
export type { SelfSignedCertificateOptions } from './issue.js';
export {
  createSelfSignedCertificate,
  issueCertificate,
  parseDistinguishedName,
} from './issue.js';
export * from './oids.js';
export { parseCertificate, parseCertificates } from './parse.js';
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
export type { VerifySignatureOptions } from './verify.js';
export { DEFAULT_SM2_USER_ID, isWithinValidity, verifyCertificateSignature } from './verify.js';

/**
 * X.509 公开类型定义。
 *
 * 这些类型不暴露底层 ASN.1 节点：需要原始字节时使用 `raw` / `tbsCertificate` /
 * `signatureValue` 等字段（红线 #9 与 spec Anti-Goal）。
 *
 * Public X.509 type definitions.
 *
 * These types never expose raw ASN.1 nodes: when the original bytes are needed,
 * use the `raw` / `tbsCertificate` / `signatureValue` fields instead (red line #9
 * and the spec's anti-goal).
 */

/**
 * 算法标识（AlgorithmIdentifier）。
 *
 * An AlgorithmIdentifier.
 */
export interface AlgorithmIdentifier {
  /**
   * 算法 OID，如 `"1.2.156.10197.1.501"`。
   *
   * The algorithm OID, e.g. `"1.2.156.10197.1.501"`.
   */
  readonly oid: string;
  /**
   * 参数字节（内容，不含 TLV）；无参数为 `undefined`。
   *
   * Parameter bytes (content only, no TLV); `undefined` when absent.
   */
  readonly parameters?: Uint8Array;
  /**
   * 参数节点的原始 TLV；无参数为 `undefined`。
   *
   * Raw TLV of the parameter node; `undefined` when absent.
   */
  readonly parametersRaw?: Uint8Array;
}

/**
 * 一个 Name 属性（AttributeTypeAndValue）。
 *
 * A single Name attribute (AttributeTypeAndValue).
 */
export interface NameAttribute {
  readonly oid: string;
  readonly value: string;
  /**
   * 该属性节点的原始 TLV。
   *
   * Raw TLV of this attribute node.
   */
  readonly raw: Uint8Array;
}

/**
 * 证书主体/签发者名称。
 *
 * A certificate subject/issuer name.
 */
export interface Name {
  readonly commonName?: string;
  readonly organization?: string;
  readonly organizationalUnit?: string;
  readonly country?: string;
  readonly state?: string;
  readonly locality?: string;
  readonly emailAddress?: string;
  /**
   * 按编码顺序的全部属性。
   *
   * All attributes, in encoding order.
   */
  readonly attributes: readonly NameAttribute[];
  /**
   * 整个 Name 的原始 DER。
   *
   * Raw DER of the whole Name.
   */
  readonly raw: Uint8Array;
  /**
   * RFC 4514 风格字符串，如 `"C=CN,O=Example,CN=Example CA"`。
   *
   * An RFC 4514 style string, e.g. `"C=CN,O=Example,CN=Example CA"`.
   */
  toString(): string;
}

/**
 * SubjectPublicKeyInfo。
 *
 * A SubjectPublicKeyInfo.
 */
export interface SubjectPublicKeyInfo {
  readonly algorithm: AlgorithmIdentifier;
  /**
   * BIT STRING 内容（去掉未使用位字节）；SM2 为 65 字节 `04 || X || Y`。
   *
   * BIT STRING content (the unused-bits byte is stripped); for SM2 this is the
   * 65-byte `04 || X || Y` form.
   */
  readonly publicKey: Uint8Array;
  /**
   * 整个 SPKI 的原始 DER。
   *
   * Raw DER of the whole SPKI.
   */
  readonly raw: Uint8Array;
}

/**
 * 原始扩展（未知扩展也按此保留）。
 *
 * A raw extension; unknown extensions are preserved in this form too.
 */
export interface Extension {
  readonly oid: string;
  readonly critical: boolean;
  /**
   * `extnValue` 的原始内容（OCTET STRING 内部字节）。
   *
   * Raw content of `extnValue` (the bytes inside the OCTET STRING).
   */
  readonly value: Uint8Array;
  /**
   * 整个 Extension 的原始 DER。
   *
   * Raw DER of the whole Extension.
   */
  readonly raw: Uint8Array;
}

/**
 * KeyUsage 扩展。
 *
 * The KeyUsage extension.
 */
export interface KeyUsage {
  readonly digitalSignature: boolean;
  readonly nonRepudiation: boolean;
  readonly keyEncipherment: boolean;
  readonly dataEncipherment: boolean;
  readonly keyAgreement: boolean;
  readonly keyCertSign: boolean;
  readonly cRLSign: boolean;
  readonly encipherOnly: boolean;
  readonly decipherOnly: boolean;
}

/**
 * BasicConstraints 扩展。
 *
 * The BasicConstraints extension.
 */
export interface BasicConstraints {
  readonly ca: boolean;
  readonly pathLen?: number;
}

/**
 * SubjectAltName 的条目。
 *
 * One SubjectAltName entry.
 */
export type GeneralName =
  | { readonly type: 'dns'; readonly value: string; readonly raw: Uint8Array }
  | { readonly type: 'ip'; readonly value: string; readonly raw: Uint8Array }
  | { readonly type: 'email'; readonly value: string; readonly raw: Uint8Array }
  | { readonly type: 'uri'; readonly value: string; readonly raw: Uint8Array }
  | {
      readonly type: 'other';
      readonly tag: number;
      /**
       * 原始内容的 hex（`#` 前缀）。
       *
       * Hex of the raw content, prefixed with `#`.
       */
      readonly value: string;
      readonly raw: Uint8Array;
    };

/**
 * AuthorityKeyIdentifier 扩展。
 *
 * The AuthorityKeyIdentifier extension.
 */
export interface AuthorityKeyIdentifier {
  readonly keyIdentifier?: Uint8Array;
  readonly authorityCertSerialNumber?: bigint;
}

/**
 * 证书有效期。
 *
 * A certificate validity period.
 */
export interface Validity {
  readonly notBefore: Date;
  readonly notAfter: Date;
}

/**
 * 解析后的证书。
 *
 * A parsed certificate.
 */
export interface Certificate {
  /**
   * 1 / 2 / 3（ASN.1 Version 编码值 + 1）。
   *
   * 1 / 2 / 3 (the encoded ASN.1 Version value plus one).
   */
  readonly version: 1 | 2 | 3;
  readonly serialNumber: bigint;
  /**
   * 序列号 hex（无 `0x` 前缀、小写、无前导零；0 为 `"0"`）。
   *
   * Serial number as hex (no `0x` prefix, lowercase, no leading zeros; 0 is `"0"`).
   */
  readonly serialNumberHex: string;
  readonly signatureAlgorithm: AlgorithmIdentifier;
  readonly issuer: Name;
  readonly validity: Validity;
  readonly subject: Name;
  readonly subjectPublicKeyInfo: SubjectPublicKeyInfo;
  readonly extensions: readonly Extension[];
  /**
   * 签名值（BIT STRING 内容，通常是 DER `SEQUENCE { r, s }`）。
   *
   * Signature value (BIT STRING content, usually a DER `SEQUENCE { r, s }`).
   */
  readonly signatureValue: Uint8Array;
  /**
   * TBS 原始字节（验签用）。
   *
   * Raw TBS bytes, used for signature verification.
   */
  readonly tbsCertificate: Uint8Array;
  /**
   * 整个证书的原始 DER。
   *
   * Raw DER of the whole certificate.
   */
  readonly raw: Uint8Array;

  /**
   * 裸公钥；SM2 为 64/65 字节。
   *
   * The bare public key; 64/65 bytes for SM2.
   */
  readonly subjectPublicKey: Uint8Array;
  readonly publicKeyAlgorithm: 'SM2' | 'RSA' | 'UNKNOWN';
  /**
   * 本库能否使用该公钥（RSA / 未知算法为 false）。
   *
   * Whether this library can use the public key (`false` for RSA and unknown algorithms).
   */
  readonly supported: boolean;

  /**
   * KeyUsage 扩展（缺失或解析失败为 `undefined`）。
   *
   * The KeyUsage extension; `undefined` when absent or unparsable.
   */
  readonly keyUsage?: KeyUsage;
  /**
   * BasicConstraints 扩展。
   *
   * The BasicConstraints extension.
   */
  readonly basicConstraints?: BasicConstraints;
  /**
   * SubjectAltName（缺失为空数组）。
   *
   * SubjectAltName entries; an empty array when absent.
   */
  readonly subjectAltNames: readonly GeneralName[];
  /**
   * ExtendedKeyUsage OID 列表（缺失为空数组）。
   *
   * ExtendedKeyUsage OIDs; an empty array when absent.
   */
  readonly extendedKeyUsage: readonly string[];
  /**
   * SubjectKeyIdentifier。
   *
   * The SubjectKeyIdentifier.
   */
  readonly subjectKeyIdentifier?: Uint8Array;
  /**
   * AuthorityKeyIdentifier。
   *
   * The AuthorityKeyIdentifier.
   */
  readonly authorityKeyIdentifier?: AuthorityKeyIdentifier;

  /**
   * 按 OID 查扩展（未知扩展也能取到原始值）。
   *
   * Looks up an extension by OID; unknown extensions still yield their raw value.
   */
  getExtension(oid: string): Extension | undefined;
  /**
   * 在 `at`（默认 now）是否处于有效期内。
   *
   * Whether `at` (default: now) falls inside the validity period.
   */
  checkValidity(at?: Date): boolean;
  /**
   * 用签发者验证本证书签名。
   *
   * `issuer` 可以是本库解析的证书、DER/PEM 字节，或裸公钥（64/65 字节）。
   * 非 SM2 证书或非 SM3withSM2 签名返回 `false`（不抛错）。
   *
   * Verifies this certificate's signature with the issuer.
   *
   * `issuer` may be a certificate parsed by this library, DER/PEM bytes, or a
   * bare public key (64/65 bytes). Non-SM2 certificates and non-SM3withSM2
   * signatures return `false` instead of throwing.
   */
  verifySignature(issuer: Certificate | Uint8Array, opts?: { userID?: Uint8Array }): boolean;
  /**
   * 指纹 hex（默认 SM3；`sha256` 走内置纯 JS 实现）。
   *
   * Fingerprint as hex (SM3 by default; `sha256` uses the built-in pure-JS implementation).
   */
  fingerprint(hash?: 'sm3' | 'sha256'): string;
}

/**
 * `parseCertificate` 可接受的输入。
 *
 * Input accepted by `parseCertificate`.
 */
export type CertificateInput = string | Uint8Array;

// ---------- 签发输入 ----------
//
// ---------- Issuance input ----------

/**
 * 签发证书时的 Distinguished Name 输入。
 *
 * Distinguished Name input used when issuing a certificate.
 */
export interface DistinguishedNameInput {
  readonly commonName: string;
  readonly organization?: string;
  readonly organizationalUnit?: string;
  /**
   * 2 字母国家代码。
   *
   * A two-letter country code.
   */
  readonly country?: string;
  readonly state?: string;
  readonly locality?: string;
  readonly emailAddress?: string;
}

/**
 * KeyUsage 位名（与解析结果 `KeyUsage` 的字段一致）。
 *
 * KeyUsage bit names, matching the fields of the parsed `KeyUsage`.
 */
export type KeyUsageName =
  | 'digitalSignature'
  | 'nonRepudiation'
  | 'keyEncipherment'
  | 'dataEncipherment'
  | 'keyAgreement'
  | 'keyCertSign'
  | 'cRLSign'
  | 'encipherOnly'
  | 'decipherOnly';

/**
 * SubjectAltName 输入。
 *
 * SubjectAltName input.
 */
export interface SubjectAltNameInput {
  readonly type: 'dns' | 'ip' | 'email' | 'uri';
  readonly value: string;
}

/**
 * BasicConstraints 输入。
 *
 * BasicConstraints input.
 */
export interface BasicConstraintsInput {
  readonly ca: boolean;
  /**
   * 仅 CA 证书可用；非负整数。
   *
   * Only valid for CA certificates; a non-negative integer.
   */
  readonly pathLen?: number;
}

/**
 * 签发者密钥材料。
 *
 * Issuer key material.
 */
export interface CertificateSigner {
  /**
   * PKCS#8 / SEC1 PEM、32 字节私钥或其 hex。
   *
   * PKCS#8 / SEC1 PEM, a 32-byte private key, or its hex.
   */
  readonly privateKey: string | Uint8Array;
  /**
   * 可选公钥（64/65 字节或 hex/PEM）；省略时从私钥派生。
   *
   * Optional public key (64/65 bytes, hex or PEM); derived from the private key when omitted.
   */
  readonly publicKey?: string | Uint8Array;
  /**
   * 可选签发者证书；用于默认 issuer 名称与 AKI。
   *
   * Optional issuer certificate; supplies the default issuer name and the AKI.
   */
  readonly certificate?: Certificate;
}

/**
 * `issueCertificate` 的选项。
 *
 * Options for `issueCertificate`.
 */
export interface IssueCertificateOptions {
  readonly subject: DistinguishedNameInput;
  /**
   * 被签发证书的主体公钥（64/65 字节、hex 或 SPKI PEM）。
   *
   * 自签时可省略（从 `signer.privateKey` 派生）；用 CA 证书签发时必须提供，
   * 否则会错误地把签发者公钥写进子证书。
   *
   * Subject public key of the certificate being issued (64/65 bytes, hex, or SPKI PEM).
   *
   * Optional for self-signing (derived from `signer.privateKey`); required when
   * signing with a CA certificate, otherwise the issuer public key would be
   * written into the child certificate by mistake.
   */
  readonly subjectPublicKey?: string | Uint8Array;
  /**
   * 省略时：有 `signer.certificate` 取其 subject，否则等于 `subject`（自签）。
   *
   * When omitted: the subject of `signer.certificate` if present, otherwise
   * `subject` itself (self-signed).
   */
  readonly issuer?: DistinguishedNameInput;
  /**
   * 正整数；省略时生成 16 字节随机数（最高位清零）。
   *
   * A positive integer; when omitted a random 16-byte value with the top bit cleared is used.
   */
  readonly serialNumber?: bigint;
  /**
   * 省略时为当前时间前 5 分钟。
   *
   * Defaults to five minutes before the current time.
   */
  readonly notBefore?: Date;
  readonly notAfter: Date;
  readonly keyUsage?: readonly KeyUsageName[];
  readonly extendedKeyUsage?: readonly string[];
  readonly basicConstraints?: BasicConstraintsInput;
  readonly subjectAltNames?: readonly SubjectAltNameInput[];
  /**
   * 默认 `true`（SM3 公钥摘要前 20 字节）；`{ hash: 'sha1' }` 兼容 OpenSSL。
   *
   * Defaults to `true` (first 20 bytes of the SM3 public-key digest); pass
   * `{ hash: 'sha1' }` for OpenSSL compatibility.
   */
  readonly subjectKeyIdentifier?: boolean | { readonly hash: 'sm3' | 'sha1' };
  /**
   * 默认有签发者时 `true`；自签或用签发者证书的 SKI。
   *
   * `true` by default when there is an issuer; uses the SKI of the issuer
   * certificate, or the subject SKI for self-signed certificates.
   */
  readonly authorityKeyIdentifier?: boolean;
  /**
   * 签名使用的 SM2 用户标识。
   *
   * 默认**空标识**（与 OpenSSL 的 X.509 路径一致，便于 `openssl verify`）；
   * 需要符合 GM/T 默认约定时传 `DEFAULT_SM2_USER_ID`。
   *
   * SM2 user identity used for signing.
   *
   * Defaults to the **empty** identity (matching OpenSSL's X.509 path so that
   * `openssl verify` works); pass `DEFAULT_SM2_USER_ID` to follow the GM/T default.
   */
  readonly userID?: Uint8Array;
  readonly signer: CertificateSigner;
}

/**
 * 签发结果。
 *
 * The issuance result.
 */
export interface IssueCertificateResult {
  readonly pem: string;
  readonly der: Uint8Array;
  readonly certificate: Certificate;
}

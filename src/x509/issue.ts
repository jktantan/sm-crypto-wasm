/**
 * X.509 证书签发（自签 + 用 CA 证书签发终端证书）。
 *
 * 安全边界（红线 #4 / #5 / #6）：
 * - 证书版本固定 v3；
 * - `basicConstraints.ca=false` 的证书不得用于签发子证书，且该证书不能带
 *   `keyUsage: keyCertSign`；
 * - 用作签发者的证书必须是 CA（`basicConstraints.ca === true`），若带 KeyUsage
 *   必须包含 `keyCertSign`；
 * - CA 证书的 KeyUsage（若提供）必须包含 `keyCertSign`；
 * - 序列号为正整数；默认生成 16 字节随机数并把最高位清零；
 * - SAN 的 dNSName / rfc822Name / URI 必须为 ASCII，iPAddress 必须是合法 4/16 字节。
 *
 * 本模块**不生成密钥、不管理私钥**：私钥由调用方提供，签名后不驻留。
 */

import { parseSm2PublicKeyPem } from '../pem/sm2.js';
import { bytesToPem, hexToBytes, toBytes } from '../runtime/convert.js';
import { randomBytes } from '../runtime/random.js';
import * as sm2 from '../sm2/index.js';
import * as sm3 from '../sm3/index.js';
import {
  type EncodedExtension,
  encodeAuthorityKeyIdentifier,
  encodeBasicConstraints,
  encodeCertificate,
  encodeExtendedKeyUsage,
  encodeKeyUsage,
  encodeSubjectAltName,
  encodeSubjectKeyIdentifier,
  encodeTbsCertificate,
  normalizePublicKey,
} from './encode.js';
import { CertificateError } from './errors.js';
import {
  OID_AUTHORITY_KEY_IDENTIFIER,
  OID_BASIC_CONSTRAINTS,
  OID_EXTENDED_KEY_USAGE,
  OID_KEY_USAGE,
  OID_SUBJECT_ALT_NAME,
  OID_SUBJECT_KEY_IDENTIFIER,
} from './oids.js';
import { parseCertificate } from './parse.js';
import { sha1Hex } from './sha1.js';
import { rawSignatureToDer } from './sig.js';
import type {
  Certificate,
  CertificateSigner,
  DistinguishedNameInput,
  IssueCertificateOptions,
  IssueCertificateResult,
  Name,
  SubjectAltNameInput,
  Validity,
} from './types.js';

/** `createSelfSignedCertificate` 的选项。 */
export type SelfSignedCertificateOptions = Omit<IssueCertificateOptions, 'issuer' | 'signer'> & {
  readonly privateKey: string | Uint8Array;
};

/**
 * 签发一张 SM2 证书。
 *
 * @throws CertificateError 输入不满足证书约束。
 * @throws RangeError 序列号/有效期/路径长度越界。
 */
export function issueCertificate(opts: IssueCertificateOptions): IssueCertificateResult {
  validateSubject(opts.subject, 'subject');
  const issuer =
    opts.issuer ??
    (opts.signer.certificate ? nameToInput(opts.signer.certificate.subject) : opts.subject);
  validateSubject(issuer, 'issuer');

  validateSigner(opts.signer);
  validateBasicConstraints(opts);

  const serialNumber = opts.serialNumber ?? randomSerialNumber();
  validateSerialNumber(serialNumber);

  const notBefore = opts.notBefore ?? new Date(Date.now() - 5 * 60_000);
  const validity = { notBefore, notAfter: opts.notAfter };
  validateValidity(validity);

  const publicKey = resolveSubjectPublicKey(opts);
  const extensions = buildExtensions(
    opts,
    publicKey,
    issuer === opts.subject && !opts.signer.certificate,
  );

  const tbs = encodeTbsCertificate({
    version: 3,
    serialNumber,
    issuer,
    validity,
    subject: opts.subject,
    publicKey,
    extensions: extensions.list,
  });

  // 默认空标识：与 OpenSSL 的 X.509 路径一致（`openssl verify` 可直接验证）。
  // 需要 GM/T 默认标识时由调用方显式传 `DEFAULT_SM2_USER_ID`。
  const signatureHex = sm2.signWithID(
    opts.signer.privateKey,
    tbs.raw,
    opts.userID ?? new Uint8Array(0),
  );
  const signatureDer = rawSignatureToDer(hexToBytes(signatureHex, 'signature'));
  const der = encodeCertificate(tbs, signatureDer);
  return {
    pem: bytesToPem(der, 'CERTIFICATE'),
    der,
    certificate: parseCertificate(der),
  };
}

/**
 * 生成自签证书（issuer = subject）。
 *
 * @throws CertificateError / RangeError 同 `issueCertificate`。
 */
export function createSelfSignedCertificate(
  opts: SelfSignedCertificateOptions,
): IssueCertificateResult {
  const { privateKey, ...rest } = opts;
  return issueCertificate({ ...rest, signer: { privateKey } });
}

/**
 * 解析 RFC 4514 子集形式的 DN 字符串，如 `"C=CN,O=Example,CN=Example CA"`。
 *
 * 支持反斜杠转义（`\,`、`\=`、`\\`）；不做完整 RFC 4514（多值 RDN、
 * `#hex` 编码、十六进制转义等）。
 *
 * @throws CertificateError 格式非法或属性名未知。
 */
export function parseDistinguishedName(input: string): DistinguishedNameInput {
  if (typeof input !== 'string' || input.trim().length === 0) {
    throw new CertificateError('parseDistinguishedName: empty input');
  }
  const result: {
    commonName?: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    state?: string;
    locality?: string;
    emailAddress?: string;
  } = {};

  for (const part of splitUnescaped(input, ',')) {
    const eq = indexOfUnescaped(part, '=');
    if (eq < 0) throw new CertificateError(`parseDistinguishedName: missing '=' in "${part}"`);
    const label = decodeEscapes(part.slice(0, eq)).trim();
    const value = decodeEscapes(part.slice(eq + 1)).trim();
    const field = FIELD_BY_LABEL[label.toUpperCase()];
    if (field === undefined) {
      throw new CertificateError(`parseDistinguishedName: unsupported attribute "${label}"`);
    }
    result[field] = value;
  }

  if (result.commonName === undefined) {
    throw new CertificateError('parseDistinguishedName: CN is required');
  }
  return {
    commonName: result.commonName,
    ...(result.organization === undefined ? {} : { organization: result.organization }),
    ...(result.organizationalUnit === undefined
      ? {}
      : { organizationalUnit: result.organizationalUnit }),
    ...(result.country === undefined ? {} : { country: result.country }),
    ...(result.state === undefined ? {} : { state: result.state }),
    ...(result.locality === undefined ? {} : { locality: result.locality }),
    ...(result.emailAddress === undefined ? {} : { emailAddress: result.emailAddress }),
  };
}

// ---------- 校验 ----------

function validateSubject(dn: DistinguishedNameInput, what: string): void {
  if (typeof dn !== 'object' || dn === null || typeof dn.commonName !== 'string') {
    throw new TypeError(`${what}: commonName is required`);
  }
  if (dn.commonName.length === 0) {
    throw new CertificateError(`${what}: commonName must not be empty`);
  }
  for (const key of [
    'organization',
    'organizationalUnit',
    'state',
    'locality',
    'emailAddress',
  ] as const) {
    const value = dn[key];
    if (value !== undefined && typeof value !== 'string') {
      throw new TypeError(`${what}.${key} must be a string`);
    }
  }
  if (dn.country !== undefined && !/^[A-Za-z]{2}$/.test(dn.country)) {
    throw new CertificateError(`${what}.country must be a 2-letter code`);
  }
  if (dn.emailAddress !== undefined) {
    assertAscii(dn.emailAddress, `${what}.emailAddress`);
  }
}

function validateSigner(signer: CertificateSigner): void {
  if (typeof signer !== 'object' || signer === null || signer.privateKey === undefined) {
    throw new TypeError('signer.privateKey is required');
  }
  const cert = signer.certificate;
  if (cert === undefined) return;
  // 红线 #4：只有 CA 证书才能签发子证书。
  if (cert.basicConstraints?.ca !== true) {
    throw new CertificateError('signer certificate is not a CA (basicConstraints.ca !== true)');
  }
  if (cert.keyUsage !== undefined && !cert.keyUsage.keyCertSign) {
    throw new CertificateError('signer certificate keyUsage does not include keyCertSign');
  }
}

function validateBasicConstraints(opts: IssueCertificateOptions): void {
  const basic = opts.basicConstraints;
  const keyUsage = opts.keyUsage;
  if (basic === undefined) return;
  if (basic.ca) {
    if (keyUsage !== undefined && !keyUsage.includes('keyCertSign')) {
      throw new CertificateError('CA certificate requires keyUsage keyCertSign');
    }
  } else {
    if (keyUsage?.includes('keyCertSign')) {
      throw new CertificateError(
        'basicConstraints.ca=false cannot be combined with keyUsage keyCertSign',
      );
    }
    if (basic.pathLen !== undefined) {
      throw new RangeError('basicConstraints.pathLen is only valid for CA certificates');
    }
  }
}

function validateSerialNumber(serialNumber: bigint): void {
  if (typeof serialNumber !== 'bigint') throw new TypeError('serialNumber must be a bigint');
  if (serialNumber <= 0n) throw new RangeError('serialNumber must be positive');
  if (serialNumber >= 1n << 160n) {
    throw new RangeError('serialNumber must fit in 20 bytes');
  }
}

function validateValidity(validity: Validity): void {
  for (const [name, date] of [
    ['notBefore', validity.notBefore],
    ['notAfter', validity.notAfter],
  ] as const) {
    if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
      throw new TypeError(`${name} must be a valid Date`);
    }
  }
  // 证书时间精度到秒；按秒比较避免毫秒差导致编码后两者相等。
  const nb = Math.floor(validity.notBefore.getTime() / 1000);
  const na = Math.floor(validity.notAfter.getTime() / 1000);
  if (na <= nb) throw new RangeError('notAfter must be later than notBefore');
}

function validateSubjectAltNames(names: readonly SubjectAltNameInput[] | undefined): void {
  if (names === undefined) return;
  for (const name of names) {
    if (name === null || typeof name !== 'object' || typeof name.value !== 'string') {
      throw new TypeError('subjectAltNames: each entry needs { type, value }');
    }
    if (name.value.length === 0) {
      throw new CertificateError('subjectAltNames: value must not be empty');
    }
    switch (name.type) {
      case 'dns':
        assertAscii(name.value, 'subjectAltNames dNSName');
        break;
      case 'email':
        assertAscii(name.value, 'subjectAltNames rfc822Name');
        break;
      case 'uri':
        assertAscii(name.value, 'subjectAltNames URI');
        break;
      case 'ip':
        // 具体解析在编码阶段完成；这里只做早期校验。
        break;
      default:
        throw new CertificateError(`subjectAltNames: unknown type "${String(name.type)}"`);
    }
  }
}

function assertAscii(value: string, what: string): void {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0x7f) throw new CertificateError(`${what} must be ASCII`);
  }
}

// ---------- 扩展 ----------

function buildExtensions(
  opts: IssueCertificateOptions,
  publicKey: Uint8Array,
  selfSigned: boolean,
): { list: EncodedExtension[] } {
  validateSubjectAltNames(opts.subjectAltNames);
  const list: EncodedExtension[] = [];

  if (opts.basicConstraints !== undefined) {
    list.push({
      oid: OID_BASIC_CONSTRAINTS,
      critical: true,
      value: encodeBasicConstraints(opts.basicConstraints),
    });
  }
  if (opts.keyUsage !== undefined && opts.keyUsage.length > 0) {
    list.push({ oid: OID_KEY_USAGE, critical: true, value: encodeKeyUsage(opts.keyUsage) });
  }
  if (opts.extendedKeyUsage !== undefined && opts.extendedKeyUsage.length > 0) {
    list.push({
      oid: OID_EXTENDED_KEY_USAGE,
      critical: false,
      value: encodeExtendedKeyUsage(opts.extendedKeyUsage),
    });
  }
  if (opts.subjectAltNames !== undefined && opts.subjectAltNames.length > 0) {
    list.push({
      oid: OID_SUBJECT_ALT_NAME,
      critical: false,
      value: encodeSubjectAltName(opts.subjectAltNames),
    });
  }

  const skiOption = opts.subjectKeyIdentifier ?? true;
  let ski: Uint8Array | undefined;
  if (skiOption !== false) {
    const hash = typeof skiOption === 'object' ? skiOption.hash : 'sm3';
    const digest = hash === 'sha1' ? sha1Hex(publicKey) : sm3.hash(publicKey);
    ski = hexToBytes(digest, 'subjectKeyIdentifier').slice(0, 20);
    list.push({
      oid: OID_SUBJECT_KEY_IDENTIFIER,
      critical: false,
      value: encodeSubjectKeyIdentifier(ski),
    });
  }

  const wantAki = opts.authorityKeyIdentifier ?? true;
  if (wantAki) {
    const aki = opts.signer.certificate?.subjectKeyIdentifier ?? (selfSigned ? ski : undefined);
    if (aki !== undefined) {
      list.push({
        oid: OID_AUTHORITY_KEY_IDENTIFIER,
        critical: false,
        value: encodeAuthorityKeyIdentifier(aki),
      });
    }
  }

  return { list };
}

// ---------- 辅助 ----------

function resolveSubjectPublicKey(opts: IssueCertificateOptions): Uint8Array {
  if (opts.subjectPublicKey !== undefined) {
    return readPublicKey(opts.subjectPublicKey, 'subjectPublicKey');
  }
  if (opts.signer.certificate !== undefined) {
    throw new CertificateError('subjectPublicKey is required when signing with a CA certificate');
  }
  return readPublicKey(sm2.getPublicKey(opts.signer.privateKey), 'signer public key');
}

function readPublicKey(input: string | Uint8Array, where: string): Uint8Array {
  if (typeof input === 'string' && input.includes('-----BEGIN')) {
    try {
      return new Uint8Array(parseSm2PublicKeyPem(input));
    } catch (err) {
      throw new CertificateError(`${where}: invalid SM2 public key PEM`, { cause: err });
    }
  }
  const bytes = typeof input === 'string' ? toBytes(input, where) : new Uint8Array(input);
  return normalizePublicKey(bytes);
}

function nameToInput(name: Name): DistinguishedNameInput {
  return {
    // Name.commonName 理论上可缺失；encodeName 会在全空时报错。
    commonName: name.commonName ?? '',
    ...(name.organization === undefined ? {} : { organization: name.organization }),
    ...(name.organizationalUnit === undefined
      ? {}
      : { organizationalUnit: name.organizationalUnit }),
    ...(name.country === undefined ? {} : { country: name.country }),
    ...(name.state === undefined ? {} : { state: name.state }),
    ...(name.locality === undefined ? {} : { locality: name.locality }),
    ...(name.emailAddress === undefined ? {} : { emailAddress: name.emailAddress }),
  };
}

function randomSerialNumber(): bigint {
  for (;;) {
    const bytes = randomBytes(16);
    // 最高位清零：编码时无需额外补 0x00，也满足“正整数”约束。
    bytes[0] = (bytes[0] as number) & 0x7f;
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    if (value > 0n) return value;
  }
}

const FIELD_BY_LABEL: Readonly<Record<string, keyof DistinguishedNameInput>> = {
  CN: 'commonName',
  '2.5.4.3': 'commonName',
  O: 'organization',
  '2.5.4.10': 'organization',
  OU: 'organizationalUnit',
  '2.5.4.11': 'organizationalUnit',
  C: 'country',
  '2.5.4.6': 'country',
  ST: 'state',
  '2.5.4.8': 'state',
  L: 'locality',
  '2.5.4.7': 'locality',
  EMAILADDRESS: 'emailAddress',
  E: 'emailAddress',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

function splitUnescaped(input: string, separator: string): string[] {
  const parts: string[] = [];
  let current = '';
  let escaped = false;
  for (const ch of input) {
    if (escaped) {
      current += `\\${ch}`;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === separator) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (escaped) throw new CertificateError('parseDistinguishedName: trailing escape');
  parts.push(current);
  return parts;
}

function indexOfUnescaped(input: string, target: string): number {
  let escaped = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i] as string;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === target) return i;
  }
  return -1;
}

function decodeEscapes(input: string): string {
  let out = '';
  let escaped = false;
  for (const ch of input) {
    if (escaped) {
      out += ch;
      escaped = false;
    } else if (ch === '\\') {
      escaped = true;
    } else {
      out += ch;
    }
  }
  if (escaped) throw new CertificateError('parseDistinguishedName: trailing escape');
  return out;
}

/** 保留类型引用，供生成的声明文件使用。 */
export type { Certificate };

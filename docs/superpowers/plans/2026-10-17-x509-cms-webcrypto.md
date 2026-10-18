# X.509 / CMS SignedData / WebCrypto 适配层 — Implementation Plan

> **For agentic workers:** 用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务执行。步骤用复选框（`- [x]`）跟踪。
>
> **状态：已完成（2026-10-18）。** 范围由用户指定：X.509 解析（只读）、X.509 签发（自签 + 简单 CA）、CMS SignedData 签名/验签、WebCrypto 适配层（精选子集）。文末 5 个决策已全部采用推荐项。四阶段在同一工作区一次性完成，发布以单个 `v0.7.0` tag 收口（未拆 0.4.0–0.6.0 的中间可构建快照）。

**Goal:** 在现有算法库之上补一层 PKI / 协议能力，让调用方可以：读国密证书、签发内网/测试证书、对报文做 CMS 签名与验签、用 `crypto.subtle` 风格调用 SM2/SM3/SM4。算法实现（`src/sm2|sm3|sm4`）不重写，全部复用。

**由来:** 2026-10-17 评估 Non-Goal 清单时确认：X.509 解析与签发是国密项目的高频缺口（拿到 SM2 证书读不出公钥/SAN/用途；内网与设备证书需要自签）；CMS SignedData 覆盖电子签章/接口签名的大部分需求；WebCrypto 适配层降低前端接入成本。证书链路径校验、CMS EnvelopedData、时间戳仍不做。

**Spec:** 无独立 spec；本计划自带设计。既有 spec：`docs/superpowers/specs/2026-10-13-sm-crypto-wasm-design.md`（其中 X.509/PKCS#7/CMS、WebCrypto 两条 Non-Goal 需要在本计划交付后同步修订）。

---

## 现状盘点（开工前核对）

| 能力 | 现状 | 差距 |
|---|---|---|
| ASN.1 解析/编码 | `src/pem/asn1.ts`（321 行）：DER definite-length，仅 INTEGER / BIT STRING / OCTET STRING / NULL / OID / SEQUENCE | 缺 BER indefinite-length、context/application tag、SET、BOOLEAN、时间、字符串、显式/隐式标签；`encodeDer` 重建 tag byte 时不带 constructed/class 位；`decodeOid` 用 32 位整数累加；`encodeOid` 首字节未走 base128 |
| SM2 密钥编解码 | `src/pem/pkcs8.ts`、`src/pem/sm2.ts`：PKCS#8 / SEC1 / SPKI 的 **PEM** 形态 | WebCrypto 的 `importKey`/`exportKey` 要 **DER**（ArrayBuffer）；需要拆出 DER 版本的编解码函数 |
| SM2 签名格式 | `src/sm2/index.ts` 的 `sign` 返回 64 字节 `r‖s`（hex） | X.509 与 CMS 的签名值必须是 DER `SEQUENCE { INTEGER r, INTEGER s }`；需要双向转换 |
| X.509 | 无 | 全缺 |
| CMS / PKCS#7 | 无（`sm4` 里的 PKCS#7 只是填充，与此无关） | 全缺 |
| WebCrypto 适配 | 无（`src/runtime/random.ts` 只使用宿主 CSPRNG） | 全缺 |
| 测试基础设施 | vitest（Node + happy-dom 双 runner）、`tests/vectors/**` 预置向量、fast-check fuzz | 需要 X.509/CMS 的 OpenSSL 样本；Node 的 `X509Certificate` 对 SM2 支持不确定，不能当 oracle |
| CI | `.github/workflows/ci.yml`：lint/typecheck、build+test、wasm 体积、`pnpm pack --dry-run` | 需要加 openssl 版本检查与证书/CMS 互操作测试 |

---

## Global Constraints

沿用主 plan（`2026-10-13-sm-crypto-wasm.md`）与 hybrid plan 的约束，另加：

- **算法复用**：不新增 wasm，不重新实现 SM2/SM3/SM4；X.509/CMS/WebCrypto 只做编码、协议编排与参数转换。
- **同步优先不变**：X.509/CMS 的 API 是同步的（`ensureLoaded()` 预热后调用）；WebCrypto 适配层对外全异步（Promise），内部仍是同步计算。
- **不公开底层 DER/大数接口**（spec 的 Anti-Goal）：`src/asn1/`、`src/x509/encode.ts` 等编码细节不进入主入口导出。
- **随机数走宿主 CSPRNG**（`src/runtime/random.ts`）；序列号、SM2 密钥、SM4 密钥一律用宿主随机。
- **错误分层**：新增 `CertificateError`、`CmsError`，继承 `SmCryptoError`；WebCrypto 适配层把错误映射为 `DOMException`（`DataError` / `InvalidAccessError` / `OperationError` / `NotSupportedError`）。
- **三语同步**：新增公开 API 必须同时有中文 / English / Русский 的 README 段落与 website 页面。
- **子路径导出**：`sm-crypto-wasm/x509`、`/cms`、`/webcrypto`；主入口提供命名空间导出（`export * as x509 from './x509/index.js'`）。
- **每个阶段可独立发布**：阶段结束即打 minor tag，可单独回滚，不攒大版本。

---

## 密码学正确性红线（Review 时逐条核对）

| # | 红线 | 为什么 |
|---|---|---|
| 1 | **CMS 验签必须对 `signedAttrs` 的原始 DER 字节做摘要**，不得解析后重新编码 | DER 重编码不保证逐字节一致（SET 顺序、可选字段、长度编码），重编码会让合法签名验不过，或让攻击者构造编码歧义 |
| 2 | X.509/CMS 的 SM2 签名值必须是 DER `SEQUENCE { r, s }`，`r`/`s` 按 INTEGER 规则去前导零、必要时补 `0x00` | 直接塞 64 字节裸 `r‖s` 会产出非标准证书，OpenSSL/网关拒收 |
| 3 | 解析证书/CMS 时**拒绝尾部多余字节**（单个对象）与**截断**；对 BER indefinite-length 只在 CMS 路径启用 | 宽松解析是签名绕过与解析歧义的常见来源 |
| 4 | `basicConstraints.ca=false` 的证书**不得**用于签发子证书；签发时 `keyUsage` 含 `keyCertSign` 才允许当 CA | 否则等于自己造了一个不受约束的 CA |
| 5 | `subjectAltName` 的 `dNSName` 必须是 IA5String、`iPAddress` 必须是 4/16 字节；签发时校验输入 | 非法 SAN 会让浏览器/网关直接拒绝握手 |
| 6 | 序列号必须是**正整数**（最高位清零、非零、≥ 64 bit 随机） | 负序列号或 0 违反 RFC 5280，部分实现直接拒绝 |
| 7 | WebCrypto 适配层必须执行 `extractable` / `usages` 检查；`extractable=false` 时 `exportKey` 抛 `InvalidAccessError` | 否则“不可导出”只是装饰，安全语义不成立 |
| 8 | SM4-GCM 在 WebCrypto 路径下输出 `ciphertext ‖ tag`（tag 在尾部），与原生 `AES-GCM` 一致；`tagLength` 仅支持 128 | 与原生 API 的字节布局不一致会让“风格兼容”变成陷阱 |
| 9 | 证书/CMS 解析不得因未知扩展、未知算法、未知属性而抛错（保留 OID + critical + 原始值） | 国密证书常带私有扩展；抛错会让库无法处理真实证书 |
| 10 | 私钥、DEK、临时标量不得出现在错误消息、日志、序列化输出中 | 沿用主 plan 的安全红线 |

---

## 依赖关系

```
Phase 0 (ASN.1) ──> Phase 1 (X.509 解析) ──> Phase 2 (X.509 签发)
                                      └────> Phase 3 (CMS SignedData)
Phase 4 (WebCrypto) 可与 Phase 3 并行（只依赖现有 sm2/sm3/sm4 API）
```

Phase 0 是单点前置，必须先完成并通过全量回归；Phase 1 的解析器是 Phase 2/3 的共用基础。

---

## 阶段 0：ASN.1 基础设施（3–4 人日）

**目标：** 一个内部通用层，覆盖 X.509 与 CMS 需要的 BER/DER 子集，同时不破坏现有 `src/pem/*` 的行为。

### 任务

- [x] 新建 `src/asn1/types.ts`：`Asn1Node` 增加 `constructed: boolean`、`indefinite: boolean`、`raw: Uint8Array`（保留原始切片）；新增 `Asn1Class` 常量。
- [x] 新建 `src/asn1/decode.ts`：
  - [x] 支持 BER indefinite-length（`0x80` + EOC `0x00 0x00`），仅用于 CMS；
  - [x] 支持高 tag number（`0x1f` 后续 base128）；
  - [x] `parseDer`（严格：拒绝 indefinite、拒绝尾部多余字节）与 `parseBer`（宽松）；
  - [x] `parseDerAll`（bundle / 多对象）；
  - [x] 保留每个节点的 `raw`，供 CMS 验签与证书 TBS 使用。
- [x] 新建 `src/asn1/encode.ts`：
  - [x] `encode(node)` 按 `cls + constructed + tag` 重建首字节（修复现有 `encodeDer` 丢 constructed 位的问题）；
  - [x] 构造器：`seq` / `set` / `setOf` / `explicit` / `implicit` / `bitString` / `octetString` / `boolean` / `utf8String` / `printableString` / `ia5String` / `utcTime` / `generalizedTime` / `integer` / `oid` / `null`；
  - [x] DER 规则：SET OF 按编码字节排序、BOOLEAN 非默认值才编码、INTEGER 最小补码编码。
- [x] 新建 `src/asn1/oid.ts`：`decodeOid` 改 bigint 累加；`encodeOid` 首字节走 base128（修复 `2.999` 这类 OID）。
- [x] 新建 `src/asn1/time.ts`：`UTCTime`（1950–2049）与 `GeneralizedTime` 的编码/解析，接受无秒、带时区偏移的输入。
- [x] 迁移：`src/pem/asn1.ts` 改为 re-export `src/asn1/index.js`，保持导出符号不变；`pkcs8.ts` / `sm2.ts` 的导入指向新层。
- [x] 测试：`tests/asn1/` 覆盖 round-trip、indefinite-length、高 tag、SET 排序、时间边界（2049/2050）、OID 大组件、畸形输入。
- [x] 回归：`pnpm test` 全绿（现有 `tests/pem/*` 不改断言）。

### 验收

- `pnpm test` 与 `pnpm test:browser` 全绿；
- 新层对 OpenSSL 生成的证书 DER 能完整 round-trip（`parse → encode` 字节一致）；
- 不新增公开导出（`src/index.ts` 不变）。

---

## 阶段 1：X.509 解析（只读）（4–6 人日）

**目标：** `parseCertificate` / `parseCertificates`，把 DER/PEM/base64 证书变成结构化对象；不做链校验、不做 OCSP/CRL。

### API 草案

```ts
// sm-crypto-wasm/x509
export interface Certificate {
  readonly version: 1 | 2 | 3;
  readonly serialNumber: bigint;
  readonly serialNumberHex: string;      // 不带前导 0x；便捷字段，避免调用方自己转
  readonly signatureAlgorithm: AlgorithmIdentifier;
  readonly issuer: Name;
  readonly validity: { notBefore: Date; notAfter: Date };
  readonly subject: Name;
  readonly subjectPublicKeyInfo: SubjectPublicKeyInfo;
  readonly extensions: readonly Extension[];
  readonly signatureValue: Uint8Array;
  readonly tbsCertificate: Uint8Array;   // 原始字节，验签用
  readonly raw: Uint8Array;

  readonly subjectPublicKey: Uint8Array; // 裸公钥；SM2 为 64/65 字节
  readonly publicKeyAlgorithm: 'SM2' | 'RSA' | 'UNKNOWN';
  readonly supported: boolean;           // 本库能否使用该公钥（RSA=false，避免把“不支持”误判成“签名无效”）
  getExtension(oid: string): Extension | undefined;
  checkValidity(at?: Date): boolean;
  verifySignature(
    issuer: Certificate | Uint8Array,
    opts?: { userID?: Uint8Array },      // 预留：SM2 ZA 的用户标识
  ): boolean;
  fingerprint(hash?: 'sm3' | 'sha256'): string;
}

export function parseCertificate(input: string | Uint8Array): Certificate;
export function parseCertificates(input: string | Uint8Array): Certificate[]; // PEM bundle
```

`Name` 暴露 `commonName` / `organization` / `organizationalUnit` / `country` / `state` / `locality` / `emailAddress` 便捷字段 + `raw` + `toString()`（RFC 4514 风格）。

### 任务

- [x] `src/x509/oids.ts`：SM2 曲线、SM3withSM2、id-ecPublicKey、常用扩展 OID、Name 属性 OID。
- [x] `src/x509/parse.ts`：Certificate / TBSCertificate / AlgorithmIdentifier / Name / Validity / SPKI / Extension 的解析。
- [x] 非 SM2 证书（RSA 等）：正常解析字段并用 `publicKeyAlgorithm` 标注；`verifySignature` 返回 `false` 且 `supported=false`，不把「不支持」误报成「签名无效」。
- [x] 时间规范化到秒（X.509 精度）：`Date` 的毫秒部分截断，保证 `parse → encode` 的 round-trip 一致。
- [x] `src/x509/extensions.ts`：解析 KeyUsage、BasicConstraints、SubjectAltName、SubjectKeyIdentifier、AuthorityKeyIdentifier、ExtendedKeyUsage；未知扩展保留 `{ oid, critical, value }`。
- [x] `src/x509/verify.ts`：单证书验签（SM3withSM2：`ZA` 默认 `1234567812345678`，签名值 DER→`r‖s`）+ `checkValidity`。
- [x] `src/x509/errors.ts`：`CertificateError extends SmCryptoError`。
- [x] `src/x509/index.ts` + `package.json` 的 `./x509` 子路径 + `src/index.ts` 命名空间导出。
- [x] 测试：`tests/x509/parse.spec.ts`、`tests/x509/verify.spec.ts`；向量放 `tests/vectors/x509/`（见下）。
- [x] 文档：README 三语 + `website/{,en/,ru/}guide/` 新增 X.509 小节。

### 测试向量（提交到仓库，注明生成命令）

- SM2 自签根 CA（v3，BasicConstraints CA=true，KeyUsage keyCertSign/cRLSign）；
- SM2 中间 CA + SM2 终端证书（SAN dNSName/iPAddress、EKU serverAuth）；
- SM2 签名证书 + SM2 加密证书（双证书各一张）；
- 过期证书、`notBefore` 在未来的证书；
- RSA 自签证书（负例：能解析字段，`verifySignature` 返回 false / 抛 `CertificateError`）。

生成命令写进 `tests/vectors/x509/README.md`（OpenSSL 3.x，`openssl req -x509 -newkey sm2 ...`）。

### 验收

- 解析结果与 `openssl x509 -text -noout` 逐字段一致（测试中固定断言关键字段）；
- DER / PEM / base64 三种输入等价；
- 未知扩展、未知签名算法不抛错；
- 篡改 TBS 任意字节后 `verifySignature` 返回 false；
- `pnpm test` 全绿。

---

## 阶段 2：X.509 签发（自签 + 简单 CA）（4–5 人日）

**目标：** 生成符合 RFC 5280 / GM/T 0015 的 SM2 证书；支持自签与用一张 CA 证书签发终端证书。

### API 草案

```ts
export interface DistinguishedNameInput {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;          // 2 字母
  state?: string;
  locality?: string;
  emailAddress?: string;
}

export interface IssueCertificateOptions {
  subject: DistinguishedNameInput;
  issuer?: DistinguishedNameInput;                 // 缺省 = subject（自签）
  serialNumber?: bigint;                           // 缺省：16 字节随机正整数
  notBefore?: Date;                                // 缺省：now - 5min
  notAfter: Date;
  keyUsage?: KeyUsage[];
  extendedKeyUsage?: string[];
  basicConstraints?: { ca: boolean; pathLen?: number };
  subjectAltNames?: { type: 'dns' | 'ip' | 'email' | 'uri'; value: string }[];
  subjectKeyIdentifier?: boolean | { hash: 'sm3' | 'sha1' }; // 缺省 true（SM3 前 20 字节）
  authorityKeyIdentifier?: boolean;                // 有 issuer 时缺省 true
  signer: {
    privateKey: string | Uint8Array;
    publicKey?: string | Uint8Array;
    certificate?: Certificate;                     // 或直接给签发者证书
  };
}

export function issueCertificate(opts: IssueCertificateOptions): {
  pem: string;
  der: Uint8Array;
  certificate: Certificate;
};

export function createSelfSignedCertificate(
  opts: Omit<IssueCertificateOptions, 'issuer' | 'signer'> & { privateKey: string | Uint8Array },
): { pem: string; der: Uint8Array; certificate: Certificate };
```

### 任务

- [x] `src/x509/encode.ts`：TBSCertificate、Name、Validity、SPKI、Extensions 的 DER 编码；`r‖s` ↔ DER `SEQUENCE { r, s }` 转换（放在 `src/x509/sig.ts`，CMS 复用）。
- [x] `src/x509/issue.ts`：自签与 CA 签发；`issuer` 缺省取 `subject`；AKI 用签发者证书的 SKI；SKI 默认 `SM3(公钥)` 前 20 字节，接受 `{ hash: 'sha1' }` 以兼容 OpenSSL 默认（避免外部 CA 的 AKI 匹配失败）。
- [x] DN 字符串解析：`"CN=foo,O=bar,C=CN"` → `DistinguishedNameInput`（仅支持 `,` 分隔与反斜杠转义；不做完整 RFC 4514）。
- [x] 时间编码：1950–2049 用 UTCTime，其余用 GeneralizedTime；`notAfter` 必须晚于 `notBefore`。
- [x] 输入校验：`country` 2 字母、SAN IP 合法、`basicConstraints.ca=false` 时禁止 `keyCertSign`（红线 #4/#5）。
- [x] 测试：`tests/x509/issue.spec.ts`；自签证书用 `openssl verify -CAfile` 交叉验证；CA→终端链用 `openssl verify -CAfile ca.pem leaf.pem`。
- [x] 文档：签发示例（自签 + CA）+ 安全边界说明（不生成密钥、不管理私钥）。

### 验收

- `openssl verify -CAfile self.pem self.pem` 通过；
- `openssl verify -CAfile ca.pem leaf.pem` 通过；
- `openssl x509 -text` 中版本、序列号、DN、有效期、KU/BC/SAN/SKI/AKI 全部正确；
- 签发结果能被阶段 1 的解析器 round-trip；
- 非法输入（负序列号、CA=false + keyCertSign、非法 IP）抛 `RangeError` / `CertificateError`。

---

## 阶段 3：CMS SignedData 签名/验签（8–12 人日）

**目标：** detached / attached 两种模式的 SM2 签名与验签，支持证书集合与 `signedAttrs`；只做 SignedData，不做 EnvelopedData / 时间戳。

### API 草案

```ts
export interface SignDataOptions {
  data: string | Uint8Array;
  privateKey: string | Uint8Array;
  certificate?: Certificate | string | Uint8Array;
  certificates?: (Certificate | string | Uint8Array)[];
  detached?: boolean;                 // 默认 true
  signingTime?: Date | false;         // 默认 now
}

export function signData(opts: SignDataOptions): {
  der: Uint8Array;
  pem: string;
  base64: string;
};

export interface VerifySignedDataOptions {
  detachedData?: string | Uint8Array;
  certificates?: (Certificate | string | Uint8Array)[];
}

export interface VerifySignedDataResult {
  valid: boolean;
  signers: {
    valid: boolean;
    certificate?: Certificate;
    signingTime?: Date;
    error?: string;
    errorCode?: 'NO_CERTIFICATE' | 'DIGEST_MISMATCH' | 'SIGNATURE_INVALID' | 'UNSUPPORTED_ALGORITHM' | 'MALFORMED';
  }[];
}

export function verifySignedData(
  cms: string | Uint8Array,
  opts?: VerifySignedDataOptions,
): VerifySignedDataResult;
```

### 任务

- [x] `src/cms/parse.ts`：ContentInfo / SignedData / EncapsulatedContentInfo / SignerInfo / 证书集合；**保留 `signedAttrs` 原始字节**（红线 #1）。
- [x] `src/cms/sign.ts`：构造 `signedAttrs`（contentType + messageDigest + signingTime）→ 用原始 DER 编码做 SM3 摘要 → SM2 签名 → DER 签名值 → 组装 SignedData。
- [x] `src/cms/verify.ts`：按 `issuerAndSerialNumber` 或 `subjectKeyIdentifier` 匹配证书；优先用 CMS 内嵌证书，其次用调用方传入；对原始 `signedAttrs` 做摘要后验签；`detached` 时校验 `detachedData` 的摘要。
- [x] `src/cms/verify.ts` 的失败原因用结构化 `errorCode` 返回（`NO_CERTIFICATE` / `DIGEST_MISMATCH` / `SIGNATURE_INVALID` / `UNSUPPORTED_ALGORITHM` / `MALFORMED`），`error` 仅作人类可读补充。
- [x] `src/cms/errors.ts`：`CmsError extends SmCryptoError`。
- [x] `src/cms/index.ts` + `package.json` 的 `./cms` 子路径 + 主入口命名空间。
- [x] 测试：`tests/cms/sign.spec.ts`、`tests/cms/verify.spec.ts`、`tests/cms/interop.spec.ts`。
- [x] 向量：`tests/vectors/cms/`（detached/attached、单签名者、BER indefinite-length、篡改样本）。
- [x] 文档：三语 README + website；说明「只验签名、不建信任链」。

### 互操作测试（本阶段的核心验收）

- 本库 `signData` → `openssl cms -verify -inform DER -content data.bin -noverify` 通过；
- `openssl cms -sign -in data.bin -signer cert.pem -inkey key.pem -outform DER` → 本库 `verifySignedData` 通过；
- detached 与 attached 各一组；
- 篡改 1 字节 → `valid=false`；
- 签名者证书不在集合中 → `valid=false` 且 `error` 可读。

### 验收

- 上述互操作全绿；
- BER indefinite-length 样本可解析并验签；
- `pnpm test` + `pnpm test:browser` 全绿；
- 不实现链校验（只验单证书签名），文档明确。

---

## 阶段 4：WebCrypto 适配层（精选子集）（5–8 人日）

**目标：** 一个 `crypto.subtle` 风格的独立对象 `smCrypto.subtle`（不是原生 `crypto.subtle` 的 polyfill），覆盖 SM2 / SM3 / SM4 的常用操作。

### 范围

| WebCrypto `name` | 底层 | 操作 | 备注 |
|---|---|---|---|
| `SM3` | `sm3.hash` | `digest` | |
| `HMAC`（`hash: 'SM3'`） | `sm3.hmac` | `sign` / `verify` | `importKey('raw')` |
| `SM4-CBC` | `encryptCBC` / `decryptCBC` | `encrypt` / `decrypt` | PKCS#7 填充，IV 16 字节 |
| `SM4-CTR` | `cryptCTR` | `encrypt` / `decrypt` | `length` 仅支持 128；其它值抛 `NotSupportedError` |
| `SM4-GCM` | `encryptGCM` / `decryptGCM` | `encrypt` / `decrypt` | 输出 `ct‖tag`；`tagLength` 仅 128 |
| `SM4-ECB` | `encryptECB` / `decryptECB` | `encrypt` / `decrypt` | 扩展名（WebCrypto 无 ECB） |
| `SM4-CFB` / `SM4-OFB` | `encryptCFB` / `cryptOFB` | `encrypt` / `decrypt` | 扩展名 |
| `SM2` | `sm2.sign` / `verify` / `encrypt` / `decrypt` | `sign` / `verify` / `encrypt` / `decrypt` | 自定义算法名；`userID` 可选 |

**不做：** JWK、`deriveKey`/`deriveBits`、`wrapKey`/`unwrapKey`、`CryptoKey` 的 `postMessage` 克隆语义、SM9/ZUC 进入 subtle。

### API 草案

```ts
import { subtle, CryptoKey } from 'sm-crypto-wasm/webcrypto';

const { publicKey, privateKey } = await subtle.generateKey(
  { name: 'SM2' },
  true,
  ['sign', 'verify'],
);
const sig = await subtle.sign({ name: 'SM2' }, privateKey, data);
const ok = await subtle.verify({ name: 'SM2' }, publicKey, sig, data);

const key = await subtle.generateKey({ name: 'SM4-GCM', length: 128 }, true, ['encrypt', 'decrypt']);
const ct = await subtle.encrypt({ name: 'SM4-GCM', iv, additionalData }, key, plain);
```

### 任务

- [x] `src/webcrypto/algorithms.ts`：算法名归一化（大小写不敏感）、参数校验、算法类别表。
- [x] `src/webcrypto/cryptoKey.ts`：`CryptoKey` 类；材料存 `WeakMap`；只读 `type` / `extractable` / `algorithm` / `usages`。
- [x] 材料用联合类型 `KeyMaterial = { kind: 'bytes'; bytes: Uint8Array } | { kind: 'provider'; provider: KeyProvider }`；v1 只实现 `bytes`，为将来 HSM/RemoteSigner 留口子（不改变公共 API）。
- [x] `src/webcrypto/subtle.ts`：`generateKey` / `importKey` / `exportKey` / `digest` / `sign` / `verify` / `encrypt` / `decrypt`。
- [x] `src/webcrypto/errors.ts`：`SmCryptoError` → `DOMException` 映射（`NotSupportedError` / `InvalidAccessError` / `DataError` / `OperationError`）。
- [x] `src/webcrypto/index.ts` + `package.json` 的 `./webcrypto` 子路径 + 主入口命名空间。
- [x] 密钥格式：`raw`（SM4/HMAC）、`pkcs8`（SM2 私钥 DER）、`spki`（SM2 公钥 DER）；需要从 `src/pem/*` 拆出 DER 版本（不新写编码逻辑）。
- [x] 与 X.509 协同：`importKey('spki', cert.subjectPublicKeyInfoRaw)` 可直接用于验签。
- [x] 测试：`tests/webcrypto/` 覆盖每个算法、`usages` 负例、`extractable` 负例、错误映射、GCM tag 布局、SM2 签名与 `sm2.sign` 一致。
- [x] 文档：三语 README + website；明确「不是原生 `crypto.subtle` 的 polyfill，生态库不会自动识别」。

### 验收

- 每个算法与对应底层 API 的结果逐字节一致；
- `usages` 不含 `sign` 的 key 调 `sign` 抛 `InvalidAccessError`；
- `extractable=false` 时 `exportKey` 抛 `InvalidAccessError`；
- 未知算法名抛 `NotSupportedError`；
- `pnpm test:browser` 在 happy-dom 下全绿；
- 不导出 `src/asn1/*` 的内部符号。

---

## 测试与向量策略

- **固定样本优先**：X.509/CMS 样本提交到 `tests/vectors/x509|`、`tests/vectors/cms/`，附生成命令与 OpenSSL 版本；CI 不依赖动态生成。
- **动态互操作**：`tests/cms/interop.spec.ts` 在 `openssl` 可用时跑（`execFileSync('openssl', ['version'])` 探测），缺失时 `describe.skip`；Windows 开发机没有 openssl 也能跑全量单测。
- **fuzz**：`tests/fuzz/x509.spec.ts`、`tests/fuzz/cms.spec.ts` 用 fast-check 随机字节喂解析器，断言“只抛 `CertificateError`/`CmsError`，不崩溃、不 OOM”。
- **负例必测**：截断 DER、尾部多余字节、indefinite-length 在 X.509 路径被拒、未知 critical 扩展、错误曲线、篡改 TBS、篡改 `signedAttrs`、空证书集合。
- **CI 增量**：`.github/workflows/ci.yml` 加 `openssl version` 打印；固定样本不依赖版本；`pnpm pack --dry-run` 确认 `dist/x509`、`dist/cms`、`dist/webcrypto` 进入包。

---

## 文档与发布

- **README 三语**：每个阶段新增对应段落；「不在范围」里删除已交付项，保留未交付项。
- **website 三语**：`website/guide/`、`website/en/guide/`、`website/ru/guide/` 新增页面；`website/.vitepress/config.ts` 增加侧边栏项。
- **spec 修订**：`docs/superpowers/specs/2026-10-13-sm-crypto-wasm-design.md` 的 Non-Goals 改为「已交付（附版本）」/「仍不做」，避免文档自相矛盾。
- **发布节奏（实际）**：原计划每阶段打 minor tag；四阶段一次性完成，以 `v0.7.0` 单 tag 收口（0.4.0–0.6.0 的中间版本未单独产出）。
- **体积预算（2026-10-18 实测，gzip、不含 wasm）**：
  - x509 解析子集 **10.8 KB**（原预算 15 KB）；
  - x509 全量（解析 + 签发）**18.1 KB**（原预算 15 KB；签发阶段新增 DER 编码与输入校验，预算调整为 20 KB）；
  - cms **6.9 KB**（预算 20 KB）；
  - webcrypto **6.1 KB**（预算 10 KB）。
  CI 已按上述阈值检查。

---

## 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| ASN.1 层是单点前置，设计不足会拖累后三个阶段 | 高 | Phase 0 先落地并用 OpenSSL 样本做 round-trip；后续阶段只加构造器不改核心 |
| CMS `signedAttrs` 重编码导致验签不一致 | 高 | 强制保留原始 `raw`；测试用 openssl 双向互操作 |
| SM2 签名值 DER 转换错误 | 高 | 独立 `src/x509/sig.ts` + 单测 + openssl 交叉验证 |
| OpenSSL 版本/算法支持差异 | 中 | 固定样本入库；动态测试探测后 skip；CI 打印版本 |
| 证书链校验需求被误认为已支持 | 中 | API 不提供 `validateChain`；文档与错误消息明确边界 |
| 包体积增长 | 中 | 子路径导出 + tree-shaking；CI 体积检查 |
| 私有扩展/非标准 OID 导致解析崩溃 | 中 | 未知扩展保留原始值；fuzz 覆盖 |
| 阶段 3 工期超预期 | 中 | 先交付 detached 单签名者；attached、多签名者、BER 作为增量 |

---

## 已拍板（2026-10-17）

全部采用推荐项；后续有真实需求再增量补齐：

1. **版本策略**：分阶段 4 个 minor（0.4.0 X.509 解析 → 0.5.0 签发 → 0.6.0 CMS → 0.7.0 WebCrypto），每阶段可独立发布/回滚。
2. **SKI 默认摘要**：SM3 前 20 字节；API 接受 `{ hash: 'sha1' }` 兼容 OpenSSL 默认。
3. **RSA 证书**：只解析字段；`verifySignature` 返回 `false` 且 `supported=false`，不引入 RSA 实现。
4. **SM4-CTR 的 `length`**：只支持 128；其它值抛 `NotSupportedError`。
5. **CMS 多签名者**：v1 签名只出单签名者；解析与验签保留多签名者数组结构。

### 为「以后补」预留的口子（零成本，现在做）

- `CryptoKey` 材料用 `KeyMaterial` 联合类型（`{ kind: 'bytes' } | { kind: 'provider' }`），v1 只实现 bytes；将来接 HSM/RemoteSigner 不改公共 API；
- `verifySignedData` 返回结构化 `errorCode`，避免以后改返回类型；
- 证书暴露 `raw` / `tbsCertificate`，CMS 暴露 `der`，需要原始字节时不必公开 ASN.1 解析器；
- 证书时间统一规范化到秒，避免 `Date` 毫秒导致 round-trip 不一致；
- `serialNumberHex` 与 `bigint` 并存，避免调用方各自转换。

---

## 明确不做

- 证书链路径校验、策略校验、名称约束；
- CRL / OCSP / AIA 拉取；
- CMS EnvelopedData、RFC 3161 时间戳、属性证书；
- JWK、`deriveKey`、`wrapKey`；
- HSM / PKCS#11 / SDF 后端（只保留将来用 provider 抽象的扩展点）；
- 在浏览器里挂载到原生 `crypto.subtle`（平台不允许注册算法）。

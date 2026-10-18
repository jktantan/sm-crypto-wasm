# CMS SignedData

`sm-crypto-wasm/cms` 提供 SM2 的 CMS SignedData 签名与验签：

- detached（默认）与 attached 两种模式；
- 构造 `contentType` / `messageDigest` / `signingTime` 三个签名属性；
- 验签时对 `signedAttrs` 的**原始 DER 字节**做摘要，不重新编码；
- 支持 BER indefinite-length 输入；
- 返回结构化失败原因。

只做 SignedData，不做 EnvelopedData / RFC 3161 时间戳；**不建立信任链**，
不检查证书有效期、用途或 CRL/OCSP。

## 签名

```ts
import { cms, sm2, sm3 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();
await sm3.ensureLoaded();

const signed = cms.signData({
  data: '报文内容',               // 字符串按 UTF-8 编码（不是 hex/base64）
  privateKey: privateKeyPem,
  certificate: certificatePem,    // 签名者证书
  certificates: [caPem],          // 可选：额外链证书
  detached: true,                 // 默认 true
  signingTime: new Date(),        // 默认当前时间；false 表示不加入
});

signed.der;     // Uint8Array
signed.pem;     // -----BEGIN CMS-----
signed.base64;  // base64
```

签名者标识使用 `issuerAndSerialNumber`（取自签名者证书）。

## 验签

```ts
const result = cms.verifySignedData(signed.der, {
  detachedData: '报文内容',
  certificates: [extraPem],       // 可选：补充候选证书
});

result.valid;                     // 所有签名者都有效才为 true
result.signers[0]?.valid;
result.signers[0]?.certificate;   // 内嵌或调用方提供的证书
result.signers[0]?.signingTime;
result.signers[0]?.errorCode;     // 失败时的结构化原因
result.signers[0]?.error;         // 人类可读补充
```

`errorCode`：

| 值 | 含义 |
| --- | --- |
| `NO_CERTIFICATE` | CMS 未内嵌签名者证书，调用方也未提供 |
| `DIGEST_MISMATCH` | `messageDigest` / `contentType` 与内容不一致 |
| `SIGNATURE_INVALID` | 签名值结构非法或 SM2 验签失败 |
| `UNSUPPORTED_ALGORITHM` | 摘要或签名算法不是 SM3 / SM3withSM2 |
| `MALFORMED` | CMS 结构非法，或 detached 模式缺少 `detachedData` |

结构完全无法解析时返回 `MALFORMED` 结果而不是抛错；wasm 未预热等环境
错误仍会抛出。

## 输入格式

`verifySignedData` / `parseSignedData` 接受：

- PEM（`-----BEGIN CMS-----` 或 `-----BEGIN PKCS7-----`）；
- base64 / hex；
- DER 或 BER 字节。

## 用户标识

CMS 签名默认使用**空** SM2 用户标识，与 OpenSSL 的 CMS 路径一致。
如需 GM/T 默认标识：

```ts
import { DEFAULT_SM2_USER_ID } from 'sm-crypto-wasm/x509';

cms.signData({ data, privateKey, certificate, userID: DEFAULT_SM2_USER_ID });
cms.verifySignedData(der, { detachedData: data, userID: DEFAULT_SM2_USER_ID });
```

省略 `userID` 验签时，先试空标识，再试 GM/T 默认标识。

## 安全边界

- 只验证“签名与内容一致”，**不验证证书是否可信**；调用方必须自行完成
  证书链/策略/有效期判断；
- 不对 `certificate` 的用途做检查；
- `signData` 不生成密钥、不管理私钥。

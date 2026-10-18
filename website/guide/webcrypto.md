# WebCrypto 适配层

`sm-crypto-wasm/webcrypto` 提供一个 **独立**的 `subtle` 对象，API 形态与
`crypto.subtle` 一致，但算法是 SM2 / SM3 / SM4。

::: warning 不是 polyfill
浏览器不允许注册自定义算法，本模块**不会**挂到原生 `crypto.subtle` 上，
第三方生态库也不会自动识别它。请显式使用 `sm-crypto-wasm/webcrypto`。
:::

```ts
import { subtle, CryptoKey } from 'sm-crypto-wasm/webcrypto';
```

所有方法都是异步的；首次调用时按算法自动加载对应 wasm。

## 摘要

```ts
const digest = await subtle.digest('SM3', data);
// ArrayBuffer(32)
```

## HMAC

```ts
const hmacKey = await subtle.importKey(
  'raw',
  keyBytes,
  { name: 'HMAC', hash: 'SM3' },
  true,
  ['sign', 'verify'],
);

const mac = await subtle.sign({ name: 'HMAC' }, hmacKey, data);
const ok = await subtle.verify({ name: 'HMAC' }, hmacKey, mac, data);
```

`generateKey({ name: 'HMAC', hash: 'SM3', length: 256 }, ...)` 可生成随机密钥
（`length` 为比特，必须是 8 的倍数）。

## SM2

```ts
const { privateKey, publicKey } = await subtle.generateKey(
  { name: 'SM2' },
  true,
  ['sign', 'verify'],
);

const signature = await subtle.sign({ name: 'SM2' }, privateKey, data); // 64 字节 r‖s
const ok = await subtle.verify({ name: 'SM2' }, publicKey, signature, data);
```

- 签名格式为 64 字节 `r ‖ s`，与 `sm2.sign` 一致；
- 默认用户标识与 `sm2.sign` / `sm2.verify` 一致；可用 `{ name: 'SM2', userID }`
  指定；
- 密钥格式：`pkcs8`（私钥 DER）、`spki`（公钥 DER）；
- `exportKey('pkcs8' | 'spki', ...)` 可直接交给后端/HSM。

```ts
const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
const spki = await subtle.exportKey('spki', publicKey);

const imported = await subtle.importKey('spki', spki, { name: 'SM2' }, true, ['verify']);
```

## SM4

```ts
const key = await subtle.generateKey(
  { name: 'SM4-GCM', length: 128 },
  true,
  ['encrypt', 'decrypt'],
);

const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await subtle.encrypt(
  { name: 'SM4-GCM', iv, additionalData },
  key,
  plaintext,
);
const pt = await subtle.decrypt(
  { name: 'SM4-GCM', iv, additionalData },
  key,
  ct,
);
```

支持：`SM4-ECB` · `SM4-CBC` · `SM4-CTR` · `SM4-CFB` · `SM4-OFB` · `SM4-GCM`。

| 算法 | 参数 | 备注 |
| --- | --- | --- |
| `SM4-ECB` | — | 不填充，数据必须是 16 的倍数 |
| `SM4-CBC` | `iv` | PKCS#7 填充 |
| `SM4-CTR` | `iv`, `length` | `length` 仅 128 |
| `SM4-CFB` | `iv` | |
| `SM4-OFB` | `iv` | |
| `SM4-GCM` | `iv`, `additionalData?`, `tagLength?` | 输出 `ciphertext ‖ tag`；`tagLength` 仅 128 |

SM4 密钥固定 128 位，使用 `importKey('raw', keyBytes, { name: 'SM4-*' }, ...)`。

## extractable / usages

- `extractable === false` 的密钥调用 `exportKey` 抛 `InvalidAccessError`；
- 密钥的 `usages` 不包含目标操作时抛 `InvalidAccessError`；
- `generateKey` 对 SM2 自动过滤不适用于对应密钥的 usages：
  - 私钥保留 `sign` / `decrypt`；
  - 公钥保留 `verify` / `encrypt`。

## 错误映射

| 情况 | DOMException |
| --- | --- |
| 未知算法 / 格式 / 不支持的参数 | `NotSupportedError` |
| 用途或 `extractable` 不允许 | `InvalidAccessError` |
| 密钥/数据格式非法 | `DataError` |
| 加解密/验签失败 | `OperationError` |

## 范围

| 能力 | 状态 |
| --- | --- |
| `SM3` digest | ✅ |
| `HMAC(SM3)` sign / verify | ✅ |
| `SM2` sign / verify、pkcs8/spki | ✅ |
| SM4 六种模式 | ✅ |
| `CryptoKey` / `extractable` / `usages` | ✅ |
| JWK | ❌ |
| `deriveKey` / `deriveBits` | ❌ |
| `wrapKey` / `unwrapKey` | ❌ |
| 挂载到原生 `crypto.subtle` | ❌（平台不允许） |

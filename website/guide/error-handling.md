# 错误处理

所有**"因输入而拒绝"**的错误都是 `SmCryptoError` 的子类，按**修复路径**分成两支：
密钥问题与密文问题。

```text
SmCryptoError
├── InvalidKeyError                密钥 / 标量输入有问题
│   └── InvalidPublicKeyError      公钥不在曲线上、坐标越界
└── CiphertextError                密文 / 签名 / 协议消息有问题
    ├── InvalidCiphertextError     结构不对（长度、ASN.1、点编码）
    └── DecryptionError            结构合法但校验不通过（C3 SM3 / GCM tag / C3 HMAC）
```

判断"这是不是这个库因输入而拒绝"：

```ts
import { isSmCryptoError } from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (isSmCryptoError(e)) { /* 输入被本库拒绝 */ }
}
```

## 按具体类型分流

```ts
import {
  DecryptionError, CiphertextError, InvalidCiphertextError,
  InvalidKeyError, InvalidPublicKeyError,
} from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (e instanceof DecryptionError) {
    // 结构合法但校验失败：密钥不匹配，或密文被改动
  } else if (e instanceof InvalidCiphertextError) {
    // 密文结构本身就不对（太短、不是合法点编码…）
  } else if (e instanceof CiphertextError) {
    // 上面两支的共同父类
  } else if (e instanceof InvalidPublicKeyError) {
    // 公钥不在曲线上
  } else if (e instanceof InvalidKeyError) {
    // 私钥 / 密钥格式或长度有问题
  } else {
    throw e;
  }
}
```

## 参数类型错误：不包装

只有"参数根本不是密码学对象"的错误才用宿主原生类型：

| 情况 | 抛出的类型 |
| --- | --- |
| 传了 `null` / `number` 之类 | `TypeError` |
| 空字符串输入（`toBytes('')`） | `TypeError` |
| 长度上限、计数器为负、非法枚举值 | `RangeError` |

这些**不会**被包成 `SmCryptoError` —— 它们不是"密码学意义上的拒绝"，是调用方写错了。

## `safeMode`：把密文支失败变成 `null`

不需要 `try / catch` 的场景（例如把校验结果当布尔用），用 `safeMode`：

```ts
// SM2
const pt = sm2.decrypt(priv, ct, { safeMode: true });   // string | null

// SM4-GCM
const pt2 = sm4.decryptGCM(key, iv, ct, tag, { aad, safeMode: true });  // string | null

// SM9
const pt3 = sm9.decrypt(ke, id, ct, { safeMode: true });  // string | null
```

`safeMode` **只吞密文支失败**。参数类型错误（`TypeError` / `RangeError`）照样抛出 ——
否则你写错参数时会得到一片 `null` 而查不出原因。

## 各算法的典型错误

| 操作 | 常见错误 |
| --- | --- |
| `sm4.encryptECB` | 明文长度不是 16 的非零倍数 → `RangeError` |
| `sm4.encryptCBC` / `decryptCBC` | key/iv 不是 16 字节 → `InvalidKeyError`；填充非法 → `DecryptionError` |
| `sm4.decryptGCM` | tag 被改 / AAD 不一致 → `DecryptionError` |
| `sm2.verify` | 公钥不在曲线上 → **不抛错，返回 `false`** |
| `sm2.encrypt` | 公钥不在曲线上 → `InvalidPublicKeyError` |
| `sm2.decrypt` | C3 校验失败 → `DecryptionError` |
| `sm9.decrypt` | C3 HMAC 校验失败 → `DecryptionError` |
| `zuc.zucEncrypt` | `(key, iv, counter)` 复用 → `InvalidKeyError` |

::: tip `verify` 的例外
`sm2.verify` / `sm9.verify` 在公钥非法或签名不对时**返回 `false`**，不抛错 ——
验签的"没通过"是正常业务结果，不该用异常表达。只有签名长度结构不对才抛
`InvalidCiphertextError`。
:::

# SM4 —— 分组密码

SM4 是国密分组密码（**GM/T 0002-2012**）：**128 位分组**、**128 位密钥**、32 轮。
本库的轮函数跑在 `sm4.wasm` 里，六种模式（ECB / CBC / CTR / CFB / OFB / GCM）都在
TS 层用块级调用拼装。

- 密钥长度固定 **16 字节**；
- 四种分组模式（ECB / CBC / CFB）的 IV 也固定 **16 字节**；GCM 的 IV 常用 12 字节；
- 加密与解密都返回 **hex 字符串**。

## 导入

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
```

## 模式怎么选

| 模式 | 需要 IV | 填充 | 错误传播 | 适用 |
| --- | --- | --- | --- | --- |
| ECB | 否 | 无 | — | **仅测试 / 兼容旧数据**；相同明文块产出相同密文块 |
| CBC | 16 B | PKCS#7 | 一个块损坏影响后一个块 | 通用场景的默认选择 |
| CTR | 16 B | 无 | 不影响其它块 | 流式、随机访问；**IV+counter 绝不可复用** |
| CFB | 16 B | 无 | 影响后续段 | 需要自同步流式的场景 |
| OFB | 16 B | 无 | 不影响其它块 | 对错误传播敏感的场景 |
| GCM | 12 B 常见 | 无 | — | **需要同时认证的推荐选择**（AEAD） |

::: tip 默认建议
需要机密性也要完整性 → **GCM**。只需要机密性、又不想管理填充 → **CTR**。
要给老系统做格式兼容 → 才考虑 ECB / CBC。
:::

## API

所有函数的密钥参数都接受 `string | Uint8Array`：字符串按 hex / base64 嗅探
（**没有 UTF-8 文本这回事**，密钥是字节）。返回值统一是小写 hex 字符串。

### 分组模式

| 函数 | 签名 | 说明 |
| --- | --- | --- |
| `encryptECB` | `(key, msg) => string` | 无填充；`msg` 长度必须是 **16 的非零倍数** |
| `decryptECB` | `(key, ct) => string` | 同上 |
| `encryptCBC` | `(key, iv, msg) => string` | PKCS#7 填充，`msg` 任意长度（含空） |
| `decryptCBC` | `(key, iv, ct) => string` | 自动去填充 |
| `encryptCFB` | `(key, iv, msg) => string` | CFB128，反馈取密文段 |
| `decryptCFB` | `(key, iv, ct) => string` | |

### 流模式

| 函数 | 签名 | 说明 |
| --- | --- | --- |
| `encryptCTR` / `decryptCTR` | `(key, iv, data) => string` | **同一个实现**（别名 `cryptCTR`），异或密钥流，长度任意 |
| `encryptOFB` / `decryptOFB` | `(key, iv, data) => string` | 同上（别名 `cryptOFB`） |

CTR / OFB 是对合的：`decrypt(encrypt(x)) === x`，所以加密解密共用入口。

### GCM（AEAD）

```ts
function encryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
  aad?: string | Uint8Array,
): { ct: string; tag: string }

function decryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
  tag: string | Uint8Array,
  aad?: string | Uint8Array | { aad?: string | Uint8Array; safeMode?: boolean },
): string
```

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | 是 | 16 字节 |
| `iv` | `string \| Uint8Array` | 是 | 不能为空；12 字节时按 GCM 规范直接用它做 J0 |
| `msg` / `ct` | `string \| Uint8Array` | 是 | **可以是空**（空明文合法） |
| `tag` | `string \| Uint8Array` | 解密时必填 | 16 字节认证标签 |
| `aad` | `string \| Uint8Array` | 否 | 附加认证数据，不加密但参与认证 |

`decryptGCM` 的第 5 个参数既可以传 `aad`，也可以传 `{ aad, safeMode: true }` ——
`safeMode` 让认证失败时返回 `null` 而不是抛 `DecryptionError`。

## 用法

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();

const key = '0123456789abcdeffedcba9876543210';  // 16 字节
const iv  = '000102030405060708090a0b0c0d0e0f';  // 16 字节

// ECB：无填充，长度必须是 16 的倍数
sm4.encryptECB(key, '00112233445566778899aabbccddeeff');

// CBC：PKCS#7 填充，任意长度
const ct = sm4.encryptCBC(key, iv, 'hello');
sm4.decryptCBC(key, iv, ct);                     // → '68656c6c6f'

// CTR / OFB：对合
sm4.encryptCTR(key, iv, '616263');
sm4.decryptCTR(key, iv, sm4.encryptCTR(key, iv, '616263'));

// GCM：额外拿到 16 字节 tag
const { ct: gcmCt, tag } = sm4.encryptGCM(key, iv, '616263', 'aabbccdd');
sm4.decryptGCM(key, iv, gcmCt, tag, 'aabbccdd');            // 校验通过才返回明文
sm4.decryptGCM(key, iv, gcmCt, tag, { aad: 'aabbccdd', safeMode: true });  // 失败 → null
```

## Playground

<Sm4Playground />

## 错误与边界

| 情况 | 抛出的错误 |
| --- | --- |
| `key` 不是 16 字节 | `InvalidKeyError` |
| CBC / CFB / OFB 的 `iv` 不是 16 字节 | `InvalidKeyError` |
| GCM 的 `iv` 为空 | `InvalidKeyError` |
| ECB 的明文长度不是 16 的非零倍数 | `RangeError` |
| ECB 的密文长度不是 16 的非零倍数 | `InvalidCiphertextError` |
| CBC 密文长度不是 16 的倍数 | `InvalidCiphertextError` |
| CBC 解密后 PKCS#7 填充非法 | `DecryptionError` |
| GCM 的 `tag` 不是 16 字节 | `InvalidCiphertextError` |
| GCM 认证失败（密文 / tag / AAD 任一被改） | `DecryptionError` |

传入非法枚举值之类"参数根本不是密码学对象"的错误，保留宿主原生 `TypeError` / `RangeError`。

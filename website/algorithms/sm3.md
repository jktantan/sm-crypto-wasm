# SM3 —— 摘要与 HMAC

SM3 是国密杂凑算法（**GM/T 0004-2012**），输出 **256 位（32 字节）** 摘要，与 SHA-256 同级别使用。
本库的实现跑在 `sm3.wasm` 里。

- 分组长度 512 位，摘要长度 256 位；
- 输入可以是任意比特串，**包括空串**（`l = 0`）；
- `hmac` 是 RFC 2104 形式的 HMAC-SM3，块长 64 字节。

## 导入

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();   // 首次使用前预热，之后全部同步
```

## API

### `sm3.ensureLoaded()`

```ts
function ensureLoaded(): Promise<void>
```

加载并实例化 `sm3.wasm`。**必须在使用 `hash` / `hmac` 前 `await` 一次**。
重复调用廉价（模块级 memoization，并发调用共用同一个 Promise）。

### `sm3.hash(input)`

```ts
function hash(input: string | Uint8Array): string
```

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `input` | `string \| Uint8Array` | 是 | 待摘要的消息 |

`input` 为字符串时按序嗅探编码：

| 起始特征 | 视为 |
| --- | --- |
| 以 `-----BEGIN` 开头 | PEM |
| 带 `0x` 前缀，或纯 `[0-9a-fA-F]` 且长度为偶数 | hex |
| 其它可被 `atob` 解码的字符串 | base64 |

**返回**：32 字节摘要的小写 hex（64 字符）。

**边界**：空输入按零长度消息处理（不是错误）—— SM3 对空串有唯一定义的结果。
想在"漏填参数"时报错的话，在调用方自己校验。

### `sm3.hmac(key, msg)`

```ts
function hmac(key: string | Uint8Array, msg: string | Uint8Array): string
```

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | 是 | 任意长度密钥；超过 64 字节会先被摘要一次 |
| `msg` | `string \| Uint8Array` | 是 | 消息 |

**返回**：32 字节 HMAC 的小写 hex。

两个参数的编码嗅探规则同 `hash`。

## 用法

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();

// 字符串 'abc' 的 UTF-8 字节
sm3.hash(new TextEncoder().encode('abc'));
// → '66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0'（去空格）

// hex 输入按字节解，等价于上面
sm3.hash('616263');

// 空串
sm3.hash('');

// HMAC-SM3（RFC 2104 形式）
sm3.hmac('00112233445566778899aabbccddeeff', '616263');
```

::: warning 字符串不是"文本"
`sm3.hash('abc')` 里的 `'abc'` **不是** UTF-8 文本 —— 它会被嗅探成 base64 尝试解码，
`'abc'` 恰好不是合法 hex，于是走 base64 分支（结果是 2 字节）。想摘要文本请显式
`new TextEncoder().encode(text)`，或传 hex 串。
:::

## Playground

下面这段直接在浏览器里加载 `sm3.wasm` 跑，不是预先录好的输出。消息编码下拉选
`utf8` 就是 `new TextEncoder().encode(text)` 那条路。

<Sm3Playground />

## 相关

- **[SM4](/algorithms/sm4)** 的 GCM 模式内部用 SM4 + GHASH，不依赖 SM3；
- **[SM2](/algorithms/sm2)** 的签名默认是 **SM3withSM2**，其 Z 值计算用 SM3；
- **[SM9](/algorithms/sm9)** 的用户密钥派生用 SM3 做 KDF 与 HMAC。

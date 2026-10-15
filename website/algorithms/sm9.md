# SM9 —— 标识密码

SM9 是基于双线性对（pairing）的**标识密码**算法（**GM/T 0044-2016** 系列）。
它最大的特点是：**用户标识（如邮箱）本身就是公钥**，不需要证书链 —— 由密钥生成中心
（KGC）用主私钥为每个标识派生用户私钥。

| 能力 | 标准 | 入口 |
| --- | --- | --- |
| 数字签名 | GM/T 0044.2 | `sign` / `verify` |
| 密钥交换 | GM/T 0044.3 | `createExchangeInitiator` / `createExchangeResponder` |
| 密钥封装与加密 | GM/T 0044.4 | `encrypt` / `decrypt`、`kemEncrypt` / `kemDecrypt` |

::: warning 两套主密钥不能混用
签名主密钥与加密主密钥是**相互独立**的两套（`purpose: 'sign' | 'enc'`）：
签名主公钥是 **G2 上的点**（128 字节），加密主公钥是 **G1 上的点**（64 字节）。
用错用途会在长度检查或配对校验上失败。
:::

主私钥 / 主公钥的用户私钥都按 **PKCS#8 + 自定义 OID `1.2.156.10197.1.100`** 编码成 PEM。

## 导入

```ts
import { sm9 } from 'sm-crypto-wasm';

await sm9.ensureLoaded();
```

## API

### `sm9.generateKeyPair(opts)`

```ts
function generateKeyPair(opts: {
  id: string | Uint8Array;          // 用户标识
  purpose?: 'sign' | 'enc';          // 默认 'sign'
}): Promise<Sm9KeyPair>
```

返回四份材料：

| 字段 | 用途 | 形态 |
| --- | --- | --- |
| `masterPrivatePem` | 主私钥（签名 `ks` / 加密 `ke`） | PKCS#8 PEM（32 字节标量） |
| `masterPublicPem` | 主公钥（签名 `[ks]P2` / 加密 `[ke]P1`） | SPKI PEM（G2 128B / G1 64B） |
| `userPrivatePem` | 用户私钥（`ds` G1 64B / `de` G2 128B） | PKCS#8 PEM |
| `userPublicPem` | 用户公钥 `Q = [H1(id,hid)]P + Ppub` | SPKI PEM |

`userPublicPem` 是 `(id, 主公钥)` 的**确定函数**，不是独立秘密 —— 第三方可用
`getUserPublicKey` 自行复算。

### 派生子公钥

| 函数 | 签名 | 返回 |
| --- | --- | --- |
| `getSignPublicKey` | `(ks: string \| Uint8Array) => string` | 128 字节 hex（G2 仿射） |
| `getEncPublicKey` | `(ke: string \| Uint8Array) => string` | 64 字节 hex（G1 仿射） |
| `getUserPublicKey` | `(masterPublicKey, id) => string` | SPI PEM |

三个函数的第一个参数都接受 32 字节裸主私钥（hex / `Uint8Array` / PKCS#8 PEM）。

### 签名 / 验签

```ts
function sign(ks, id, msg, r?): string      // → 96 字节签名的 hex（h‖Sx‖Sy，192 字符）
function verify(publicKey, id, msg, sig): boolean
```

| 参数 | 说明 |
| --- | --- |
| `ks` / `publicKey` | 签名可用 **32 字节主私钥**（或 PKCS#8 PEM），也可传 **128 字节签名主公钥**（或 SPKI PEM）—— 靠长度区分 |
| `id` | 用户标识（字符串或 `Uint8Array`） |
| `msg` | 消息；字符串按 UTF-8 |
| `r` | 可选，32 字节随机数（测试注入）；不传走宿主 CSPRNG |

### 加密 / 解密

```ts
function encrypt(publicKey, id, msg, r?): string      // → 密文 hex（C1 65B ‖ C3 32B ‖ C2）
function decrypt(ke, id, ct, opts?: { safeMode?: boolean }): string
```

`encrypt` 的第一个参数可以是 **32 字节加密主私钥**，也可以是 **64 字节加密主公钥**
（SPKI PEM 亦可）。`decrypt` 必须用**加密主私钥**（或派生出的用户私钥），
认证失败抛 `DecryptionError`；`{ safeMode: true }` 时返回 `null`。

### 密钥封装 KEM（GM/T 0044.4）

```ts
function kemEncrypt(ke, id, klen = 32, r?): { key: string; encapsulation: string }
function kemDecrypt(ke, id, encapsulation, klen = 32): string
```

| 参数 | 说明 |
| --- | --- |
| `ke` | **加密主私钥**（KEM 需要它派生 `Ppub-e`，与 `encrypt` 可传主公钥不同） |
| `id` | 接收方标识 |
| `klen` | 会话密钥字节数，默认 32 |
| `encapsulation` | 65 字节封装点（`04 ‖ x ‖ y`）的 hex |

### 密钥交换（GM/T 0044.3）

```ts
const initiator = await sm9.createExchangeInitiator(keSelf, idPeer, idSelf, opts?);
const responder = await sm9.createExchangeResponder(keSelf, idPeer, idSelf, opts?);

const m1 = initiator.initiate();          // 阶段 1
const m2 = responder.respond(m1);         // 阶段 2（含 confirm）
const m3 = initiator.confirm(m2);         // 阶段 3
initiator.getSharedKey(m2, kLen?);        // 两端得到同一把会话密钥
responder.getSharedKey(m3, kLen?);
```

`options.kLen` 设会话密钥长度（默认 32），`options.ephemeral` 是**测试注入**的临时私钥。

## 用法

```ts
import { sm9 } from 'sm-crypto-wasm';

const id = 'alice@example.com';

// 签名用与加密用各一套主密钥
const signKp = await sm9.generateKeyPair({ id });                 // purpose 默认 'sign'
const encKp  = await sm9.generateKeyPair({ id, purpose: 'enc' });

// 签名 / 验签
const sig = sm9.sign(signKp.masterPrivatePem, id, 'abc');
sm9.verify(signKp.masterPublicPem, id, 'abc', sig);                // → true

// 加密 / 解密
const ct = sm9.encrypt(encKp.masterPublicPem, id, 'abc');
sm9.decrypt(encKp.masterPrivatePem, id, ct);                       // → '616263'

// KEM：协商一把对称密钥，不传消息
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, id, 32);
sm9.kemDecrypt(encKp.masterPrivatePem, id, encapsulation, 32);     // === key
```

## Playground

<Sm9Playground />

::: details 为什么 SM9 比其它算法慢
pairing 是这里的主要成本：一次签名约 4 ms、验签约 8 ms、加密约 3.7 ms，比 SM2 高一个量级。
这是 pairing 的数学代价，不是实现问题 —— 详见[性能页](/performance)。
:::

## 错误与边界

| 情况 | 抛出的错误 |
| --- | --- |
| `id` 为空 | `RangeError` |
| `purpose` 不是 `'sign'` / `'enc'` | `RangeError` |
| 主私钥长度不是 32 字节 | `InvalidKeyError` |
| 签名长度不是 96 字节 | `InvalidCiphertextError` |
| 密文短于 97 字节 | `InvalidCiphertextError` |
| C3 HMAC 校验失败 | `DecryptionError` |
| `kemDecrypt` 的 `encapsulation` 不是 65 字节 | `RangeError` |
| `klen` 不是正整数 | `RangeError` |

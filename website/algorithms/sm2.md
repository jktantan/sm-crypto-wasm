# SM2 —— 椭圆曲线公钥密码

SM2 是国密椭圆曲线公钥密码算法（**GM/T 0003-2012** 系列），曲线 **`sm2p256v1`**
（256 位素域，`a = p - 3`）。本库覆盖四块：

| 能力 | 标准 | 入口 |
| --- | --- | --- |
| 数字签名 | GM/T 0003.2 | `sign` / `verify`（默认 **SM3withSM2**） |
| 公钥加密 | GM/T 0003.4 | `encrypt` / `decrypt`（密文默认 **C1C3C2**） |
| 密钥交换 | GM/T 0003.3 | `createExchangeInitiator` / `createExchangeResponder` |
| 密钥生成 | — | `generateKeyPair` / `getPublicKey` |

::: tip 默认值
签名固定用 **SM3withSM2**，用户标识默认 `"1234567812345678"`（GM/T 0003.2 的默认 ID）。
加密密文默认按 **C1C3C2** 组装，解密端**自动识别** C1C3C2 / C1C2C3。
:::

## 导入

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();   // 只有 generateKeyPair 是 async 的
```

## 密钥形态

SM2 的密钥参数同时接受三种形态，按需选一种即可：

| 形态 | 私钥 | 公钥 |
| --- | --- | --- |
| 裸字节 / hex | 32 字节 | 64 字节 `x‖y`，或 65 字节带 `04` 前缀 |
| PEM | PKCS#8（`PRIVATE KEY`）、SEC1（`EC PRIVATE KEY`） | SPKI（`PUBLIC KEY`） |
| `Uint8Array` | 32 字节 | 64 / 65 字节 |

字符串一律按编码嗅探（`-----BEGIN` → PEM；偶数长度纯 hex → hex；否则 base64）。
**不接受"UTF-8 文本"形态的密钥**。

## API

### `sm2.generateKeyPair()`

```ts
function generateKeyPair(): Promise<{ privateKeyPem: string; publicKeyPem: string }>
```

异步：含 wasm 实例化 + 宿主 CSPRNG 取私钥 `d`。返回 **PKCS#8 私钥 PEM** 与 **SPKI 公钥 PEM**，
可直接被 OpenSSL / GmSSL 读取。

### `sm2.getPublicKey(privateKey)`

```ts
function getPublicKey(privateKey: string | Uint8Array): string
```

从私钥派生公钥。**返回** 128 字符 hex（64 字节 `x‖y`）。
这个方法**每次真算**（不做缓存），保持"派生公钥"这个操作的语义。

### `sm2.sign(privateKey, message)`

```ts
function sign(privateKey: string | Uint8Array, message: string | Uint8Array): string
```

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `privateKey` | `string \| Uint8Array` | 是 | 32 字节 / PKCS#8 / SEC1 |
| `message` | `string \| Uint8Array` | 是 | 待签名消息（字符串按 UTF-8 字节处理） |

**返回** 64 字节签名的 hex（`r‖s`，128 字符）。内部随机 `k` 走宿主 CSPRNG，
`r`/`s` 为 0 的极小概率会重抽（最多 16 次）。

### `sm2.verify(publicKey, message, signature)`

```ts
function verify(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  signature: string | Uint8Array,
): boolean
```

**公钥不在曲线上时直接返回 `false`**（不抛错）—— 这样"公钥非法"不会与"签名不对"混淆成
两种异常路径。签名长度不是 64 字节则抛 `InvalidCiphertextError`。

### `sm2.encrypt(publicKey, message, opts?)`

```ts
function encrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { outputFormat?: 'C1C3C2' | 'C1C2C3' },
): string
```

**返回** 密文 hex：`C1(65B) ‖ C3(32B) ‖ C2`（默认），或按 `outputFormat: 'C1C2C3'`
换成 `C1 ‖ C2 ‖ C3`。公钥不在曲线上抛 `InvalidPublicKeyError`。

### `sm2.decrypt(privateKey, ciphertext, opts?)`

```ts
function decrypt(
  privateKey: string | Uint8Array,
  ciphertext: string | Uint8Array,
  opts?: { inputFormat?: 'C1C3C2' | 'C1C2C3' | 'auto'; safeMode?: boolean },
): string
```

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `inputFormat` | `'auto'` | `auto` 先按 C1C3C2 解，C3 校验失败再按 C1C2C3 重排重试 |
| `safeMode` | `false` | `true` 时密文支失败返回 `null`，不抛 `CiphertextError` |

`safeMode` 只吞"密文支"失败；参数类型错误（`TypeError` / `RangeError`）仍然抛出。

### `sm2.configurePublicKeyCache(opts)` / `sm2.clearPublicKeyCache()`

```ts
function configurePublicKeyCache(opts: { enabled?: boolean; capacity?: number }): void
function clearPublicKeyCache(): void
```

`sign` 每次都需要公钥来算 Z 值，而公钥只依赖私钥。默认开启一个 **进程内缓存**
（以私钥 hex 为键，容量 32，FIFO 淘汰），命中即跳过固定基点标量乘 —— 实测让
`sign` 从 252 µs 降到 142 µs。

**取舍**：缓存在进程内存里驻留"私钥的派生结果"（以及私钥本身的 hex 形态）。
不接受这一点的安全模型下用 `configurePublicKeyCache({ enabled: false })` 关掉，
即回到每次都重算的无状态行为。

## 密钥交换（GM/T 0003.3）

```ts
const alice = await sm2.createExchangeInitiator(privA, pubB, { idSelf: 'Alice', idPeer: 'Bob' });
const bob = await sm2.createExchangeResponder(privB, pubA, { idSelf: 'Bob', idPeer: 'Alice' });

const r1 = alice.initiate();     // 阶段 1：发起方 → 响应方（RA）
const r2 = bob.respond(r1);      // 阶段 2：响应方 → 发起方（RB + S_B）
const r3 = alice.confirm(r2);    // 阶段 3：发起方 → 响应方（S_A）

const kA = alice.getSharedKey(r3);
const kB = bob.getSharedKey(r3);  // 双方得到同一把共享密钥
```

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `idSelf` | `"1234567812345678"` | 本端用户标识 |
| `idPeer` | `"1234567812345678"` | 对端用户标识 |
| `ephemeralPrivateKey` | 宿主 CSPRNG | **测试注入用**，生产勿传 |

| 端点方法 | 返回 | 说明 |
| --- | --- | --- |
| `initiator.initiate()` | `{ ephemeralPub }` | 只能调用一次 |
| `initiator.confirm(r2)` | `{ confirm }` | 会**校验收到的 S_B**，不通过抛错 |
| `initiator.getSharedKey(r3?, kLen?)` | hex | 需先 `confirm()` |
| `responder.respond(r1)` | `{ ephemeralPub, confirm }` | 只能调用一次 |
| `responder.getSharedKey(r3, kLen?)` | hex | 会校验发起方的 S_A |

## 用法

```ts
import { sm2 } from 'sm-crypto-wasm';

// 1) 生成密钥对（PEM）
const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

// 2) 签名 / 验签
const sig = sm2.sign(privateKeyPem, 'abc');
sm2.verify(publicKeyPem, 'abc', sig);                    // → true

// 3) 加密 / 解密
const ct = sm2.encrypt(publicKeyPem, 'abc');             // 默认 C1C3C2
sm2.decrypt(privateKeyPem, ct);                          // → '616263'

// 与只认 C1C2C3 的老系统对接
const ct2 = sm2.encrypt(publicKeyPem, 'abc', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct2, { inputFormat: 'C1C2C3' });
```

裸 hex 密钥同样可用：

```ts
const d = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const pub = sm2.getPublicKey(d);                          // 128 字符 hex
const sig = sm2.sign(d, 'abc');
sm2.verify(pub, 'abc', sig);
```

## Playground

<Sm2Playground />

## 错误与边界

| 情况 | 抛出的错误 |
| --- | --- |
| 私钥不是 32 字节 | `InvalidKeyError` |
| 公钥不是 64 / 65 字节 | `InvalidKeyError` |
| `encrypt` 的公钥不在曲线上 | `InvalidPublicKeyError` |
| `verify` 的公钥不在曲线上 | 不抛错，**返回 `false`** |
| 签名长度不是 64 字节 | `InvalidCiphertextError` |
| 密文短于 97 字节 | `InvalidCiphertextError` |
| C3 校验失败（密钥 / 密文不匹配） | `DecryptionError` |
| `outputFormat` / `inputFormat` 传了未知值 | `RangeError` |
| `configurePublicKeyCache({ capacity: 0 })` | `RangeError` |

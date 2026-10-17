# SM2 —— 椭圆曲线公钥密码

SM2 是国密椭圆曲线公钥密码算法（**GM/T 0003-2012** 系列），曲线 **`sm2p256v1`**
（256 位素域，`a = p - 3`）。本库覆盖四块：

| 能力 | 标准 | 入口 |
| --- | --- | --- |
| 数字签名 | GM/T 0003.2 | `sign` / `verify`（默认 **SM3withSM2**） |
| 公钥加密 | GM/T 0003.4 | `encrypt` / `decrypt`（密文默认 **C1C3C2**） |
| 密钥封装 / 混合加密 | —（约定做法） | `kemEncrypt` / `kemDecrypt`、`hybridEncrypt` / `hybridDecrypt` |
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

### `sm2.sign(privateKey, message, opts?)`

```ts
function sign(
  privateKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { pointPool?: SignaturePoint[] },
): string
```

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `privateKey` | `string \| Uint8Array` | 是 | 32 字节 / PKCS#8 / SEC1 |
| `message` | `string \| Uint8Array` | 是 | 待签名消息（字符串按 UTF-8 字节处理） |
| `opts.pointPool` | `SignaturePoint[]` | 否 | 预计算的签名点池，见 `createSignaturePointPool`。会被原地消费 |

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

### `sm2.kemEncrypt(publicKey, klen = 32)` / `sm2.kemDecrypt(privateKey, encapsulation, klen = 32, opts?)`

```ts
function kemEncrypt(publicKey: string | Uint8Array, klen?: number):
  { key: string; encapsulation: string }
function kemDecrypt(
  privateKey: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen?: number,
  opts?: { safeMode?: boolean },
): string
```

**SM2 没有国标定义的独立 KEM**；这里用的是“用 SM2 公钥加密一把随机对称密钥”的约定做法。
`encapsulation` 是完整的 SM2 密文（C1C3C2，长度 `97 + klen` 字节），自带 C3 校验；
错误私钥或篡改都会抛 `DecryptionError`。`safeMode: true` 时返回 `null`。

### `sm2.hybridEncrypt(publicKey, message, opts?)` / `sm2.hybridDecrypt(privateKey, sealed, opts?)`

```ts
function hybridEncrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { iv?: string | Uint8Array },
): string
function hybridDecrypt(
  privateKey: string | Uint8Array,
  sealed: string | Uint8Array,
  opts?: { safeMode?: boolean },
): string
```

一次调用完成 **KEM + SM4-GCM**：公钥只保护 16 字节 DEK，消息交给对称算法。适合大消息，
也避免把长数据塞进 SM2 的 KDF / 点运算路径。

- 每次调用都新生成 16 字节 DEK 与 12 字节 IV；`iv` 只用于测试 / 协议互操作，正常不要传。
- `message` 字符串按 **hex** 解释；空消息传 `new Uint8Array(0)`。
- 返回版本化 `sealed`：`version(1) ‖ klen(1) ‖ encapLen(2) ‖ encapsulation ‖ iv(12) ‖ tag(16) ‖ ct`。
- AAD 绑定 `encapsulation`；sealed 被篡改、私钥错误都会抛 `DecryptionError`。
- `safeMode: true` 时密文支失败返回 `null`。
- hybrid 同时依赖 `sm2.wasm` 与 `sm4.wasm`：首次调用前请 `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])`。

### `sm2.sealedToObject(sealed)` / `sm2.sealedFromObject(obj)`

```ts
function sealedToObject(sealed: string | Uint8Array): {
  v: number; klen: number; encapsulation: string; iv: string; tag: string; ct: string;
}
function sealedFromObject(obj: SealedObject): string
```

把 `sealed` 在 hex 字符串与自描述对象之间互转，便于调试或与手工
`kemEncrypt` + `sm4.encryptGCM` 组装互操作。

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

### `sm2.createSignaturePointPool(n)`

```ts
class SignaturePoint {
  readonly point: string; // k·G 的仿射坐标 x‖y（64 字节 hex），公开信息
}
async function createSignaturePointPool(n: number): Promise<SignaturePoint[]>
```

预算 `n` 个一次性签名点，供 `sign` 的 `pointPool` 选项消费。签名里的固定基点标量乘
`k·G` 约占单次签名的 **56%**，提前摊销后关键路径只剩 `e = SM3(Z‖M)` 与两条模运算 ——
实测单次签名 **141 µs → 24 µs（快 5.9×）**。只有服务端连续签发的批量场景才值得，
零散签名直接用默认路径。

```ts
const pool = await sm2.createSignaturePointPool(10000);
for (const msg of messages) {
  const sig = sm2.sign(privateKey, msg, { pointPool: pool }); // 每签一次消费一个点
}
```

**"绝不复用 k" 是结构性保证的，不需要你操心。** 临时私钥 `k` 封在库内部：既不暴露、
也无法复制（`SignaturePoint` 上只有公开的 `k·G` 坐标），`sign` 取走后立刻从索引摘除并
抹掉字节。同一个点再喂一次会**当场抛错**，而不是悄悄复用 —— 复用 `k` 在 SM2 下会直接
解出私钥。伪造一个 `SignaturePoint` 同样无效（索引里没有它）。

池被取空后 `sign` 自动回退到现算路径（不少签、不签错）；`n` 须为非负整数，否则抛
`RangeError`。

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

KEM 与混合加密：

```ts
// 4) KEM：用公钥保护一把随机会话密钥
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);        // === key

// 5) 混合加密：一次调用完成 KEM + SM4-GCM，适合大消息
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);                 // → '616263'

// sealed 也可以在 hex 与对象形态之间互转
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
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
| `kemDecrypt` C3 校验失败 / 私钥错误 | `DecryptionError` |
| `hybridDecrypt` 的 sealed 结构错（版本 / 长度字段 / 截断） | `InvalidCiphertextError` |
| `hybridDecrypt` GCM tag 校验失败 | `DecryptionError` |
| `hybridEncrypt` 的 `iv` 不是 12 字节 | `RangeError` |
| `kemEncrypt` / `kemDecrypt` 的 `klen` 不在 [1, 65536] 内 | `RangeError` |
| `outputFormat` / `inputFormat` 传了未知值 | `RangeError` |
| `configurePublicKeyCache({ capacity: 0 })` | `RangeError` |

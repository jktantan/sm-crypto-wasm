# ZUC —— 序列密码

ZUC 是国密序列密码算法（**GM/T 0001-2012**，即 3GPP TS 35.221 的 **ZUC-128**）。
本库实现两块：

| 能力 | 标准 | 入口 |
| --- | --- | --- |
| **EEA3** 机密性算法 | GM/T 0001.2-2012 | `zucEncrypt` / `zucDecrypt` / `zucKeystream` |
| **EIA3** 完整性算法 | GM/T 0001.3-2012 | `zucMac` / `zucEia3Iv` |

::: warning 只支持 ZUC-128
ZUC-256（GM/T 0001.1-2021）的 LFSR / 初始化 / 密钥加载与 ZUC-128 不是参数化关系，
是另一套算法，**本库暂不实现**。`zucMac` 的标签长度因此只接受 32 位。
:::

::: danger 密钥流绝不可复用
同一 `(key, iv, counter)` 生成的密钥流，异或两条明文就泄露了两者的异或值 ——
这是机密性事故。所以**加密路径显式拒绝复用**（抛 `InvalidKeyError`），而不是静默放行。
:::

## 导入

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
```

::: tip 返回值是字节，不是 hex
ZUC 的四个主函数返回 **`Uint8Array`**（与 SM2 / SM3 / SM4 返回 hex 字符串不同）。
要 hex 展示请用库同时导出的 `bytesToHex`。
:::

## API

### 密钥流 `zuc.zucKeystream(key, iv, nBytes)`

```ts
function zucKeystream(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  nBytes: number,
): Uint8Array
```

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | 是 | **16 字节** |
| `iv` | `string \| Uint8Array` | 是 | **16 字节** |
| `nBytes` | `number` | 是 | 输出字节数，非负整数 |

密钥流本身不参与复用保护 —— 需要自己保证不重复使用。

### EEA3 加密 `zuc.zucEncrypt(key, iv, data, counter?, opts?)`

```ts
function zucEncrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  counter?: number,                       // 默认 0
  opts?: { reuseGuard?: boolean },        // 本次是否参与复用保护，默认 true
): Uint8Array
```

与密钥流异或得到密文。**同一 `(key, iv, counter)` 第二次调用会抛 `InvalidKeyError`**。
确有需要（比如密钥/IV 由外部计数器严格管理）可传 `{ reuseGuard: false }`，或用
`configureReuseGuard({ enabled: false })` 全局关闭。

### EEA3 解密 `zuc.zucDecrypt(key, iv, data, counter?)`

```ts
function zucDecrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  counter?: number,
): Uint8Array
```

EEA3 是自反的（异或同样的密钥流）。**解密路径豁免复用保护** —— 密文可能被多次校验或重放处理。

### EIA3 MAC `zuc.zucMac(key, iv, msg, bitLengthOrOptions?, tagBits?)`

```ts
function zucMac(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
  bitLengthOrOptions?: number | { bitLength?: number; tagBits?: number },
  tagBits?: number,
): Uint8Array
```

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | — | 16 字节完整性密钥 |
| `iv` | `string \| Uint8Array` | — | 16 字节 IV（见 `zucEia3Iv`） |
| `msg` | `string \| Uint8Array` | — | 受保护消息 |
| `bitLength` | `number` | `msg.length * 8` | 参与计算的消息**比特数**（非整字节消息要显式给） |
| `tagBits` | `number` | `32` | 只支持 32 |

**返回** 4 字节（32 位）标签。

### EIA3 IV 组装 `zuc.zucEia3Iv(count, bearer, direction)`

```ts
function zucEia3Iv(count: number, bearer: number, direction: number): Uint8Array
```

按 GM/T 0001.3 / TS 35.221 的布局，把 `COUNT(32) ‖ BEARER(5) ‖ DIRECTION(1) ‖ 0(26)`
组装成 16 字节 IV（与 GmSSL 的 `zuc_set_eia_iv` 一致）。

| 参数 | 取值 |
| --- | --- |
| `count` | 32 位无符号整数 |
| `bearer` | 0..31 |
| `direction` | 0 或 1 |

### 复用保护开关

```ts
function configureReuseGuard(opts: { enabled?: boolean; capacity?: number }): void
function resetReuseGuard(): void
```

默认 `{ enabled: true, capacity: 4096 }`：记录用过的 `(key, iv, counter)`，FIFO 淘汰最旧一条
（**必须有界**，否则长期运行会吃内存）。`resetReuseGuard()` 清空记录，只在测试与明确的
密钥轮换场景下用。

## 用法

```ts
import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();

const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

// 密钥流
bytesToHex(zuc.zucKeystream(key, iv, 16));

// EEA3 加解密（counter 要严格管理，避免复用）
const ct = zuc.zucEncrypt(key, iv, 'abc', 0);
const pt = zuc.zucDecrypt(key, iv, ct, 0);

// EIA3 完整性标签
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
bytesToHex(zuc.zucMac(key, macIv, 'abc'));          // → 4 字节标签

// 非整字节消息：显式给比特长度
zuc.zucMac(key, macIv, msg, { bitLength: 577 });
```

## Playground

<ZucPlayground />

## 错误与边界

| 情况 | 抛出的错误 |
| --- | --- |
| `key` 或 `iv` 不是 16 字节 | `InvalidKeyError` |
| `zucEncrypt` 的 `(key, iv, counter)` 已用过 | `InvalidKeyError` |
| `zucEncrypt` 的 `counter` 不是非负整数 | `RangeError` |
| `zucKeystream` 的 `nBytes` 不是非负整数 | `RangeError` |
| `zucMac` 的 `tagBits` 不是 32 | `RangeError` |
| `zucMac` 的 `bitLength` 超出 `[0, msg.length * 8]` | `RangeError` |
| `zucEia3Iv` 的 `count` / `bearer` / `direction` 越界 | `RangeError` |

命名别名（与主名指向同一实现）：`zuc.encrypt` = `zucEncrypt`、`zuc.decrypt` = `zucDecrypt`、
`zuc.generateKeystream` = `zucKeystream`、`zuc.mac` = `zuc.eia3` = `zucMac`。

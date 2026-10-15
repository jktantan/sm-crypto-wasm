# 安装与快速开始

## 安装

```bash
pnpm add sm-crypto-wasm
# 或
npm i sm-crypto-wasm
# 或
yarn add sm-crypto-wasm
```

要求 **Node >= 18**；浏览器需支持 WebAssembly 与 `crypto.getRandomValues`。
包只带 `.wasm` 与薄 TS 胶水，**不需要 `node-gyp` / Rust / 编译器**。

## 异步边界：先 `ensureLoaded()`

每个算法是一个独立命名空间，各自暴露一个 **`ensureLoaded()`**：

```ts
import { sm3, sm4 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();   // 首次使用前预热
sm3.hash('616263');         // 之后全部是同步调用
```

WASM 的实例化是异步的，之后所有业务函数都是同步的。**按算法分包**意味着
`sm4.wasm` 只在你 `await sm4.ensureLoaded()` 时才下载 —— 没用到的算法不会增加加载体积。

重复调用 `ensureLoaded()` 很廉价：模块级 memoization，并发调用共用同一个 Promise。

## 五个算法，各来一段

### SM3 —— 摘要与 HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                                     // 32 字节摘要的 hex
sm3.hash(new TextEncoder().encode('abc'));              // 同上，文本走显式 UTF-8
sm3.hmac('00112233445566778899aabbccddeeff', '616263'); // HMAC-SM3
```

### SM4 —— 对称加解密

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key = '0123456789abcdeffedcba9876543210';
const iv  = '000102030405060708090a0b0c0d0e0f';

sm4.encryptCBC(key, iv, 'hello');                        // PKCS#7 填充，任意长度
const { ct, tag } = sm4.encryptGCM(key, iv, 'hello', 'aad');
sm4.decryptGCM(key, iv, ct, tag, 'aad');                 // 认证失败抛 DecryptionError
```

### SM2 —— 签名 / 加解密

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

const sig = sm2.sign(privateKeyPem, 'abc');              // SM3withSM2
sm2.verify(publicKeyPem, 'abc', sig);                    // → true

const ct = sm2.encrypt(publicKeyPem, 'abc');             // 默认 C1C3C2
sm2.decrypt(privateKeyPem, ct);                          // 解密端自动识别顺序
```

### SM9 —— 标识密码

```ts
import { sm9 } from 'sm-crypto-wasm';

const id = 'alice@example.com';
const signKp = await sm9.generateKeyPair({ id });            // 默认 purpose: 'sign'
const encKp  = await sm9.generateKeyPair({ id, purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, id, 'abc');
sm9.verify(signKp.masterPublicPem, id, 'abc', sig);

const ct = sm9.encrypt(encKp.masterPublicPem, id, 'abc');
sm9.decrypt(encKp.masterPrivatePem, id, ct);
```

### ZUC —— EEA3 / EIA3

```ts
import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

const ct = zuc.zucEncrypt(key, iv, 'abc', 0);            // 返回 Uint8Array
zuc.zucDecrypt(key, iv, ct, 0);

const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
bytesToHex(zuc.zucMac(key, macIv, 'abc'));               // 4 字节标签
```

## 输入输出约定

| 方向 | 约定 |
| --- | --- |
| 输入字符串 | 按 **PEM → hex → base64** 顺序嗅探；`Uint8Array` 原样使用 |
| 输出（SM2 / SM3 / SM4 / SM9） | 默认小写 **hex** |
| 输出（ZUC） | **`Uint8Array`**（ZUC 的四个主函数） |
| 密钥 | 字符串按编码嗅探；**没有"UTF-8 文本密钥"这回事** |

## 下一步

- 体积敏感？看 [**只用一个算法**](/guide/subpath-imports)；
- 想在浏览器 / Worker 里跑？看 [**跨运行时**](/guide/cross-runtime)；
- 抓到了异常不知道是哪一类？看 [**错误处理**](/guide/error-handling)；
- 想知道每个操作用哪个算法页面：SM3 · SM4 · SM2 · SM9 · ZUC 都有独立页，页内带可运行的 Playground。

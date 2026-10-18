# sm-crypto-wasm

[![npm version](https://img.shields.io/npm/v/sm-crypto-wasm.svg?style=flat-square)](https://www.npmjs.com/package/sm-crypto-wasm)
[![npm downloads](https://img.shields.io/npm/dm/sm-crypto-wasm.svg?style=flat-square)](https://www.npmjs.com/package/sm-crypto-wasm)
[![license](https://img.shields.io/npm/l/sm-crypto-wasm.svg?style=flat-square)](https://github.com/jktantan/sm-crypto-wasm/blob/main/LICENSE)
[![Node.js](https://img.shields.io/node/v/sm-crypto-wasm.svg?style=flat-square)](https://nodejs.org/)

**简体中文** · [English](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/README.en.md) · [Русский](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/README.ru.md) · [完整文档](https://jktantan.github.io/sm-crypto-wasm/)

> Chinese cryptography standards (**SM2 / SM3 / SM4 / SM9 / ZUC**) implemented in **AssemblyScript → WebAssembly**.

国密算法（SM2 / SM3 / SM4 / SM9 / ZUC）的 **AssemblyScript → WebAssembly** 实现，Node 18+ 与现代浏览器（含 Web Worker）均可使用，按算法分包、按需懒加载。

- **性能**：热点（大整数模运算 / hash 压缩 / 分组密码轮函数）跑在 WASM 里。与同机纯 JS 参考实现相比，SM3 / ZUC 快 1.8~2.3×、SM4 六种模式快 3.6~11.2×、SM2 快 1.8~7.6×；
- **零工具链**：发布物是 `.wasm` + 薄 TS 胶水，使用者不需要 `node-gyp` / Rust / 编译器；
- **跨运行时**：同一份 API 在 Node、浏览器、Worker 下一致；
- **国标对齐**：实现按 GM/T 0003 / 0004 / 0002 / 0044 / 0001 系列，测试用官方向量与 OpenSSL / GmSSL / gmkitx 交叉对拍。

---

## 安装

```bash
npm install sm-crypto-wasm
# 或 pnpm add sm-crypto-wasm / yarn add sm-crypto-wasm
```

要求 Node **>= 18**（浏览器需支持 WebAssembly 与 `crypto.getRandomValues`）。

---

## 快速开始

> **每个算法首次使用前需要 `await algo.ensureLoaded()`** —— WASM 模块的实例化是异步的，
> 之后所有业务函数都是同步的。只加载你实际用到的算法，未用到的 `.wasm` 不会下载。

### SM3 —— 摘要与 HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                          // '66c7f0f4…8f4ba8e0'（hex 输入按字节解）
sm3.hash(new Uint8Array([0x61, 0x62, 0x63])); // 同上；字节输入最省事
sm3.hmac('00112233445566778899aabbccddeeff', '616263');
```

### SM4 —— 对称加解密（ECB / CBC / CTR / CFB / OFB / GCM）

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key   = '0123456789abcdeffedcba9876543210';
const iv    = '000102030405060708090a0b0c0d0e0f';
const msg16 = '00112233445566778899aabbccddeeff';  // 16 字节
const aad   = 'aabbccdd';                          // 附加认证数据（hex）

sm4.encryptECB(key, msg16);                    // ECB 无填充：输入须为 16 字节的整数倍
sm4.encryptCBC(key, iv, '616263');             // CBC 带 PKCS#7 填充，任意长度
sm4.decryptCBC(key, iv, sm4.encryptCBC(key, iv, '616263'));
sm4.encryptCTR(key, iv, '616263');             // CTR/OFB 为流模式（等价 cryptCTR / cryptOFB）
const { ct, tag } = sm4.encryptGCM(key, iv, '616263', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);         // 认证失败抛 DecryptionError；可传 { safeMode: true }
```

### SM2 —— 密钥生成 / 签名 / 验签 / 加解密

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();  // async，返回 PKCS#8 / SPKI PEM

const sig = sm2.sign(privateKeyPem, '616263');          // 默认 SM3withSM2，输出 r||s 的 hex
sm2.verify(publicKeyPem, '616263', sig);                // → true

const ct  = sm2.encrypt(publicKeyPem, '616263');                  // 默认 C1C3C2
const ct2 = sm2.encrypt(publicKeyPem, '616263', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct);                         // 解密端自动识别 C1C3C2 / C1C2C3
sm2.decrypt(privateKeyPem, ct, { safeMode: true });     // 失败返回 null 而不抛错
```

密钥也可以用裸 hex / `Uint8Array` 传入（32 字节私钥、64/65 字节公钥）。

### SM2 —— 密钥封装与混合加密

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();

// KEM：用公钥保护一把随机会话密钥（16 或 32 字节）。
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);       // === key

// 混合加密：一次调用完成 KEM + SM4-GCM，适合大消息。
// 返回版本化 sealed：version || klen || encapLen || encapsulation || iv || tag || ct
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);               // → '616263'（明文 hex）

// sealed 也可转成自描述对象，便于调试或与手工组装互操作。
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
```

- `hybridEncrypt` 每次调用都新生成 16 字节 DEK 与 12 字节 IV；消息字符串按 **hex** 解释（空消息传 `new Uint8Array(0)`）。
- hybrid 同时用到 `sm2.wasm` 与 `sm4.wasm`，首次调用前请 `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])`。
- `hybridDecrypt` 支持 `{ safeMode: true }`，密文支失败返回 `null`。
- SM2 没有国标定义的独立 KEM；`kemEncrypt` 是“用 SM2 公钥加密随机密钥”的约定做法。

### SM2 —— 密钥交换协议（GM/T 0003.3）

```ts
import { sm2 } from 'sm-crypto-wasm';

const A = await sm2.generateKeyPair();
const B = await sm2.generateKeyPair();

const alice = await sm2.createExchangeInitiator(A.privateKeyPem, B.publicKeyPem, {
  idSelf: 'Alice', idPeer: 'Bob',
});
const bob = await sm2.createExchangeResponder(B.privateKeyPem, A.publicKeyPem, {
  idSelf: 'Bob', idPeer: 'Alice',
});

const r1 = alice.initiate();      // 发起方 → 响应方的第一轮消息
const r2 = bob.respond(r1);       // 响应方 → 发起方的应答
const r3 = alice.confirm(r2);     // 发起方确认（内含 S_A，供响应方校验）

alice.getSharedKey(r3);           // 双方得到同一把共享密钥
bob.getSharedKey(r3);
```

### SM9 —— 签名 / 加密 / 密钥封装（GM/T 0044）

```ts
import { sm9 } from 'sm-crypto-wasm';

// SM9 的签名主密钥与加密主密钥是两套（purpose 区分），主公钥分别是 G2 / G1 点。
const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });                 // 默认 purpose: 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', '616263');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', '616263', sig);
// verify / encrypt 的第一参数也接受主私钥（沿用旧形态）。

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);      // → '616263'

// 密钥封装（KEM）：协商出一把对称密钥，不传消息。
// 注意第一参数是**加密主私钥**（KEM 需要它派生 Ppub-e，与 encrypt 可传主公钥不同）。
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);  // === key

// 混合加密：主公钥（或主私钥）+ id 封装 16 字节 DEK，再用 SM4-GCM 加密消息。
const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.hybridDecrypt(encKp.masterPrivatePem, 'alice@foo.com', sealed);  // → '616263'
```

> SM9 hybrid 同时用到 `sm9.wasm` 与 `sm4.wasm`：首次调用前请分别 `await sm9.ensureLoaded()` 与 `await sm4.ensureLoaded()`。

### ZUC —— EEA3 机密性 + EIA3 完整性

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

zuc.zucKeystream(key, iv, 16);                  // 密钥流（Uint8Array）
zuc.zucEncrypt(key, iv, '616263');              // EEA3；同一 (key, iv, counter) 只允许加密一次
zuc.zucDecrypt(key, iv, ct);                    // 解密（豁免复用保护）

// EIA3 完整性标签（32 位）；IV 由 COUNT / BEARER / DIRECTION 组装
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
zuc.zucMac(key, macIv, '616263');               // → 4 字节标签
```

---

### X.509 · CMS · WebCrypto

```ts
import { x509, cms, webcrypto } from 'sm-crypto-wasm';

const cert = x509.parseCertificate(pem);
const signed = cms.signData({ data, privateKey, certificate: cert });
const digest = await webcrypto.subtle.digest('SM3', data);
```

- **X.509**：证书解析、单证书验签、自签 / 简单 CA 签发（[文档](https://jktantan.github.io/sm-crypto-wasm/guide/x509)）；
- **CMS**：SignedData detached / attached、`signedAttrs` 原始 DER 验签、BER（[文档](https://jktantan.github.io/sm-crypto-wasm/guide/cms)）；
- **WebCrypto**：`subtle` 风格的 SM3 / HMAC(SM3) / SM2 / SM4 子集（[文档](https://jktantan.github.io/sm-crypto-wasm/guide/webcrypto)）。

X.509 / CMS 不做证书链路径校验、CRL/OCSP；WebCrypto 不是原生 `crypto.subtle` 的 polyfill。

---

## API 一览

| 模块 | 函数 |
|---|---|
| `sm2` | `generateKeyPair`(async) · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `preparePublicKey`(async) · `configurePreparedKeyCache` · `clearPreparedPublicKeys` · `getPreparedPublicKeys` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `createExchangeInitiator`(async) · `createExchangeResponder`(async) |
| `webcrypto` | `subtle` · `CryptoKey` |
| `cms` | `signData` · `verifySignedData` · `parseSignedData` · `CmsError` |
| `x509` | `parseCertificate` · `parseCertificates` · `createSelfSignedCertificate` · `issueCertificate` · `parseDistinguishedName` · `verifyCertificateSignature` |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB`/`decryptECB` · `encryptCBC`/`decryptCBC` · `encryptCTR`/`decryptCTR` · `encryptCFB`/`decryptCFB` · `encryptOFB`/`decryptOFB` · `encryptGCM`/`decryptGCM` |
| `sm9` | `generateKeyPair`(async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator`(async) · `createExchangeResponder`(async) |
| `zuc` | `zucKeystream` · `zucEncrypt` · `zucDecrypt` · `zucMac` · `zucEia3Iv` · `configureReuseGuard` |

文档名别名（与主名指向同一实现）：`sm4.encryptCTR`/`decryptCTR` 等价 `cryptCTR`、`encryptOFB`/`decryptOFB` 等价 `cryptOFB`；`zuc.encrypt`/`decrypt`/`generateKeystream`/`mac`/`eia3` 等价 `zucEncrypt`/`zucDecrypt`/`zucKeystream`/`zucMac`。

---

## 只用一个算法（子路径导入）

体积敏感的场景可以绕过聚合入口，只加载需要的 `.wasm`：

```ts
import { hash } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

可用子路径：`sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/x509` · `/cms` · `/webcrypto` · `/zuc`。

---

## 跨运行时

| 环境 | 加载路径 |
|---|---|
| Node 18+ | `fs/promises` 读取 `dist/<algo>/<algo>.wasm`，可用 `loadWasmSync()` 同步预热 |
| 浏览器（经打包器） | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`，由打包器归档并重写 URL |
| Web Worker | 加载器不依赖 DOM，Worker 内可用 |
| Deno / Bun | 走 Node 同路径 |
| 微信内置浏览器 | 与浏览器相同（`fetch` + `crypto.getRandomValues`）；见[微信与小程序](https://jktantan.github.io/sm-crypto-wasm/guide/wechat) |
| 微信小程序 | `WXWebAssembly` + `wx.getRandomValues`；见[微信与小程序](https://jktantan.github.io/sm-crypto-wasm/guide/wechat) |

### 打包器支持

包内按环境提供两份实现（Node 版读文件 / 浏览器版 `fetch`），由 `package.json` 的
`browser` 字段在打包时自动切换。因此**浏览器产物里不会出现 `node:*`** —— 不做 node 内置
模块外部化的打包器（Webpack、esbuild、Rspack）也不会在解析期报 `Can't resolve 'node:fs'`。

| 打包器 | 需要配置吗 | wasm 资源 |
|---|---|---|
| **Vite 5** | 零配置 | 自动归档进产物（`assets/*.wasm`） |
| **Webpack 5** | 零配置 | 作为 asset 自动产出 |
| **Rspack 2** | 零配置 | 作为 asset 自动产出（带 hash 文件名） |
| **Turbopack**（Next.js 16 默认） | 零配置 | 归档到 `static/media/*.wasm` |
| **esbuild** | 加一行插件（见下） | esbuild 不处理 `new URL(..., import.meta.url)` 指向的文件 |
| **Node 18+** | 零配置 | 读 `dist/<algo>/<algo>.wasm` |

esbuild 的用户装一个自带的小插件，它会自动把 wasm 放到运行时能解析到的位置：

```ts
import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outdir: 'dist/assets',        // 产物 JS 落这里
  plugins: [smCryptoWasm()],    // → wasm 复制到 dist/<algo>/<algo>.wasm
});
```

不想用插件也可以：把 `node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc}`
复制到**产物 JS 的上级目录**（上例即 `dist/`）。

浏览器需要**安全上下文**（`https://` 或 `localhost`）才能拿到 `crypto.getRandomValues`；
拿不到时库会**抛错**（fail-closed），不会退化成非密码学随机源。

Cloudflare Workers / Vercel Edge 这类"严格流式 WASM"环境**不在当前范围**；
`<script type="module">` 直载（不经打包器）同样不支持。

---

## 错误处理

所有"因输入而拒绝"的错误都是 `SmCryptoError` 的子类，分两支：

```ts
import { SmCryptoError, InvalidKeyError, InvalidPublicKeyError,
         CiphertextError, InvalidCiphertextError, DecryptionError } from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (e instanceof DecryptionError) { /* 密文/密钥不匹配 */ }
  else if (e instanceof CiphertextError) { /* 密文结构或校验问题 */ }
  else if (e instanceof InvalidKeyError) { /* 密钥格式/长度/曲线问题 */ }
  else throw e;
}
```

- 密钥支：`InvalidKeyError`（`InvalidPublicKeyError` 是其子类）；
- 密文支：`CiphertextError`（`InvalidCiphertextError` 结构错、`DecryptionError` 校验失败）；
- 参数类型/数值越界（如长度上限、非法枚举值）保留宿主原生 `TypeError` / `RangeError`。

---

## 安全说明

- **随机数只用宿主的**：`crypto.getRandomValues`（浏览器 / Node 19+）或 Node 18 的 `node:crypto` shim，库内**不实现**任何 RNG；
- **私钥不落盘、不写日志**：库不做任何序列化到磁盘或日志的行为；
- **ZUC 复用保护**：同一 `(key, iv, counter)` 二次加密会抛错（密钥流复用是机密性事故）。确需按外部计数器自行管理时可 `configureReuseGuard({ enabled: false })` 或在单次调用上传 `{ reuseGuard: false }`；
- **SM2 公钥合法性**：`encrypt` 对不在曲线上的公钥抛 `InvalidPublicKeyError`，`verify` 返回 `false`；
- 不接国密机 / HSM / PKCS#11 / 软证书句柄；不解析 PEM 之外的密钥格式。

---

## 性能

热点（大整数模运算、hash 压缩函数、分组密码轮函数、双线性对）在 WASM 内执行。
所有经过对比的公开操作都快于同机纯 JS 参考实现：SM3 / ZUC 快 1.8\~2.3×，
SM4 六种模式 3.6\~11.2×，SM2 1.8\~7.6×。

完整的逐项操作表、与 `gmkitx` 的对比，以及「为什么是这个形状」的分析，见
**[性能页](https://jktantan.github.io/sm-crypto-wasm/performance)**。本机复现：
`pnpm bench`。

---

## 开发

```bash
pnpm install
pnpm build          # clean + asc（5 个 .wasm）+ tsc → dist/（无 source map）
pnpm build:ts:debug # 需要调试时：带 .js.map / .d.ts.map 重编译 TS 到 dist/
pnpm test           # Node runner（vitest）
pnpm test:browser   # 浏览器 runner（happy-dom）
pnpm bench          # mitata 微型基准（5 大块算法）
pnpm lint           # biome（lint + format）
pnpm typecheck      # tsc --noEmit
```

`pnpm build` 是发布路径：先清空 `dist/`，且 `tsconfig.build.json` 关掉了 `sourceMap` /
`declarationMap`，所以产物里既没有 `.map`，也没有 `//# sourceMappingURL=` 注释。原因：发布包
只带 `dist/`，map 的 `sources` 指向未随包发布的 `../src/*.ts`（且不含 `sourcesContent`），
下游既拿不到源码、编辑器也跳不到定义，却要多付约 35% 体积。仓库内调试改用
`pnpm build:ts:debug`（`tsconfig.build.debug.json`），它把 map 产出到 `dist/`。

**所有 wasm 模块都只带 `--optimize`，不含 `--enable simd`**：SM4 的加速走的是标量
多块交错，不依赖任何 SIMD 指令集。因此五个算法模块对运行时的要求一致，`sm4.wasm`
不再要求 **WASM SIMD**。

`src/**/assembly/**` 是 AssemblyScript 源，由 `asc` 编译；这些文件**不要**用 `import { type X}`
或让格式化器重排 import —— `asc` 0.28 不认类型修饰符（biome 配置里已对该目录关闭相关规则）。

每个 `src/*/assembly/` 目录下都有一个 `tsconfig.json`（只有一行 `extends`，指向根
`tsconfig.assembly.json`）。它继承 AssemblyScript 的类型定义，**只为让 IDE 按 AS 语义检查**——
否则编辑这些文件时，`usize` / `u32` / `StaticArray` 之类会被当成普通 TS 报 `TS2304`。
根 `tsconfig.json` 已 `exclude` 该目录，命令行 `tsc` 不碰它们，所以这些配置不影响构建与类型检查。

---

## 贡献

欢迎提交 Issue 与 Pull Request。开发环境、测试命令与 PR 要求见
[CONTRIBUTING.md](./CONTRIBUTING.md)；agent 协作、中英双语注释与代码规范见
[AGENTS.md](./AGENTS.md)；安全问题请按 [SECURITY.md](./SECURITY.md) 报告。

提交前请运行：

```bash
pnpm lint && pnpm typecheck && pnpm test:unit
```

---

## License

[Apache-2.0](./LICENSE)。

本项目的算法实现参考/移植了以下同样以 Apache-2.0 发布的项目，归属声明见 [`NOTICE`](./NOTICE)：

- [GmSSL](https://github.com/guanzhi/GmSSL) —— SM2 / SM9 的算法语义与命名对齐基准；
- [gmkit / gmkitx](https://github.com/gmkits/gmkit) —— ZUC 实现的移植来源。

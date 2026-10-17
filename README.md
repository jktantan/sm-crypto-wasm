# sm-crypto-wasm

[🇨🇳 中文](#zh-阅读下面的中文文档) · [🇺🇸 English](#en-english-documentation) · [🇷🇺 Русский](#ru-документация-на-русском)

Chinese cryptography standards (**SM2 / SM3 / SM4 / SM9 / ZUC**) implemented in
**AssemblyScript → WebAssembly**. Works on Node 18+ and modern browsers (incl.
Web Workers). Algorithms are split into sub-packages and lazy-loaded on demand.

- **Performance**: elliptic curves and bilinear pairings run in WASM, ~10×
  faster than pure-JS implementations;
- **Zero toolchain**: the published artifact is `.wasm` + a thin TS shim; users
  do not need `node-gyp`, Rust, or a compiler;
- **Runtime-agnostic**: the same API works in Node, browsers, and Workers;
- **Standards-aligned**: implementations follow the GM/T 0003 / 0004 / 0002 /
  0044 / 0001 series, cross-validated against official test vectors and
  OpenSSL / GmSSL / gmkitx.

---

## zh 阅读下面的中文文档

# sm-crypto-wasm

> 📖 **完整文档**（每个算法的参数表、用法与**可交互 Playground**）：<https://jktantan.github.io/sm-crypto-wasm/>

国密算法（SM2 / SM3 / SM4 / SM9 / ZUC）的 **AssemblyScript → WebAssembly** 实现，Node 18+ 与现代浏览器（含 Web Worker）均可使用，按算法分包、按需懒加载。

- **性能**：热点（大整数模运算 / hash 压缩 / 分组密码轮函数）跑在 WASM 里。轻量算法
  （SM3 / SM4 / ZUC）实测快于纯 JS 参考实现 1.1~3.0×；椭圆曲线部分（SM2）仍在优化中，
  见下方 **性能** 小节；
- **零工具链**：发布物是 `.wasm` + 薄 TS 胶水，使用者不需要 `node-gyp` / Rust / 编译器；
- **跨运行时**：同一份 API 在 Node、浏览器、Worker 下一致；
- **国标对齐**：实现按 GM/T 0003 / 0004 / 0002 / 0044 / 0001 系列，测试用官方向量与 OpenSSL / GmSSL / gmkitx 交叉对拍。

---

## 性能

热点（大整数模运算、hash 压缩函数、分组密码轮函数、双线性对）在 WASM 内执行。
所有经过对比的公开操作都快于同机纯 JS 参考实现：SM3 / ZUC 快 1.8\~2.3×，
SM4 六种模式 3.6\~11.2×，SM2 1.8\~7.6×。

完整的逐项操作表、与 `gmkitx` 的对比，以及「为什么是这个形状」的分析，见
**[性能页](https://jktantan.github.io/sm-crypto-wasm/performance)**。本机复现：
`pnpm bench`。

## 安装

```bash
pnpm add sm-crypto-wasm
# 或 npm i sm-crypto-wasm / yarn add sm-crypto-wasm
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

## API 一览

| 模块 | 函数 |
|---|---|
| `sm2` | `generateKeyPair`(async) · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `createExchangeInitiator`(async) · `createExchangeResponder`(async) |
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

可用子路径：`sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/zuc`。

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

## License

[Apache-2.0](./LICENSE)。

本项目的算法实现参考/移植了以下同样以 Apache-2.0 发布的项目，归属声明见 [`NOTICE`](./NOTICE)：

- [GmSSL](https://github.com/guanzhi/GmSSL) —— SM2 / SM9 的算法语义与命名对齐基准；
- [gmkit / gmkitx](https://github.com/gmkits/gmkit) —— ZUC 实现的移植来源。

---

<details>
<summary><h2 id="en-english-documentation" style="display:inline-block">🇺🇸 English</h2></summary>

# sm-crypto-wasm

> 📖 **Full documentation** (per-algorithm parameter tables, usage and **interactive Playgrounds**): <https://jktantan.github.io/sm-crypto-wasm/en/>

An **AssemblyScript → WebAssembly** implementation of Chinese cryptography
standards (**SM2 / SM3 / SM4 / SM9 / ZUC**). Runs on Node 18+ and modern
browsers (including Web Workers). Algorithms are split into sub-packages and
lazy-loaded on demand.

- **Performance**: hot paths (bignum modular arithmetic, hash compression,
  block-cipher rounds) run inside WASM. The lightweight algorithms (SM3 / SM4 /
  ZUC) measure 1.1~3.0× faster than the pure-JS reference implementation; the
  elliptic-curve side (SM2) is still being optimised — see **Performance** below;
- **Zero toolchain**: the published artifact is `.wasm` plus a thin TS shim;
  users don't need `node-gyp`, Rust, or a compiler;
- **Runtime-agnostic**: the same API works in Node, browsers, and Workers;
- **Standards-aligned**: implementations follow the GM/T 0003 / 0004 / 0002 /
  0044 / 0001 series and are cross-checked against official vectors using
  OpenSSL / GmSSL / gmkitx.

---

## Performance

Hot paths (bignum modular arithmetic, hash compression, block-cipher rounds,
pairings) run inside WASM. **Every operation with a pure-JS counterpart is faster
than it**: SM3 / ZUC by 1.8–2.3×, the six SM4 modes by 3.6–11.2×, SM2 by 1.8–7.6×.

The full per-operation table, the head-to-head against `gmkitx`, and the
"why it looks like this" notes live on the
**[performance page](https://jktantan.github.io/sm-crypto-wasm/en/performance)**.
Reproduce locally with `pnpm bench`.

## Installation

```bash
pnpm add sm-crypto-wasm
# or: npm i sm-crypto-wasm / yarn add sm-crypto-wasm
```

Requires Node **>= 18** (browsers must support WebAssembly and
`crypto.getRandomValues`).

---

## Quick Start

> **Call `await algo.ensureLoaded()` once before the first use of each
> algorithm.** Instantiating a WASM module is asynchronous; afterwards every
> business function is synchronous. Only the `.wasm` files you actually use
> are downloaded.

### SM3 — hash & HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                          // '66c7f0f4…8f4ba8e0' — hex input is decoded byte-wise
sm3.hash(new Uint8Array([0x61, 0x62, 0x63])); // same output; byte input is the most ergonomic
sm3.hmac('00112233445566778899aabbccddeeff', '616263');
```

### SM4 — symmetric encryption (ECB / CBC / CTR / CFB / OFB / GCM)

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key   = '0123456789abcdeffedcba9876543210';
const iv    = '000102030405060708090a0b0c0d0e0f';
const msg16 = '00112233445566778899aabbccddeeff';  // 16 bytes
const aad   = 'aabbccdd';                          // additional authenticated data (hex)

sm4.encryptECB(key, msg16);                    // ECB has no padding; input must be a multiple of 16 bytes
sm4.encryptCBC(key, iv, '616263');             // CBC uses PKCS#7 padding; any length is fine
sm4.decryptCBC(key, iv, sm4.encryptCBC(key, iv, '616263'));
sm4.encryptCTR(key, iv, '616263');             // CTR / OFB are stream modes (aliases of cryptCTR / cryptOFB)
const { ct, tag } = sm4.encryptGCM(key, iv, '616263', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);         // throws DecryptionError on auth failure; pass { safeMode: true } to suppress
```

### SM2 — key generation / signature / verification / encryption

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();  // async; returns PKCS#8 / SPKI PEM

const sig = sm2.sign(privateKeyPem, '616263');          // default SM3withSM2; output is r||s as hex
sm2.verify(publicKeyPem, '616263', sig);                // → true

const ct  = sm2.encrypt(publicKeyPem, '616263');                  // default C1C3C2
const ct2 = sm2.encrypt(publicKeyPem, '616263', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct);                         // decrypt side auto-detects C1C3C2 / C1C2C3
sm2.decrypt(privateKeyPem, ct, { safeMode: true });     // returns null instead of throwing on failure
```

Keys may also be passed as raw hex / `Uint8Array` (32-byte private key, 64- or
65-byte public key).

### SM2 — key encapsulation & hybrid encryption

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();

// KEM: protect a random symmetric key with the public key (16 or 32 bytes).
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);       // === key

// Hybrid encryption: one call performs KEM + SM4-GCM; suited to large messages.
// Returns a versioned sealed value: version || klen || encapLen || encapsulation || iv || tag || ct
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);               // → '616263' (plaintext hex)

// The sealed value can also be inspected as a self-describing object.
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
```

- Every `hybridEncrypt` call generates a fresh 16-byte DEK and 12-byte IV; message strings are interpreted as **hex** (pass `new Uint8Array(0)` for an empty message).
- Hybrid uses both `sm2.wasm` and `sm4.wasm`; warm them up with `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])` before the first call.
- `hybridDecrypt` supports `{ safeMode: true }`, returning `null` for ciphertext-side failures.
- SM2 has no standardized KEM construction; `kemEncrypt` is the conventional "encrypt a random key with SM2" idiom.

### SM2 — key exchange (GM/T 0003.3)

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

const r1 = alice.initiate();      // initiator → responder, round 1
const r2 = bob.respond(r1);       // responder → initiator, reply
const r3 = alice.confirm(r2);     // initiator confirmation (carries S_A for the responder to verify)

alice.getSharedKey(r3);           // both sides derive the same shared secret
bob.getSharedKey(r3);
```

### SM9 — sign / encrypt / KEM (GM/T 0044)

```ts
import { sm9 } from 'sm-crypto-wasm';

// SM9 has two master keys (distinguished by purpose): the sign master uses a
// G2 master public key, the encrypt master uses a G1 master public key.
const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });                 // default purpose: 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', '616263');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', '616263', sig);
// The first argument of verify / encrypt also accepts the master private key (legacy shape).

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);      // → '616263'

// Key encapsulation (KEM): negotiate a symmetric key without sending a message.
// Note the first parameter is the *encryption master private key* (KEM needs it to
// derive Ppub-e; encrypt() above can take a master public key instead).
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);  // === key

// Hybrid encryption: encapsulate a 16-byte DEK with the master public (or private) key + id,
// then encrypt the message with SM4-GCM.
const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.hybridDecrypt(encKp.masterPrivatePem, 'alice@foo.com', sealed);  // → '616263'
```

> SM9 hybrid uses both `sm9.wasm` and `sm4.wasm`: call `await sm9.ensureLoaded()` and `await sm4.ensureLoaded()` before the first use.

### ZUC — EEA3 confidentiality + EIA3 integrity

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

zuc.zucKeystream(key, iv, 16);                  // keystream (Uint8Array)
zuc.zucEncrypt(key, iv, '616263');              // EEA3 — each (key, iv, counter) may be encrypted once
zuc.zucDecrypt(key, iv, ct);                    // decryption (exempt from the reuse guard)

// EIA3 integrity tag (32-bit); IV is assembled from COUNT / BEARER / DIRECTION
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
zuc.zucMac(key, macIv, '616263');               // → 4-byte tag
```

---

## API at a glance

| Module | Functions |
|---|---|
| `sm2` | `generateKeyPair` (async) · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB` / `decryptECB` · `encryptCBC` / `decryptCBC` · `encryptCTR` / `decryptCTR` · `encryptCFB` / `decryptCFB` · `encryptOFB` / `decryptOFB` · `encryptGCM` / `decryptGCM` |
| `sm9` | `generateKeyPair` (async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `zuc` | `zucKeystream` · `zucEncrypt` · `zucDecrypt` · `zucMac` · `zucEia3Iv` · `configureReuseGuard` |

Documented aliases (they point to the same implementation):
`sm4.encryptCTR` / `decryptCTR` alias `cryptCTR`,
`encryptOFB` / `decryptOFB` alias `cryptOFB`;
`zuc.encrypt` / `decrypt` / `generateKeystream` / `mac` / `eia3` alias
`zucEncrypt` / `zucDecrypt` / `zucKeystream` / `zucMac`.

---

## Using a single algorithm (sub-path imports)

For size-sensitive scenarios, you can skip the aggregated entry point and
load just the `.wasm` you need:

```ts
import { hash } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

Available sub-paths: `sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/zuc`.

---

## Cross-runtime

| Environment | Loading path |
|---|---|
| Node 18+ | reads `dist/<algo>/<algo>.wasm` via `fs/promises`; `loadWasmSync()` available |
| Browser (via a bundler) | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`; the bundler archives and rewrites it |
| Web Worker | the loader is DOM-free and works inside a Worker |
| Deno / Bun | follows the Node path |
| WeChat built-in browser | same as browsers (`fetch` + `crypto.getRandomValues`); see [WeChat & Mini Programs](https://jktantan.github.io/sm-crypto-wasm/en/guide/wechat) |
| WeChat Mini Program | `WXWebAssembly` + `wx.getRandomValues`; see [WeChat & Mini Programs](https://jktantan.github.io/sm-crypto-wasm/en/guide/wechat) |

### Bundler support

The package ships two implementations (a Node one reading files, a browser one
using `fetch`) and `package.json`'s `browser` field switches between them at
build time. So **`node:*` never appears in a browser bundle** — bundlers that do
not externalise node built-ins (Webpack, esbuild, Rspack) no longer fail at
resolve time with `Can't resolve 'node:fs'`.

| Bundler | Configuration | wasm asset |
|---|---|---|
| **Vite 5** | none | archived into the output (`assets/*.wasm`) |
| **Webpack 5** | none | emitted as an asset |
| **Rspack 2** | none | emitted as an asset (hashed filenames) |
| **Turbopack** (Next.js 16 default) | none | archived under `static/media/*.wasm` |
| **esbuild** | one plugin line (below) | esbuild does not handle files pointed at by `new URL(..., import.meta.url)` |
| **Node 18+** | none | reads `dist/<algo>/<algo>.wasm` |

esbuild users add a small bundled plugin that drops the wasm where the runtime looks for it:

```ts
import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outdir: 'dist/assets',        // output JS lands here
  plugins: [smCryptoWasm()],    // → wasm copied to dist/<algo>/<algo>.wasm
});
```

Prefer no plugin? Copy `node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc}`
into the **parent** directory of the output JS (i.e. `dist/` in the example above).

Browsers need a **secure context** (`https://` or `localhost`) for
`crypto.getRandomValues`; when it is missing the library **throws** (fail-closed)
rather than falling back to a non-cryptographic source.

Strict-streaming WASM environments such as Cloudflare Workers / Vercel Edge are
**out of scope**; so is loading the raw ESM output directly via
`<script type="module">` (without a bundler).

---

## Error handling

All "rejected because of input" errors are subclasses of `SmCryptoError`, in
two branches:

```ts
import { SmCryptoError, InvalidKeyError, InvalidPublicKeyError,
         CiphertextError, InvalidCiphertextError, DecryptionError } from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (e instanceof DecryptionError) { /* ciphertext / key mismatch */ }
  else if (e instanceof CiphertextError) { /* structure or validation issue */ }
  else if (e instanceof InvalidKeyError) { /* key format / length / curve */ }
  else throw e;
}
```

- Key branch: `InvalidKeyError` (with `InvalidPublicKeyError` as a subclass);
- Ciphertext branch: `CiphertextError` (with `InvalidCiphertextError` for
  structural errors and `DecryptionError` for validation failures);
- Type or range problems (e.g. length caps, invalid enum values) keep the
  host's native `TypeError` / `RangeError`.

---

## Security notes

- **The library uses only the host's RNG**: `crypto.getRandomValues`
  (browsers / Node 19+) or the Node 18 `node:crypto` shim. **No RNG is
  implemented inside the library.**
- **No disk writes, no logs of private keys**: the library never serializes
  keys to disk or to logs.
- **ZUC reuse guard**: encrypting twice with the same `(key, iv, counter)`
  throws (keystream reuse is a confidentiality breach). If you manage the
  counter yourself, you can disable the guard globally with
  `configureReuseGuard({ enabled: false })` or per call via `{ reuseGuard: false }`.
- **SM2 public-key validity**: `encrypt` throws `InvalidPublicKeyError` for
  points not on the curve; `verify` simply returns `false`.
- No integration with crypto hardware / HSM / PKCS#11 / soft-cert handles;
  no key parsing outside PEM.

---

## Development

```bash
pnpm install
pnpm build          # clean + asc (5 .wasm files) + tsc → dist/ (no source maps)
pnpm build:ts:debug # for debugging: recompile TS to dist/ with .js.map / .d.ts.map
pnpm test           # Node runner (vitest)
pnpm test:browser   # browser runner (happy-dom)
pnpm bench          # mitata micro-benchmarks (5 algorithm blocks)
pnpm lint           # biome (lint + format)
pnpm typecheck      # tsc --noEmit
```

`pnpm build` is the release path: it empties `dist/` first, and `tsconfig.build.json` turns off
`sourceMap` / `declarationMap`, so the output carries neither `.map` files nor
`//# sourceMappingURL=` comments. The reason: the published package ships only `dist/`, while a
map's `sources` point at `../src/*.ts`, which is not published (and the maps embed no
`sourcesContent`) — downstream can neither read the sources nor jump to definitions, yet pays
roughly 35% extra size for it. For in-repo debugging use `pnpm build:ts:debug`
(`tsconfig.build.debug.json`), which emits maps into `dist/`.

**Every wasm module is built with `--optimize` only, no `--enable simd`**: SM4's speed
comes from scalar multi-block interleaving and depends on no SIMD instruction set. All
five algorithm modules therefore share the same runtime requirements, and `sm4.wasm`
no longer requires **WASM SIMD**.

Files under `src/**/assembly/**` are AssemblyScript sources compiled by
`asc`. **Do not** use `import { type X }` in those files or let the
formatter reorder imports — `asc` 0.28 doesn't recognize the type modifier
(those rules are already turned off for the directory in the biome config).

Each `src/*/assembly/` directory contains a single-line `tsconfig.json`
that just `extends` the root `tsconfig.assembly.json`. It pulls in the AS
type definitions **only so that IDEs type-check these files with AS
semantics** — otherwise editing them reports `TS2304` for things like
`usize`, `u32`, `StaticArray`. The root `tsconfig.json` `exclude`s the
directory, so the CLI `tsc` doesn't touch them; these per-directory
configs don't affect the build or typecheck.

---

## License

[Apache-2.0](./LICENSE).

The algorithm implementations in this project reference or are ported from
the following Apache-2.0 projects; attribution details are in [`NOTICE`](./NOTICE):

- [GmSSL](https://github.com/guanzhi/GmSSL) — the alignment baseline for
  SM2 / SM9 semantics and naming;
- [gmkit / gmkitx](https://github.com/gmkits/gmkit) — the source the ZUC
  implementation was ported from.

</details>

---

<details>
<summary><h2 id="ru-документация-на-русском" style="display:inline-block">🇷🇺 Русский</h2></summary>

# sm-crypto-wasm

> 📖 **Полная документация** (таблицы параметров, примеры и **интерактивные Playground**): <https://jktantan.github.io/sm-crypto-wasm/ru/>

Реализация китайских криптографических стандартов (**SM2 / SM3 / SM4 / SM9 /
ZUC**) на **AssemblyScript → WebAssembly**. Работает на Node 18+ и в
современных браузерах (включая Web Workers). Алгоритмы разделены по
подпакетам и подгружаются лениво.

- **Производительность**: горячие пути (модульная арифметика больших чисел,
  сжатие хэша, раунды блочного шифра) выполняются в WASM. Лёгкие алгоритмы
  (SM3 / SM4 / ZUC) измеренно в 1.1~3.0× быстрее чистой JS-реализации; часть на
  эллиптических кривых (SM2) ещё оптимизируется — см. **Производительность** ниже;
- **Без инструментария**: на выходе `.wasm` плюс тонкая TS-прослойка;
  пользователю не нужны `node-gyp`, Rust или компилятор;
- **Кросс-рантайм**: один и тот же API работает в Node, браузере и
  Worker'е;
- **Соответствие стандартам**: реализации следуют серии GM/T 0003 / 0004 /
  0002 / 0044 / 0001 и сверяются с официальными векторами через
  OpenSSL / GmSSL / gmkitx.

---

## Производительность

Горячие пути (модульная арифметика больших чисел, сжатие хэша, раунды блочного
шифра, спаривания) выполняются внутри WASM. **Каждая операция, у которой есть
чистый JS-аналог, быстрее его**: SM3 / ZUC — в 1.8–2.3×, шесть режимов SM4 —
в 3.6–11.2×, SM2 — в 1.8–7.6×.

Полная таблица по операциям, сравнение с `gmkitx` и разбор «почему именно так» —
на **[странице производительности](https://jktantan.github.io/sm-crypto-wasm/ru/performance)**.
Локально воспроизводится через `pnpm bench`.

## Установка

```bash
pnpm add sm-crypto-wasm
# либо: npm i sm-crypto-wasm / yarn add sm-crypto-wasm
```

Требуется Node **>= 18** (в браузере — поддержка WebAssembly и
`crypto.getRandomValues`).

---

## Быстрый старт

> **Перед первым использованием каждого алгоритма нужен
> `await algo.ensureLoaded()`** — инстанцирование WASM-модуля
> асинхронное; после него все рабочие функции синхронные. Загружаются
> только те `.wasm`, которые вы реально используете.

### SM3 — хеш и HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                          // '66c7f0f4…8f4ba8e0' — hex-строка декодируется побайтово
sm3.hash(new Uint8Array([0x61, 0x62, 0x63])); // тот же результат; байтовый ввод удобнее всего
sm3.hmac('00112233445566778899aabbccddeeff', '616263');
```

### SM4 — симметричное шифрование (ECB / CBC / CTR / CFB / OFB / GCM)

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key   = '0123456789abcdeffedcba9876543210';
const iv    = '000102030405060708090a0b0c0d0e0f';
const msg16 = '00112233445566778899aabbccddeeff';  // 16 байт
const aad   = 'aabbccdd';                          // дополнительные аутентифицируемые данные (hex)

sm4.encryptECB(key, msg16);                    // ECB без паддинга: ввод должен быть кратен 16 байтам
sm4.encryptCBC(key, iv, '616263');             // CBC с PKCS#7-паддингом; допустима любая длина
sm4.decryptCBC(key, iv, sm4.encryptCBC(key, iv, '616263'));
sm4.encryptCTR(key, iv, '616263');             // CTR/OFB — потоковые режимы (алиасы cryptCTR / cryptOFB)
const { ct, tag } = sm4.encryptGCM(key, iv, '616263', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);         // при ошибке аутентификации бросает DecryptionError; можно передать { safeMode: true }
```

### SM2 — генерация ключей / подпись / проверка / шифрование

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();  // async; возвращает PKCS#8 / SPKI PEM

const sig = sm2.sign(privateKeyPem, '616263');          // по умолчанию SM3withSM2; на выходе r||s в hex
sm2.verify(publicKeyPem, '616263', sig);                // → true

const ct  = sm2.encrypt(publicKeyPem, '616263');                  // по умолчанию C1C3C2
const ct2 = sm2.encrypt(publicKeyPem, '616263', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct);                         // на стороне расшифровки автоматически распознаётся C1C3C2 / C1C2C3
sm2.decrypt(privateKeyPem, ct, { safeMode: true });     // при ошибке возвращает null вместо исключения
```

Ключи также можно передавать как «сырой» hex или `Uint8Array` (32 байта для
закрытого ключа, 64 или 65 байт для открытого).

### SM2 — инкапсуляция ключа и гибридное шифрование

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();

// KEM: защитить случайный симметричный ключ открытым ключом (16 или 32 байта).
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);       // === key

// Гибридное шифрование: один вызов выполняет KEM + SM4-GCM; подходит для больших сообщений.
// Возвращает версионированный sealed: version || klen || encapLen || encapsulation || iv || tag || ct
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);               // → '616263' (открытый текст в hex)

// sealed можно представить в виде самоописывающего объекта.
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
```

- Каждый вызов `hybridEncrypt` создаёт новые 16-байтовый DEK и 12-байтовый IV; строки сообщений интерпретируются как **hex** (для пустого сообщения передайте `new Uint8Array(0)`).
- Гибридному режиму нужны и `sm2.wasm`, и `sm4.wasm`; перед первым вызовом выполните `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])`.
- `hybridDecrypt` поддерживает `{ safeMode: true }` и возвращает `null` при ошибках, связанных с шифртекстом.
- В SM2 нет стандартизованной конструкции KEM; `kemEncrypt` — общепринятый приём «зашифровать случайный ключ открытым ключом SM2».

### SM2 — протокол обмена ключами (GM/T 0003.3)

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

const r1 = alice.initiate();      // инициатор → ответчик, первое сообщение
const r2 = bob.respond(r1);       // ответчик → инициатор, ответ
const r3 = alice.confirm(r2);     // подтверждение инициатора (содержит S_A для проверки ответчиком)

alice.getSharedKey(r3);           // обе стороны получают один и тот же общий секрет
bob.getSharedKey(r3);
```

### SM9 — подпись / шифрование / инкапсуляция ключей (GM/T 0044)

```ts
import { sm9 } from 'sm-crypto-wasm';

// В SM9 два мастер-ключа (различаются по purpose): мастер-ключ подписи
// использует мастер-публичный ключ в G2, мастер-ключ шифрования — в G1.
const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });                 // по умолчанию purpose: 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', '616263');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', '616263', sig);
// Первый аргумент verify / encrypt также принимает мастер-приватный ключ (для обратной совместимости).

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);      // → '616263'

// Инкапсуляция ключа (KEM): согласование симметричного ключа без передачи сообщения.
// Обратите внимание: первый аргумент — это *мастер-приватный ключ шифрования*
// (KEM нуждается в нём, чтобы вывести Ppub-e; для encrypt выше допустим мастер-публичный ключ).
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);  // === key

// Гибридное шифрование: инкапсулировать 16-байтовый DEK мастер-публичным (или приватным)
// ключом и id, затем зашифровать сообщение через SM4-GCM.
const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.hybridDecrypt(encKp.masterPrivatePem, 'alice@foo.com', sealed);  // → '616263'
```

> Гибридному режиму SM9 нужны и `sm9.wasm`, и `sm4.wasm`: перед первым вызовом выполните `await sm9.ensureLoaded()` и `await sm4.ensureLoaded()`.

### ZUC — конфиденциальность EEA3 и целостность EIA3

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

zuc.zucKeystream(key, iv, 16);                  // поток ключей (Uint8Array)
zuc.zucEncrypt(key, iv, '616263');              // EEA3 — каждая тройка (key, iv, counter) может шифроваться лишь единожды
zuc.zucDecrypt(key, iv, ct);                    // расшифровка (защита от повторного использования не действует)

// Тег целостности EIA3 (32 бита); IV собирается из COUNT / BEARER / DIRECTION
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
zuc.zucMac(key, macIv, '616263');               // → 4-байтовый тег
```

---

## Сводка API

| Модуль | Функции |
|---|---|
| `sm2` | `generateKeyPair` (async) · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB` / `decryptECB` · `encryptCBC` / `decryptCBC` · `encryptCTR` / `decryptCTR` · `encryptCFB` / `decryptCFB` · `encryptOFB` / `decryptOFB` · `encryptGCM` / `decryptGCM` |
| `sm9` | `generateKeyPair` (async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `zuc` | `zucKeystream` · `zucEncrypt` · `zucDecrypt` · `zucMac` · `zucEia3Iv` · `configureReuseGuard` |

Документированные алиасы (указывают на ту же реализацию):
`sm4.encryptCTR` / `decryptCTR` — алиасы `cryptCTR`,
`encryptOFB` / `decryptOFB` — алиасы `cryptOFB`;
`zuc.encrypt` / `decrypt` / `generateKeystream` / `mac` / `eia3` — алиасы
`zucEncrypt` / `zucDecrypt` / `zucKeystream` / `zucMac`.

---

## Использование одного алгоритма (импорт по подпутям)

В сценариях, критичных к размеру, можно обойти агрегированную точку входа
и подгружать только нужный `.wasm`:

```ts
import { hash } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

Доступные подпути: `sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/zuc`.

---

## Кросс-рантайм

| Среда | Путь загрузки |
|---|---|
| Node 18+ | читает `dist/<algo>/<algo>.wasm` через `fs/promises`; доступен `loadWasmSync()` |
| Браузер (через сборщик) | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`; сборщик кладёт файл в вывод и переписывает URL |
| Web Worker | загрузчик не зависит от DOM и работает внутри Worker'а |
| Deno / Bun | идут по Node-пути |
| Встроенный браузер WeChat | как обычный браузер (`fetch` + `crypto.getRandomValues`); см. [WeChat и мини-программы](https://jktantan.github.io/sm-crypto-wasm/ru/guide/wechat) |
| Мини-программа WeChat | `WXWebAssembly` + `wx.getRandomValues`; см. [WeChat и мини-программы](https://jktantan.github.io/sm-crypto-wasm/ru/guide/wechat) |

### Поддержка сборщиков

Пакет поставляет две реализации (Node-версия читает файлы, браузерная использует
`fetch`), а поле `browser` в `package.json` переключает их на этапе сборки. Поэтому
**`node:*` не попадает в браузерный бандл** — сборщики, которые не выносят встроенные
модули Node наружу (Webpack, esbuild, Rspack), больше не падают на этапе разбора
с `Can't resolve 'node:fs'`.

| Сборщик | Нужна настройка? | Ресурс wasm |
|---|---|---|
| **Vite 5** | нет | автоматически попадает в вывод (`assets/*.wasm`) |
| **Webpack 5** | нет | автоматически выдаётся как asset |
| **Rspack 2** | нет | выдаётся как asset (имена с hash) |
| **Turbopack** (по умолчанию в Next.js 16) | нет | попадает в `static/media/*.wasm` |
| **esbuild** | одна строка плагина (ниже) | esbuild не обрабатывает файлы, на которые указывает `new URL(..., import.meta.url)` |
| **Node 18+** | нет | читает `dist/<algo>/<algo>.wasm` |

Пользователи esbuild подключают небольшой встроенный плагин — он кладёт wasm туда,
откуда его берёт рантайм:

```ts
import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outdir: 'dist/assets',        // сюда попадает выходной JS
  plugins: [smCryptoWasm()],    // → wasm копируется в dist/<algo>/<algo>.wasm
});
```

Не хотите плагин? Скопируйте `node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc}`
в **родительский** каталог выходного JS (в примере выше — `dist/`).

Браузеру нужен **защищённый контекст** (`https://` или `localhost`) для
`crypto.getRandomValues`; если его нет, библиотека **бросает ошибку** (fail-closed), а не
откатывается к некриптографическому источнику.

Среды со строго потоковой загрузкой WASM, такие как Cloudflare Workers / Vercel Edge,
**вне области поддержки**; загрузка «сырого» ESM напрямую через `<script type="module">`
(без сборщика) — тоже.

---

## Обработка ошибок

Все ошибки вида «отклонено из-за ввода» — подклассы `SmCryptoError`, в двух
ветках:

```ts
import { SmCryptoError, InvalidKeyError, InvalidPublicKeyError,
         CiphertextError, InvalidCiphertextError, DecryptionError } from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (e instanceof DecryptionError) { /* шифртекст не соответствует ключу */ }
  else if (e instanceof CiphertextError) { /* проблема структуры или валидации */ }
  else if (e instanceof InvalidKeyError) { /* формат / длина / кривая ключа */ }
  else throw e;
}
```

- Ветка ключей: `InvalidKeyError` (с подклассом `InvalidPublicKeyError`);
- Ветка шифртекста: `CiphertextError` (с подклассом
  `InvalidCiphertextError` для структурных ошибок и `DecryptionError` —
  для ошибок валидации);
- Проблемы с типом или диапазоном (например, ограничения длины,
  недопустимые значения перечислений) сохраняют нативные `TypeError` /
  `RangeError` среды исполнения.

---

## Замечания по безопасности

- **Используется только ГПСЧ среды исполнения**: `crypto.getRandomValues`
  (браузеры / Node 19+) либо `node:crypto`-shim для Node 18. **Собственный
  ГПСЧ в библиотеке не реализован.**
- **Закрытые ключи не пишутся на диск и не журналируются**: библиотека
  не выполняет никакой сериализации ключей на диск и не пишет их в логи.
- **Защита от повторного использования ZUC**: повторное шифрование с той
  же тройкой `(key, iv, counter)` приводит к исключению (повторное
  использование потока ключей — инцидент конфиденциальности). Если
  счётчик ведётся внешне, защиту можно отключить глобально через
  `configureReuseGuard({ enabled: false })` либо разово передав
  `{ reuseGuard: false }`.
- **Корректность открытого ключа SM2**: `encrypt` бросает
  `InvalidPublicKeyError` для точек вне кривой; `verify` возвращает
  просто `false`.
- Нет интеграции с криптографическим оборудованием / HSM / PKCS#11 /
  программными сертификатами; форматы ключей за пределами PEM не
  разбираются.

---

## Разработка

```bash
pnpm install
pnpm build          # clean + asc (5 .wasm-файлов) + tsc → dist/ (без source map)
pnpm build:ts:debug # для отладки: пересборка TS в dist/ с .js.map / .d.ts.map
pnpm test           # Node-раннер (vitest)
pnpm test:browser   # браузерный раннер (happy-dom)
pnpm bench          # микро-бенчмарки mitata (5 блоков алгоритмов)
pnpm lint           # biome (lint + format)
pnpm typecheck      # tsc --noEmit
```

`pnpm build` — это путь релиза: он сначала очищает `dist/`, а `tsconfig.build.json` отключает
`sourceMap` / `declarationMap`, поэтому в артефактах нет ни `.map`, ни комментариев
`//# sourceMappingURL=`. Причина: в пакет попадает только `dist/`, а `sources` в map указывают
на `../src/*.ts`, которых в пакете нет (и `sourcesContent` не встроен) — потребитель не получит ни
исходников, ни перехода к определениям, но заплатит примерно +35% размера. Для отладки внутри
репозитория используйте `pnpm build:ts:debug` (`tsconfig.build.debug.json`) — он кладёт map в
`dist/`.

**Все wasm-модули собираются только с `--optimize`, без `--enable simd`**: скорость SM4
даёт скалярное чередование блоков, которое не зависит ни от какого набора SIMD-инструкций.
Поэтому все пять модулей предъявляют одинаковые требования к среде, и `sm4.wasm` больше
не требует **WASM SIMD**.

Файлы в `src/**/assembly/**` — это исходники AssemblyScript, компилируемые
`asc`. **Не используйте** в них `import { type X }` и не позволяйте
форматтеру переставлять импорты — `asc` 0.28 не понимает модификатор типа
(соответствующие правила уже отключены для этого каталога в конфиге
biome).

В каждом каталоге `src/*/assembly/` лежит одно-строчный `tsconfig.json`,
который лишь `extends` корневой `tsconfig.assembly.json`. Он подтягивает
определения типов AS **исключительно ради того, чтобы IDE проверяла эти
файлы по семантике AS** — иначе при редактировании появляется `TS2304`
для `usize`, `u32`, `StaticArray` и т. п. Корневой `tsconfig.json`
`exclude`ит этот каталог, поэтому CLI-`tsc` их не трогает; эти
конфигурации не влияют ни на сборку, ни на проверку типов.

---

## Лицензия

[Apache-2.0](./LICENSE).

Реализации алгоритмов в этом проекте ссылаются на или портированы из
следующих проектов под Apache-2.0; сведения об авторстве — в
[`NOTICE`](./NOTICE):

- [GmSSL](https://github.com/guanzhi/GmSSL) — базовый источник семантики
  и наименований SM2 / SM9;
- [gmkit / gmkitx](https://github.com/gmkits/gmkit) — источник, из
  которого портирована реализация ZUC.

</details>
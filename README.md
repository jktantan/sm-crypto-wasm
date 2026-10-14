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

国密算法（SM2 / SM3 / SM4 / SM9 / ZUC）的 **AssemblyScript → WebAssembly** 实现，Node 18+ 与现代浏览器（含 Web Worker）均可使用，按算法分包、按需懒加载。

- **性能**：热点（大整数模运算 / hash 压缩 / 分组密码轮函数）跑在 WASM 里。轻量算法
  （SM3 / SM4 / ZUC）实测快于纯 JS 参考实现 1.1~3.0×；椭圆曲线部分（SM2）仍在优化中，
  见下方 **性能** 小节；
- **零工具链**：发布物是 `.wasm` + 薄 TS 胶水，使用者不需要 `node-gyp` / Rust / 编译器；
- **跨运行时**：同一份 API 在 Node、浏览器、Worker 下一致；
- **国标对齐**：实现按 GM/T 0003 / 0004 / 0002 / 0044 / 0001 系列，测试用官方向量与 OpenSSL / GmSSL / gmkitx 交叉对拍。

---

## 性能

热点（大整数模运算、hash 压缩函数、分组密码轮函数）在 WASM 内执行。下表覆盖本库
每个算法的**全部公开操作**；`gmkitx` 一列是对应的纯 JS 参考实现（同机、同参数、
同消息），**它没有的操作留 `—`**。实测环境 AMD Ryzen 7 7800X3D / Node 24.15 / Windows 11，
`pnpm bench` 可复现：

| 算法 | 操作 | sm-crypto-wasm | 纯 JS 参考（gmkitx） | 对比 |
|---|---|---|---|---|
| SM3 | hash 32 B / 1 KB / 64 KB | 1.03 µs / 6.35 µs / 332 µs | 13.6 µs（1 KB） | 快 2.1× |
| SM3 | hmac 1 KB | 10.4 µs | 17.9 µs | 快 1.7× |
| SM4 | ECB 16 B / 1 KB | 0.78 µs / 19.6 µs | 37.7 µs（1 KB） | 快 1.9× |
| SM4 | CBC 1 KB | 22.8 µs | 41.9 µs | 快 1.8× |
| SM4 | CTR 1 KB | 20.3 µs | 36.8 µs | 快 1.8× |
| SM4 | CFB 1 KB | 22.3 µs | 38.2 µs | 快 1.7× |
| SM4 | OFB 1 KB | 21.9 µs | 36.7 µs | 快 1.7× |
| SM4 | GCM 1 KB | 33.0 µs | 226 µs | 快 6.8× |
| SM2 | 密钥对生成 | 183 µs | — | — |
| SM2 | 公钥派生 | 139 µs | 191 µs | 快 1.4× |
| SM2 | 签名 64 B | 336 µs | 443 µs | 快 1.3× |
| SM2 | 验签 64 B | 487 µs | 2.79 ms | 快 5.7× |
| SM2 | 加密 64 B | 547 µs | 2.94 ms | 快 5.4× |
| SM2 | 解密 64 B | 350 µs | 2.53 ms | 快 7.5× |
| SM2 | 密钥交换（完整 A↔B） | 1.65 ms | 11.4 ms | 快 7.0× |
| SM9 | 主密钥对生成（签名 / 加密） | 3.57 / 3.03 ms | — | — |
| SM9 | 主公钥派生（签名 / 加密） | 167 / 88.7 µs | — | — |
| SM9 | 用户公钥派生 | 1.07 ms | — | — |
| SM9 | 签名 32 B | 6.78 ms | — | — |
| SM9 | 验签 32 B | 12.8 ms | — | — |
| SM9 | 加密 32 B | 5.54 ms | — | — |
| SM9 | 解密 32 B | 7.73 ms | — | — |
| SM9 | KEM 封装 / 解封装 | 4.99 / 7.63 ms | — | — |
| SM9 | 密钥交换（完整 A↔B） | 28.0 ms | — | — |
| ZUC | EEA3 加密 1 KB | 9.58 µs | 20.4 µs | 快 2.1× |
| ZUC | EEA3 密钥流 1 KB | 6.43 µs | — | — |
| ZUC | EIA3 MAC 1 KB | 11.2 µs | — | — |

要点：

- **所有经过对比的操作都快于纯 JS 参考**：SM3 / ZUC 快 1.7~2.1×，SM4 六种模式
  1.7~6.8×，SM2 快 1.3~7.5×；
- **SM4 的 CFB / OFB 曾比纯 JS 慢 1.4~1.5×**：这两种模式原先在 TS 侧逐块调用
  wasm（每 16 字节一次 alloc + 调用 + 取值，1 KB 要 64 次跨界）；补上与 CBC/CTR
  同款的批量导出后降到 24 µs 一带，反过来快 1.3~1.4×；
- **SM4 的瓶颈是每轮 4 次 S 盒查表**：把 S 盒与 L 变换合成 T-table 只换来 8~10%
  （查表次数不变），因为成本不在 ALU 而在内存访问。本库进一步把 ECB / CTR / GCM 的
  GCTR 改成 **WASM SIMD 的 4 路并行**——4 个块摊到一个 `v128` 的 4 个 lane，异或链与
  线性层 L 一次算 4 块（S 盒仍逐 lane 走标量查表，故收益停在约 1.3× 而非 4×），
  尾块回退标量。这也解释了为什么仍追不上 C：它靠 ARMv8 的 `SM4E` 指令用电路做
  S 盒、**根本不查表**，而 WebAssembly 不暴露该指令集（通用 SIMD 也只给通用算子）；
- **SM9 没有可比实现**（纯 JS 生态普遍如此，pairing 在纯 JS 里成本过高），故只给
  本库的绝对耗时；
- **SM2 的 wasm 大整数是线性内存裸指针**（`U256` 即 `usize`，配模块级 bump arena 与
  每次导出调用回卷），在这一层之上做了四件事：
  1. **素域 p 的归约走 Solinas**——p = 2^256−2^224−2^96+2^64−1 是伪 Mersenne，展开
     2^256 ≡ 2^224+2^96−2^64+1 后归约只需加减移位、没有乘法；
  2. **平方改 Comba（列扫描）+ 统一进位**——旧实现每对 (i,j) 要跑两遍完整的进位传播
     循环（共 56 次内存循环），是整个库最贵的单个函数；
  3. **标量乘分两条路**：固定基点走 comb 预计算表（w=5、32 项；51 次倍点 + 52 次点加），
     任意点走 wNAF（w=5，点加从 ~128 次降到 ~43 次）。表惰性构造一次，缓存在 arena
     之外的永久区；
  4. **点运算全程原地**：倍点 / 点加写模块级 scratch，不再逐次 `new U256` + `new JPoint`
     （一次倍点原本 ~11 次堆分配，而标量乘要调用它几百次）。
  合起来签名从 6.10 ms 降到 300 µs（20×），公钥派生 2.96 ms → 115 µs（26×）；
- **代价与取舍**：comb 只适用于固定基点，Solinas 只适用于伪 Mersenne 模数——SM2 的
  标量模 n 与 SM9 的 p/n 都不是这个形状（仍走 Barrett），SM9 若要再快需要换 Montgomery，
  而那意味着把该曲线全部常数搬进 Montgomery 域，属重写级改动；
- SM9 由 pairing 主导，扩域元素（Fp2/Fp4/Fp12）改为连续内存表示后 sign / verify
  快约 2.6×；
- 数字随版本与机器变化，请以本机 `pnpm bench` 为准。

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
```

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
| `sm2` | `generateKeyPair`(async) · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `createExchangeInitiator`(async) · `createExchangeResponder`(async) |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB`/`decryptECB` · `encryptCBC`/`decryptCBC` · `encryptCTR`/`decryptCTR` · `encryptCFB`/`decryptCFB` · `encryptOFB`/`decryptOFB` · `encryptGCM`/`decryptGCM` |
| `sm9` | `generateKeyPair`(async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator`(async) · `createExchangeResponder`(async) |
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

| 环境 | 说明 |
|---|---|
| Node 18+ | `fs/promises` 读取 `dist/<algo>/<algo>.wasm` |
| 浏览器 / Vite / Webpack | `fetch(new URL('./<algo>.wasm', import.meta.url))`，打包器负责重写 URL |
| Web Worker | 加载器不依赖 DOM，Worker 内可用 |
| Deno / Bun | 走 Node 同路径 |

Cloudflare Workers / Vercel Edge 这类"严格流式 WASM"环境**不在当前范围**。

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
pnpm build          # asc（5 个 .wasm）+ tsc → dist/
pnpm test           # Node runner（vitest）
pnpm test:browser   # 浏览器 runner（happy-dom）
pnpm bench          # mitata 微型基准（5 大块算法）
pnpm lint           # biome（lint + format）
pnpm typecheck      # tsc --noEmit
```

**SM4 的 wasm 用 `--enable simd` 编译**（`build:wasm:sm4` 已带该 flag），因为它的
ECB / CTR / GCM-GCTR 走 WASM SIMD 的 4 路并行。因此 `sm4.wasm` 要求运行时支持
**WASM SIMD**——Node 18+ 与现代浏览器都满足；若某运行时禁用了 SIMD，SM4 会在实例化
时报错，其它算法（不带 SIMD）不受影响。

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

Hot paths (bignum modular arithmetic, hash compression, block-cipher rounds) run
inside WASM. The table below covers **every public operation of every algorithm**
in this library; the `gmkitx` column is the corresponding pure-JS reference (same
machine, same parameters, same messages), and **operations it does not offer are
left as `—`**. Measured on AMD Ryzen 7 7800X3D / Node 24.15 / Windows 11, reproducible
with `pnpm bench`:

| Algorithm | Operation | sm-crypto-wasm | pure-JS reference (gmkitx) | |
|---|---|---|---|---|
| SM3 | hash 32 B / 1 KB / 64 KB | 1.03 µs / 6.35 µs / 332 µs | 13.6 µs (1 KB) | 2.1× faster |
| SM3 | hmac 1 KB | 10.4 µs | 17.9 µs | 1.7× faster |
| SM4 | ECB 16 B / 1 KB | 0.78 µs / 19.6 µs | 37.7 µs (1 KB) | 1.9× faster |
| SM4 | CBC 1 KB | 22.8 µs | 41.9 µs | 1.8× faster |
| SM4 | CTR 1 KB | 20.3 µs | 36.8 µs | 1.8× faster |
| SM4 | CFB 1 KB | 22.3 µs | 38.2 µs | 1.7× faster |
| SM4 | OFB 1 KB | 21.9 µs | 36.7 µs | 1.7× faster |
| SM4 | GCM 1 KB | 33.0 µs | 226 µs | 6.8× faster |
| SM2 | generateKeyPair | 183 µs | — | — |
| SM2 | public key derive | 139 µs | 191 µs | 1.4× faster |
| SM2 | sign 64 B | 336 µs | 443 µs | 1.3× faster |
| SM2 | verify 64 B | 487 µs | 2.79 ms | 5.7× faster |
| SM2 | encrypt 64 B | 547 µs | 2.94 ms | 5.4× faster |
| SM2 | decrypt 64 B | 350 µs | 2.53 ms | 7.5× faster |
| SM2 | key exchange (full A↔B) | 1.65 ms | 11.4 ms | 7.0× faster |
| SM9 | master key pair (sign / enc) | 3.57 / 3.03 ms | — | — |
| SM9 | master public key (sign / enc) | 167 / 88.7 µs | — | — |
| SM9 | user public key (derive) | 1.07 ms | — | — |
| SM9 | sign 32 B | 6.78 ms | — | — |
| SM9 | verify 32 B | 12.8 ms | — | — |
| SM9 | encrypt 32 B | 5.54 ms | — | — |
| SM9 | decrypt 32 B | 7.73 ms | — | — |
| SM9 | KEM encapsulate / decapsulate | 4.99 / 7.63 ms | — | — |
| SM9 | key exchange (full A↔B) | 28.0 ms | — | — |
| ZUC | EEA3 encrypt 1 KB | 9.58 µs | 20.4 µs | 2.1× faster |
| ZUC | EEA3 keystream 1 KB | 6.43 µs | — | — |
| ZUC | EIA3 MAC 1 KB | 11.2 µs | — | — |

Notes:

- **Every operation with a counterpart beats the pure-JS reference**: SM3 / ZUC by
  1.7–2.1×, the six SM4 modes by 1.7–6.8×, SM2 by 1.3–7.5×;
- **SM4's CFB / OFB used to be 1.4–1.5× *slower* than pure JS**: those two modes
  were driven block-by-block from the TS side (alloc + call + copy back every 16
  bytes — 64 wasm crossings per KB). With the same batched export CBC/CTR already
  had, they now land at ~24 µs, i.e. **1.3–1.4× faster** than the reference;
- **SM4's bottleneck is the four S-box lookups per round**: merging the S-box and L
  transform into T-tables bought only 8–10% (the lookup count is unchanged), because
  the cost is memory access, not ALU work. This library goes further and runs
  ECB / CTR / GCM's GCTR as **4-way WASM SIMD** — four blocks spread across the four
  lanes of a `v128`, so the XOR chain and the L transform are computed four blocks at
  a time (the S-box still walks the scalar lookup table lane by lane, which is why the
  gain stops at ~1.3× rather than 4×), with the tail falling back to scalar. This also
  explains the remaining gap to C: OpenSSL uses ARMv8's `SM4E` instruction to
  implement the S-box in circuitry with **no table lookup at all**, and WebAssembly
  does not expose that instruction set (generic SIMD only offers generic operators);
- **SM9 has no comparable implementation** (as usual for pure JS, where pairing is
  prohibitively expensive), so only this library's absolute timings are given;
- **SM2's wasm big integers are linear-memory raw pointers** (`U256` is a `usize`
  backed by a module-level bump arena that rewinds at every exported entry), and
  on top of that four things changed:
  1. **Reduction in the prime field p uses Solinas** — p = 2^256−2^224−2^96+2^64−1
     is pseudo-Mersenne, so expanding 2^256 ≡ 2^224+2^96−2^64+1 makes reduction
     pure add/subtract/shift with no multiplication at all;
  2. **Squaring was rewritten as Comba (column scan) with a single carry pass** —
     the old version ran two full carry-propagation loops per (i,j) pair (56 memory
     loops in total), making it the single most expensive function in the library;
  3. **Scalar multiplication takes two routes**: fixed-base uses a comb table
     (w=5, 32 entries; 51 doublings + 52 additions), arbitrary-point uses wNAF
     (w=5, cutting additions from ~128 to ~43). The table is built lazily once and
     cached in a permanent area outside the arena;
  4. **Point arithmetic is fully in-place**: doubling and addition write
     module-level scratch instead of allocating a fresh `U256` per operation plus
     a `JPoint` (a single doubling used to cost ~11 heap allocations, and scalar
     multiplication calls it hundreds of times).
  Together: signing 6.10 ms → 300 µs (20×), public-key derivation 2.96 ms → 115 µs
  (26×);
- **Trade-offs**: comb applies only to the fixed base point and Solinas only to
  pseudo-Mersenne moduli — SM2's scalar modulus n and SM9's p/n are not of that
  shape (they still use Barrett), and making SM9 faster than this would mean
  Montgomery, i.e. moving every curve constant into the Montgomery domain, which
  is a rewrite rather than a change;
- SM9 is dominated by pairings; with its extension-field elements (Fp2/Fp4/Fp12)
  now laid out as contiguous memory, sign / verify are ~2.6× faster;
- Numbers vary with version and machine — run `pnpm bench` locally.

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
```

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
| `sm2` | `generateKeyPair` (async) · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB` / `decryptECB` · `encryptCBC` / `decryptCBC` · `encryptCTR` / `decryptCTR` · `encryptCFB` / `decryptCFB` · `encryptOFB` / `decryptOFB` · `encryptGCM` / `decryptGCM` |
| `sm9` | `generateKeyPair` (async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
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

| Environment | Notes |
|---|---|
| Node 18+ | reads `dist/<algo>/<algo>.wasm` via `fs/promises` |
| Browser / Vite / Webpack | `fetch(new URL('./<algo>.wasm', import.meta.url))`; the bundler rewrites the URL |
| Web Worker | the loader is DOM-free and works inside a Worker |
| Deno / Bun | follows the Node path |

Strict-streaming WASM environments such as Cloudflare Workers / Vercel Edge
are **out of scope**.

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
pnpm build          # asc (5 .wasm files) + tsc → dist/
pnpm test           # Node runner (vitest)
pnpm test:browser   # browser runner (happy-dom)
pnpm bench          # mitata micro-benchmarks (5 algorithm blocks)
pnpm lint           # biome (lint + format)
pnpm typecheck      # tsc --noEmit
```

**SM4's wasm is compiled with `--enable simd`** (`build:wasm:sm4` already carries the
flag), because its ECB / CTR / GCM-GCTR run as 4-way WASM SIMD. `sm4.wasm` therefore
requires a runtime with **WASM SIMD** — Node 18+ and modern browsers qualify; on a
runtime with SIMD disabled, SM4 fails at instantiation, while the other algorithms
(which carry no SIMD) are unaffected.

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
шифра) выполняются внутри WASM. Таблица ниже покрывает **все публичные операции
каждого алгоритма**; столбец `gmkitx` — соответствующая чистая JS-реализация
(та же машина, те же параметры, те же сообщения), а **операции, которых у неё
нет, оставлены как `—`**. Измерено на AMD Ryzen 7 7800X3D / Node 24.15 / Windows 11,
воспроизводится через `pnpm bench`:

| Алгоритм | Операция | sm-crypto-wasm | чистая JS (gmkitx) | |
|---|---|---|---|---|
| SM3 | hash 32 B / 1 KB / 64 KB | 1.03 µs / 6.35 µs / 332 µs | 13.6 µs (1 KB) | в 2.1× быстрее |
| SM3 | hmac 1 KB | 10.4 µs | 17.9 µs | в 1.7× быстрее |
| SM4 | ECB 16 B / 1 KB | 0.78 µs / 19.6 µs | 37.7 µs (1 KB) | в 1.9× быстрее |
| SM4 | CBC 1 KB | 22.8 µs | 41.9 µs | в 1.8× быстрее |
| SM4 | CTR 1 KB | 20.3 µs | 36.8 µs | в 1.8× быстрее |
| SM4 | CFB 1 KB | 22.3 µs | 38.2 µs | в 1.7× быстрее |
| SM4 | OFB 1 KB | 21.9 µs | 36.7 µs | в 1.7× быстрее |
| SM4 | GCM 1 KB | 33.0 µs | 226 µs | в 6.8× быстрее |
| SM2 | generateKeyPair | 183 µs | — | — |
| SM2 | вывод открытого ключа | 139 µs | 191 µs | в 1.4× быстрее |
| SM2 | подпись 64 B | 336 µs | 443 µs | в 1.3× быстрее |
| SM2 | проверка 64 B | 487 µs | 2.79 ms | в 5.7× быстрее |
| SM2 | шифрование 64 B | 547 µs | 2.94 ms | в 5.4× быстрее |
| SM2 | расшифрование 64 B | 350 µs | 2.53 ms | в 7.5× быстрее |
| SM2 | обмен ключами (полный A↔B) | 1.65 ms | 11.4 ms | в 7.0× быстрее |
| SM9 | главная пара ключей (sign / enc) | 3.57 / 3.03 ms | — | — |
| SM9 | главный открытый ключ (sign / enc) | 167 / 88.7 µs | — | — |
| SM9 | открытый ключ пользователя | 1.07 ms | — | — |
| SM9 | подпись 32 B | 6.78 ms | — | — |
| SM9 | проверка 32 B | 12.8 ms | — | — |
| SM9 | шифрование 32 B | 5.54 ms | — | — |
| SM9 | расшифрование 32 B | 7.73 ms | — | — |
| SM9 | KEM инкапсуляция / декапсуляция | 4.99 / 7.63 ms | — | — |
| SM9 | обмен ключами (полный A↔B) | 28.0 ms | — | — |
| ZUC | EEA3 шифрование 1 KB | 9.58 µs | 20.4 µs | в 2.1× быстрее |
| ZUC | EEA3 гамма 1 KB | 6.43 µs | — | — |
| ZUC | EIA3 MAC 1 KB | 11.2 µs | — | — |

Примечания:

- **Каждая операция, у которой есть аналог, быстрее чистой JS-реализации**:
  SM3 / ZUC — в 1.7–2.1×, шесть режимов SM4 — в 1.7–6.8×, SM2 — в 1.3–7.5×;
- **CFB / OFB у SM4 раньше были в 1.4–1.5× _медленнее_ чистой JS**: эти два режима
  вызывались поблочно со стороны TS (alloc + вызов + копирование на каждые 16 байт —
  64 пересечения границы на 1 KB). С тем же пакетным экспортом, что уже был у CBC/CTR,
  они теперь ~24 µs, то есть **в 1.3–1.4× быстрее** аналога;
- **Узкое место SM4 — четыре обращения к S-блоку за раунд**: объединение S-блока и
  L-преобразования в T-таблицы дало лишь 8–10% (число обращений не меняется), потому что
  стоимость — это доступ к памяти, а не работа ALU. Эта библиотека идёт дальше и выполняет
  ECB / CTR / GCTR у GCM как **4-полосный WASM SIMD** — четыре блока раскладываются по
  четырём полосам одного `v128`, так что цепочка XOR и L-преобразование считаются сразу для
  четырёх блоков (S-блок по-прежнему идёт по скалярной таблице полоса за полосой — поэтому
  выигрыш останавливается на ~1.3×, а не 4×), хвост обрабатывается скалярно. Это же
  объясняет оставшийся разрыв с C: OpenSSL использует инструкцию ARMv8 `SM4E`, реализующую
  S-блок схемой **вообще без обращений к таблицам**, а WebAssembly этого набора инструкций
  не предоставляет (общий SIMD даёт только общие операторы);
- **У SM9 нет сопоставимой реализации** (обычная ситуация для чистого JS, где
  спаривания запредельно дороги), поэтому приведены только абсолютные времена
  этой библиотеки;
- **Большие числа в wasm-части SM2 — сырые указатели в линейной памяти** (`U256` —
  это `usize` поверх bump-арены уровня модуля, которая откатывается на каждом входе
  в экспортируемую функцию); поверх этого сделано четыре вещи:
  1. **Приведение в простом поле p по схеме Солинаса** — p = 2^256−2^224−2^96+2^64−1
     псевдо-мерсенново, поэтому после разложения 2^256 ≡ 2^224+2^96−2^64+1 приведение
     состоит только из сложений, вычитаний и сдвигов, без умножений вообще;
  2. **Возведение в квадрат переписано по схеме Comba (сканирование по столбцам) с
     одним проходом переносов** — старая версия выполняла два полных цикла
     распространения переносов на каждую пару (i,j) (56 циклов по памяти), из-за чего
     это была самая дорогая функция в библиотеке;
  3. **Скалярное умножение идёт двумя путями**: для фиксированной базовой точки —
     comb-таблица (w=5, 32 записи; 51 удвоение + 52 сложения), для произвольной точки —
     wNAF (w=5, сложений ~128 → ~43). Таблица строится лениво один раз и кэшируется в
     постоянной области вне арены;
  4. **Операции над точками полностью на месте**: удвоение и сложение пишут в
     модульные scratch-буферы вместо `new U256` на каждую операцию плюс `JPoint`
     (одно удвоение стоило ~11 выделений в куче, а скалярное умножение вызывает его
     сотни раз).
  Итого: подпись 6.10 ms → 300 µs (20×), вывод открытого ключа 2.96 ms → 115 µs (26×);
- **Компромиссы**: comb применим только к фиксированной базовой точке, Солинас — только
  к псевдо-мерсенновым модулям: скалярный модуль n у SM2 и p/n у SM9 не такой формы
  (там по-прежнему Барретт), а чтобы ускорить SM9 дальше, нужен Монтгомери — то есть
  перенос всех констант кривой в область Монтгомери, а это переписывание, а не правка;
- SM9 определяется спариваниями; после перехода элементов расширения (Fp2/Fp4/Fp12)
  на непрерывную память sign / verify ускорились примерно в 2.6×;
- Цифры зависят от версии и машины — запускайте `pnpm bench` локально.

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
```

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
| `sm2` | `generateKeyPair` (async) · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB` / `decryptECB` · `encryptCBC` / `decryptCBC` · `encryptCTR` / `decryptCTR` · `encryptCFB` / `decryptCFB` · `encryptOFB` / `decryptOFB` · `encryptGCM` / `decryptGCM` |
| `sm9` | `generateKeyPair` (async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
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

| Среда | Примечания |
|---|---|
| Node 18+ | читает `dist/<algo>/<algo>.wasm` через `fs/promises` |
| Браузер / Vite / Webpack | `fetch(new URL('./<algo>.wasm', import.meta.url))`; бандлер переписывает URL |
| Web Worker | загрузчик не зависит от DOM и работает внутри Worker'а |
| Deno / Bun | идут по Node-пути |

Среды со строго потоковой загрузкой WASM, такие как Cloudflare Workers /
Vercel Edge, **вне области поддержки**.

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
pnpm build          # asc (5 .wasm-файлов) + tsc → dist/
pnpm test           # Node-раннер (vitest)
pnpm test:browser   # браузерный раннер (happy-dom)
pnpm bench          # микро-бенчмарки mitata (5 блоков алгоритмов)
pnpm lint           # biome (lint + format)
pnpm typecheck      # tsc --noEmit
```

**wasm-часть SM4 компилируется с `--enable simd`** (флаг уже в `build:wasm:sm4`),
потому что её ECB / CTR / GCTR у GCM работают как 4-полосный WASM SIMD. Поэтому
`sm4.wasm` требует среды с поддержкой **WASM SIMD** — Node 18+ и современные браузеры
подходят; если в среде SIMD отключён, SM4 падает при инстанцировании, а остальные
алгоритмы (без SIMD) не затронуты.

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
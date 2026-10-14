# sm-crypto-wasm 设计稿

- 日期：2026-10-13
- 仓库：`/Users/bytonsec/works/github/sm-crypto-wasm`
- 包名：`sm-crypto-wasm`
- 版本起步：`0.1.0`
- 目标 Node：`>=18`
- License：`Apache-2.0`

> 这份文档给"国密 WASM 工具包"项目锁定的范围、目标、约束、关键决策。读完即可进入 plan 阶段，无需再回头问产品问题。

---

## 1. Intent & Why

我们要做一个 npm 包 `sm-crypto-wasm`，让前端 / Node 后端工程师用一行 `import { sm2, sm4 } from 'sm-crypto-wasm'` 就能调用国密算法，不需要懂 ASN.1 / 大数 / WASM 桥接。

**为什么现在**：国内金融、政企、医疗场景的合规需求把 SM2 / SM3 / SM4 从"可选"推到"必选"。现有 JS 国密库多是纯 JS 实现，性能差；或纯 Node addon、不能上浏览器；或功能碎片、要自己拼协议。我们想补这个"性能 + 跨运行时 + API 友好"三合一的空缺。

**为什么 AssemblyScript + WASM**：

- 业务侧的工程语言是 TypeScript，AS 编译产物的 JS 桥接层非常薄、维护成本低；
- 比纯 JS 国密库快一个数量级（椭圆曲线、Pairing 都是热点）；
- 比 C++ / Rust 实现分发到 npm 简单——不需要 node-gyp、不需要用户装编译工具链；
- 一个 `asc` 工具链就够，不需要维护 N-API。

---

## 2. Goals / Non-Goals / Anti-Goals

### Goals（必须达到）

- 暴露 5 大块算法的高层 API：SM2、SM3、SM4、SM9、ZUC；
- SM2 必须含密钥交换协议（GM/T 0003-2014 路径），业务方法（加密/签名/验签/解密）**同步**暴露；
- SM9 必须含签名/验签/加密/解密，对应"密钥封装"由此覆盖；主私钥 / 主公钥采用 **PKCS#8 + 自定义 OID（1.2.156.10197.1.100）** 编码；
- ZUC 必须含 EEA3 机密性算法 + EIA3 完整性算法；
  - **仅 ZUC-128**（GM/T 0001-2012 / 3GPP TS 35.221）。ZUC-256（GM/T 0001.1-2021）列为将来支持，当前不实现（2026-10-13 用户确认）。
- Node 18+ 与现代浏览器（含 Web Worker）均可 `import`；
- 输入输出自动嗅探（hex/base64/Uint8Array），输出默认 hex；
- WASM 按算法分包，按需懒加载；
- 提供 TS 类型与 JSDoc；
- 提供 GM/T 标准测试向量与自写 sanity 用例；
- 提供 Wycheproof 风格的 fuzz 用例（公钥攻击、负值曲线参数、长度溢出等）；
- 通过 GitHub Actions 自动构建 + 测试 + tag 发布。

### Non-Goals（这次不做，但留扩展点）

- **ZUC-256**（GM/T 0001.1-2021）——独立的 LFSR/初始化/密钥加载，非 ZUC-128 的参数化；无现成第三方 oracle；列为将来支持。
- WebCrypto 适配层（`crypto.subtle` 风格的 API）；
- 国密机 / HSM / PKCS#11 / 软证书句柄（你确认 C 很少）；
- X.509 / PKCS#7 / CMS / SMIME 协议封装；
- Cloudflare Workers / Vercel Edge 这类"严格流式 WASM"环境；
- 硬件加速（Intel ADX、ARMv8 CE）；
- WebAssembly SIMD 优化（AssemblyScript 当前 SIMD 支持有限）—— **SM4 已部分落地**：ECB / CTR / GCM 的 GCTR 走 `v128` 4 路并行（约 1.3×，见 README 性能小节）；SM2 / SM3 / SM9 / ZUC 与 SM4 其余模式仍按 Non-Goal。

### Anti-Goals（一旦发现正在做，立刻停）

- 暴露大数 / 曲线点 / 模运算等底层接口给业务开发者（属于上一级抽象，开发者只能进 crypto.subtle 这种）；
- 内置 `随机数生成器` —— 永远用宿主 `crypto.getRandomValues` / `crypto.randomBytes`，不另起 RNG；
- 把任何私钥 / 中间状态序列化到磁盘 / 日志。

---

## 3. 范围算法清单

| 算法 | 规格 | 设计 API | 实际导出（2026-10-14 对账） |
|---|---|---|---|
| SM2 | GM/T 0003-2014（含密钥交换协议、加密、签名） | `sm2.encrypt / decrypt / sign / verify / keyExchange / generateKeyPair` | `generateKeyPair`（async，PEM 密钥对）、`encrypt`（`{ outputFormat: 'C1C3C2' \| 'C1C2C3' }`，默认 C1C3C2）、`decrypt`（自动识别两种顺序，支持 `safeMode`）、`sign / verify / getPublicKey`、`createExchangeInitiator / createExchangeResponder` |
| SM3 | GM/T 0004-2014 | `sm3.hash / sm3.hmac` | 同设计（另有 `ensureLoaded()` 预热；空输入按零长度消息处理） |
| SM4 | GM/T 0002-2014 | ECB / CBC / CTR / CFB / OFB / GCM | `encryptECB/decryptECB`、`encryptCBC/decryptCBC`、`encryptCFB/decryptCFB`、`encryptGCM/decryptGCM`（后者支持 `{ aad?, safeMode? }`）、`cryptCTR`（别名 `encryptCTR` / `decryptCTR`）、`cryptOFB`（别名 `encryptOFB` / `decryptOFB`） |
| SM9 | GM/T 0044-2016（含签名、密钥封装、密钥交换） | `sm9.sign / verify / encrypt / decrypt / generateKeyPair` | `generateKeyPair`（async，PKCS#8/SPKI PEM 四件套含 `userPublicPem`）、`sign`、`verify` / `encrypt`（密钥参数可为**主私钥**或**主公钥**：hex / PEM / 点字节）、`decrypt`（支持 `safeMode`）、`kemEncrypt / kemDecrypt`、`getSignPublicKey / getEncPublicKey / getUserPublicKey`、`createExchangeInitiator / createExchangeResponder` |
| ZUC | GM/T 0001-2012 + GM/T 0001.1-2012 128 比特 | `zuc.encrypt (EEA3) / zuc.mac (EIA3) / zuc.generateKeystream` | `zucKeystream`（别名 `generateKeystream`）、`zucEncrypt`（别名 `encrypt`，带可配置的 (key,iv,counter) 复用保护）、`zucDecrypt`、`zucMac`（别名 `mac` / `eia3`，第 4 参支持 options 对象）、`zucEia3Iv` |

不重复造"密钥交换"作独立算法：SM2 内置密钥交换协议、SM9 内置密钥封装，合并覆盖。

---

## 4. 工程栈与构建

- 语言：核心算法用 **AssemblyScript**；胶水层用 **TypeScript**；
- 编译：`asc`（AssemblyScript 官方编译器）；
- 打包：`rollup` 把 AS 编译产物 + TS 胶水打 ESM / CJS 双产物；
- 测试：`vitest`（Node 端 + 浏览器端 jsdom）、`mitata`（micro-bench）；
- fuzz：`fast-check`，Wycheproof 风格；
- 发布：`pnpm publish`，GitHub Actions `release.yml` 在 tag 推送时触发；
- Lint / 格式化：`eslint` + `prettier` + `biome`（任选其一，挑快的）；
- 包管理：`pnpm`，仓库自带 `pnpm-lock.yaml`。

---

## 5. 产物结构

```
sm-crypto-wasm/
├── src/
│   ├── index.ts                  # 聚合入口，动态 import 实现懒加载
│   ├── runtime.ts                # 跨运行时工具：Uint8Array/hex/base64 互转
│   ├── pem.ts                    # PEM / DER 解码（PKCS#8 / SPKI / SM2 专用）
│   ├── sm2/
│   │   ├── index.ts              # 业务 API 层
│   │   ├── curve.ts              # 椭圆曲线参数 + 点乘
│   │   └── assembly/index.ts     # AS 实现的（编译为 sm2.wasm）
│   ├── sm3/
│   │   ├── index.ts
│   │   └── assembly/index.ts
│   ├── sm4/...
│   ├── sm9/...
│   └── zuc/...
├── dist/                         # build 产物
│   ├── index.js / index.cjs / index.d.ts
│   ├── sm2/                      # 每个算法一份：sm2.wasm + sm2.js + sm2.d.ts
│   ├── sm3/...
│   ├── sm4/...
│   ├── sm9/...
│   └── zuc/...
├── tests/
│   ├── vectors/                  # GM/T 标准向量 JSON
│   ├── *.spec.ts                 # vitest 用例
│   └── fuzz/                     # fast-check fuzz
├── bench/
│   └── *.bench.ts                # mitata micro-bench
├── package.json                  # version 0.1.0, engines ">=18", license Apache-2.0
├── README.md
├── LICENSE                       # Apache-2.0
└── docs/
    └── superpowers/specs/        # 本目录
```

发布到 npm 时 `dist/` 是主体，`src/` 作为 source map 引用保留但不强制要求消费者使用。

---

## 6. API 形态（预览）

业务开发者视角：

```ts
import { sm2, sm3, sm4, sm9, zuc } from 'sm-crypto-wasm';

// SM3（纯同步）
const digest = sm3.hash('hello');                     // → hex
const hmac   = sm3.hmac(key, 'msg');

// SM4（纯同步；模式=方法名后缀）
const ct = sm4.encryptCBC(keyHex, ivHex, 'plain');    // 输出 hex
const pt = sm4.decryptCBC(keyHex, ivHex, ct);
const ctGcm = sm4.encryptGCM(keyHex, ivHex, 'plain', aad);

// SM2：业务方法全部同步；只有密钥生成 / 密钥交换协议是 async
const kp  = await sm2.generateKeyPair();             // → { privateKeyPem, publicKeyPem }
const ct  = sm2.encrypt(publicKeyPem, 'msg');        // 默认 C1C3C2
const sig = sm2.sign(privateKeyPem, 'msg');          // 默认 SM3withSM2
const ok  = sm2.verify(publicKeyPem, 'msg', sig);

// SM2 密钥交换协议（双方，async 协议流）
const alice = await sm2.createExchangeInitiator(privA, pubB);
const bob   = await sm2.createExchangeResponder(privB, pubA);
const r1    = alice.initiate();
const r2    = bob.respond(r1);
const r3    = alice.confirm(r2);
const keyA  = alice.getSharedKey(r3);
const keyB  = bob.getSharedKey(r3);

// SM9：加密/签名同步；密钥生成 async
const kp  = await sm9.generateKeyPair({ id: 'alice@foo.com' });
const sig = sm9.sign(masterPrivatePem, 'alice@foo.com', 'msg');
const ok  = sm9.verify(masterPublicPem, 'alice@foo.com', 'msg', sig);
const { ciphertext, key } = sm9.encrypt(masterPublicPem, 'alice@foo.com');
const pt = sm9.decrypt(masterPrivatePem, 'alice@foo.com', ciphertext);

// ZUC（纯同步）
const stream = zuc.encrypt(key, iv, 'plain');        // EEA3
const mac    = zuc.mac(key, iv, 'msg', 32);          // EIA3
```

子入口（体积敏感场景）：

```ts
import { encrypt } from 'sm-crypto-wasm/sm2';   // 只加载 sm2.wasm
```

> 详细同步/异步策略见 §12.1 已确认项。

---

## 7. 跨运行时

- **Node 18+**：`pnpm install` 后即可 `import`；`sm2.wasm` 等用 `fs/promises.readFile` + `WebAssembly.instantiate`；
- **浏览器**：打包器（Vite/Webpack）把 `*.wasm` 当资源处理，自动生成 fetch URL；库对外仍只暴露 `import` 入口；
- **Deno / Bun**：天然支持，只要产物里有 `.wasm` 文件可直接 import；
- **Web Worker**：库的 loader 在 Worker 上下文里也能正常 `import`；
- **Cloudflare Workers / Edge runtime**：**不在本期范围**，留给未来 PR。

---

## 8. 性能取向

- SM2 / SM9 椭圆曲线：**Jacobian 坐标** + **wNAF 窗口点乘**（窗口大小 5–7，依算法选择）；
- SM9 双线性对：走 **R-ate pairing** 的工程优化（多项式约化、预计算表）；
- SM4：AES-NI 不适用（SM4 ≠ AES），走 **32-bit T-table 化实现**；GCM 模式走纯 AS 的 CTR + Karatsuba GHASH（详见 §12.2 Q4）；
- ZUC：LFSR 直接模拟，bit-slicing 不上（小体积更划算）；
- 桥接层：输入优先接 `Uint8Array`，避免 `.slice()`；hex/base64 解析走 Web Crypto / Node `Buffer`；
- 子包懒加载：业务首次调用某个算法时再下载对应 `*.wasm`。

---

## 9. 安全姿态

- 不实现、不维护任何 RNG：所有随机数（SM2 加密用的 k、SM9 签名用的 r）从 `crypto.getRandomValues`（浏览器）/ `crypto.randomBytes`（Node）取；
- 私钥 / 中间状态不出内存，不写日志、不 stringify；
- Wycheproof 风格的攻击向量专门做成测试组（无效曲线、长度溢出、负值参数、奇异点等）；
- 不接收、解析、可信任何来源的公钥/私钥 PEM 之外的格式（不接 HSM、不接软证书）。

---

## 10. 测试与发布

- 测试：`vitest`，分 Node 与浏览器两套 runner；
- 标准向量：把 GM/T 0003-2014 / 0004-2014 / 0002-2014 / 0044-2016 / 0001-2012 公开测试向量落到 `tests/vectors/*.json`；
- fuzz：`fast-check`，针对每个算法的"应当拒绝"边界（坏 PEM、坏签名、空输入、超长输入）；
- CI：`.github/workflows/ci.yml`（push/PR 跑测试）；`.github/workflows/release.yml`（tag 触发 `pnpm publish`）；
- CHANGELOG：自动由 `release-it` 生成。

---

## 11. 留给 builder 的小决策（我会自己做主）

- 具体 lint/格式化工具选 `biome`（快、零配置）；
- 测试文件名遵循 `*.spec.ts`（vitest 约定）；
- 文档站点暂不建，README + JSDoc 够；
- 子入口默认导出"动词函数"而不是 `sm2` 对象（保持体积敏感场景的 tree-shake 友好）；
- README 配四档速查：SM3 hash、SM4 对称加解密、SM2 加密签名、SM2 密钥交换协议；
- `package.json` 的 `exports` 字段按 Node 18 ESM 解析约定完整写法（`.`、`./sm2`、`./sm3`、`./sm4`、`./sm9`、`./zuc`、`./package.json`）。
- **代码注释约定**：所有 `.ts` / `.as` 文件的注释**以中文为主，英文为辅**（锁定 2026-10-13）：
  - 文件顶部：中文说明文件用途、与 spec/plan 的对应关系、输入输出约束；
  - 函数 JSDoc：`@param` / `@returns` 用英文（IDE 友好），描述体用中文；
  - 行内注释：算法步骤、GM/T 引用、不变量用中文；明显的关键字（如 `TODO`、`FIXME`、`HACK`）和 RFC/GMT 编号用英文；
  - 测试用例 `it(...)` 描述用中文，便于国内团队读测试。

---

## 12. 开放问题清单

下面这些影响实现细节、不影响产品范围。

### 12.1 已确认（2026-10-13 锁定）

- **(Q1) SM2 默认密文顺序 → `C1C3C2`**
  - `sm2.encrypt` 默认按 `C1C3C2` 组装输出；
  - 如对接方需要 `C1C2C3`，加 `{ outputFormat: 'C1C2C3' }` 选项即可；解密端按输入自动识别。

- **(Q2) API 同步/异步策略 → "同步为主 + 必要的异步"**
  - 同步方法全部暴露：`sm2.encrypt / decrypt / sign / verify`、所有 SM3/SM4/ZUC 业务函数；
  - `async` 仅出现在：
    - `sm2.generateKeyPair()`（含 wasm 实例化 + 宿主 RNG）；
    - `sm9.generateKeyPair()`（同上 + 必要时的主私钥派生）；
    - `sm2.keyExchange.*` 协议流（本来就是两轮对话）。
  - 每个异步入口同时提供 `*Sync` 名字的"先 init 后调用"拆解版本：例如 `sm2.loadPrivateKeySync(pem)` 同步、`sm2.encryptWith(loadedKey, msg)` 同步。

- **(Q3) SM9 主私钥编码 → `PKCS#8 + 自定义 OID`**
  - SM9 算法 OID：`1.2.156.10197.1.100`（已校对：301=SM3、302=SM2、SM9 是 100）。
  - 主私钥：`PKCS#8 PrivateKeyInfo`，算法字段 OID `1.2.156.10197.1.100`；
  - 主公钥：`SPKI SubjectPublicKeyInfo`，算法字段 OID 同上；
  - 用户私钥：`PKCS#8`，算法字段 OID 同上；
  - 用户公钥：`SPKI`，算法字段 OID 同上；
  - 不接国密机自定义格式，未来若有需求通过 `KeyProvider` 接口扩展。

### 12.2 留给下一轮 plan / 实现的小决策（无需你拍板，builder 自决）

- **(Q6) Node 原生回退策略 → "浏览器优先 + Node 自动回退原生"（2026-10-13 用户确认）**
  - 事实基线（Node v26 / OpenSSL 3.x 实测）：Node 原生支持 `sm3`（hash）、
    `sm4-ecb/cbc/ctr/cfb/ofb`（cipher）、`SM2`（namedCurve）；**不支持 ZUC、SM9**。
  - 决策：每个算法模块内部检测运行环境。
    - **Node**：SM2 / SM3 / SM4 走 `node:crypto` 原生（更快、经 OpenSSL 审计）；
      ZUC / SM9 仍走 WASM。
    - **浏览器**：SM2 / SM3 / SM4 / SM9 / ZUC 全部走 WASM。
  - **因此 5 个算法的 WASM 实现一个都不能省**——浏览器是主战场。
  - 对外 API 完全一致，调用方无需感知底层路径。

- **(Q4) SM4-GCM 实现策略 → "纯 AS，性能优先"**
  - **更正**：SM4 不是 AES，主机没有 SM4-NI 指令集，"借宿主 AES-NI"这条路不存在。
  - 走法：纯 AS 实现 SM4-CTR + GHASH，全部在 WASM 内完成；GHASH 用 Karatsuba 乘法 + ClMul-H 风格优化（按 64-bit limb 切分）。
  - 备选：若未来发现性能仍不达标，可临时退到"SM4-CTR + HMAC-SM3"的加密+完整性组合，**不影响 API 形态**。

---

## 13. 完成定义（Definition of Done）

勾选状态以 §14 的对账为准（2026-10-14）。

- [x] `pnpm install` 一键装齐依赖；
- [x] `pnpm build` 产出 `dist/`（实际走 `asc` + `tsc`，未引入 rollup/CJS 双产物）；
- [x] `pnpm test` 在 Node 与浏览器两套 runner 全绿（Node 182/182，浏览器 6/6）；
- [x] `pnpm bench` 跑通，给出 micro-bench 报告（mitata，5 大块算法）；
- [x] README 含 5 大块算法的 5 分钟速查（每个示例都经实跑验证）；
- [x] GitHub Actions `ci.yml` + `release.yml` 已创建（本地已模拟全链通过）；
- [x] `pnpm pack --dry-run` 报出正确字段（name、version、license、engines、exports、types）。

---

## 14. 实现状态对账（2026-10-14）

本节由一次 spec/plan ↔ 代码的对账产生，是第 13 节勾选状态的依据。

### 已完成

- 五大算法的 WASM 核心各一份 `.wasm` + TS 胶水：SM2（曲线/签名/加密/密钥交换）、
  SM3、SM4（六种模式含 GCM）、SM9（pairing / KEM / 密钥交换）、ZUC（EEA3 + EIA3）；
- `runtime`（`loadWasm` 记忆化、hex/base64/PEM 嗅探、宿主 CSPRNG）与
  `pem`（ASN.1 + PKCS#8/SPKI + SM2/SM9 算法 OID）；
- 标准向量与交叉验证：GM/T 0001.3-2012（EIA3 三组）、GM/T 0003-2014 密钥交换
  官方向量，以及 gmkitx / OpenSSL / GmSSL 的对拍；
- `sm9` 已从 facade 导出；`sm2.generateKeyPair`（PEM 密钥对）与
  `sm9.generateKeyPair`（PKCS#8/SPKI + OID `1.2.156.10197.1.100`）可用；
- SM2 密文 C1C3C2（默认）/ C1C2C3（可选，解密端自动识别）；
- ZUC EIA3 完整性算法 + `(key, iv, counter)` 复用保护；
- SM4 / ZUC 的"文档名"别名（见 §3 表）。

### 未完成

**P1 — 工程化与发布（§2 Goals、§10、§13）**

已在 2026-10-14 全部处理（见「P1 批次」），仅两条有意留下：

- 打包仍为纯 `tsc` ESM：无 CJS 产物、`exports` 无 `require`、无 `rollup.config.mjs` ——
  实际分发形态是 ESM-only，`package.json` 与 README 均按现状描述；
- `tests/packaging/smoke.spec.ts` 未单独建（facade 与浏览器 smoke 已覆盖同一批 API）。

### P1 批次（2026-10-14 补齐）

- **biome**：新增 `biome.json`（lint + format 双开），并修净仓库内 100+ 处既有违规；
- **bench**：`bench/` 落地 5 大块算法的 mitata 微型基准，`pnpm bench` 可跑；
- **浏览器 runner**：新增 `vitest.browser.config.ts`（happy-dom）+ `tests/browser/smoke.spec.ts`；
- **runtime 单测**：`tests/runtime/{loadWasm,convert,random}.spec.ts`；
- **fuzz**：`tests/fuzz/wycheproof-style.spec.ts`（SM2 坏点、SM4 tag 翻转、SM3 跨 oracle 对拍）；
- **CI / 发布**：`.github/workflows/{ci,release}.yml` + `.release-it.json`；
- **README**：5 大块算法速查 + API 一览 + 错误层级 + 安全说明，示例经实跑验证。

### 顺带修掉的阻塞（2026-10-14）

- **`pnpm build` 原本跑不通**：biome 的 `useImportType` 规则把 `src/**/assembly/**` 的
  `import { U256 }` 改成了 `import { type U256 }`，而 `asc` 0.28 不认类型修饰符 ——
  发布链路（`prepack = build && test`）因此完全断掉。已对该目录关闭 `useImportType`
  与 `organizeImports`，并恢复 23 处 import 形态（commit `c509319`）。
  教训：**格式化器不得介入 AssemblyScript 源的类型与导入语义**。

### 本批次新发现、留作后续的小项

- `sm9.kemEncrypt` / `kemDecrypt` 的第一参数只接受**加密主私钥**，而 `sm9.encrypt`
  同时接受主公钥（按长度判别）。二者不一致，建议下一轮把 KEM 也放宽到主公钥形态。
- `.gitignore` 里列了 `pnpm-lock.yaml` / `pnpm-workspace.yaml`，但两者其实都被 git
  跟踪 —— 配置与事实矛盾（CI 因此仍可用 `--frozen-lockfile`）。

### 许可统一（2026-10-14）

此前三处声明互不一致、且其中一对存在法律冲突：

| 位置 | 原值 |
|---|---|
| `LICENSE` 文件 | **GPL-2.0** 全文（339 行） |
| `package.json` / `README.md` | **MIT** |
| `src/zuc/assembly/index.ts` | "逐行移植自 gmkitx（Apache-2.0）… 见仓库 LICENSE 与 NOTICE" |

GPL-2.0 与 Apache-2.0 **不兼容**（专利条款冲突），因此"LICENSE=GPL-2.0"与"代码逐行移植自
Apache-2.0 的 gmkit"不可能同时成立；`NOTICE` 文件也不存在。

已统一为 **Apache-2.0**：

- `LICENSE`：替换为标准 Apache-2.0 全文；
- `package.json`：`"license": "Apache-2.0"`，`files` 增加 `NOTICE`；
- `README.md`：License 段改为 Apache-2.0 并列出上游归属；
- 新增 `NOTICE`：按 Apache-2.0 §4(d) 声明对 GmSSL 与 gmkit / gmkitx 的归属。

**P2 — 已实现但与本文档不符**

其中三条已在 2026-10-14 修复（见下面的「P2 批次」）：

- ~~`sm2.decrypt` 与 SM4-GCM 校验失败抛 `Error`~~ → 现在抛 `DecryptionError`；
- ~~`InvalidPublicKeyError` 不存在~~ → 已新增：`encrypt` 对坏公钥抛它、`verify` 返回 false；
- ~~空输入策略不一致~~ → 更准确的描述是：`toBytes('')` 本来就抛 `TypeError`，而
  `hash(new Uint8Array(0))` 能算出摘要；现在统一为**摘要类接受空输入**（SM3 的定义域
  含空比特串），密钥 / IV / 密文类仍抛错。

仍与 plan 有出入（保留为记录，不影响功能）：

- 文件结构与 plan 有出入（plan 的 `pem/spki.ts`、`sm2/pem.ts`、`sm4/modes.ts`、
  `sm9/pairing.ts` 等不存在，功能合并到别处）；
- 向量文件清单与 plan Task 5 不一致（实际以 oracle 交叉验证为主 + 按需落盘）。

### P2 批次（2026-10-14 修复）

- **`DecryptionError`**：`sm2.decrypt`（C3 校验）、`sm4.decryptGCM`（认证标签）、
  `sm9.decrypt`（C3 HMAC）统一抛出；长度 / 结构类错误按 `errors.ts` 的既有约定
  保留 `RangeError`（不包装为 `SmCryptoError`）。
- **`InvalidPublicKeyError`**（继承 `InvalidKeyError`，facade 已导出）：`sm2.encrypt`
  对不在曲线上的公钥（含坐标 ≥ p）抛错，`sm2.verify` 返回 `false` 而不抛。
- **SM3 空输入**：`hash('')` == `hash(new Uint8Array(0))` ==
  `1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b`；
  `hmac` 同时接受空 key 与空消息。
- 配套测试：新增 `tests/errors.spec.ts`（错误类型契约），并在 `tests/sm2.spec.ts`、
  `tests/sm3-oracle.spec.ts` 增加对应用例。

**原「留作后续的缺口」—— 已于同日晚些时候实现**

- ~~`sm9.verify` / `sm9.encrypt` 不接受主公钥 PEM~~ → wasm 新增 `sm9VerifyPubOut` /
  `sm9EncryptPubOut`，TS 层按长度判别主私钥（32B）与主公钥（64 / 128B）；
- ~~`generateKeyPair` 不产出 `userPublicPem`~~ → 已产出（签名 G2 128B / 加密 G1 64B），
  并提供 `getUserPublicKey(masterPublicKey, id)` 供第三方复算。

### 扩展性批次（2026-10-14）

P2 之后又做了一轮"消除未来 breaking 的扩展点"改造，逐条 ruling 见 ledger：

- **错误体系统一**：新增 `CiphertextError` 基类 —— 密文 / 签名 / 协议消息类错误归密文支
  （`InvalidCiphertextError` / `DecryptionError`），密钥 / 标量类归密钥支
  （`InvalidKeyError` / `InvalidPublicKeyError`）；只有类型与数值参数错保留宿主原生
  `TypeError` / `RangeError`。（上面「P2 批次」里"长度 / 结构类错误保留 `RangeError`"
  那条已随之更新。）
- **ZUC**：`zucMac` 第 4 参支持 options 对象（给 ZUC-256 留位）；复用保护可配
  （`configureReuseGuard` / `zucEncrypt(..., { reuseGuard })`）；新增 `zucEia3Iv()`。
- **SM9**：PEM 解析从通用 `toBytes` 移出、只在密钥参数上生效；`verify` / `encrypt`
  接受主公钥；`generateKeyPair` 产出 `userPublicPem`；新增 `getUserPublicKey()`。
- **safeMode**：`sm2.decrypt` / `sm9.decrypt` / `sm4.decryptGCM` 支持失败返回 `null`
  （plan Review Focus #4）；用重载保证既有调用点的返回类型仍是 `string`。

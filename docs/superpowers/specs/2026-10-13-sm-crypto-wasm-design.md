# sm-crypto-wasm 设计稿

- 日期：2026-10-13
- 仓库：`/Users/bytonsec/works/github/sm-crypto-wasm`
- 包名：`sm-crypto-wasm`
- 版本起步：`0.1.0`
- 目标 Node：`>=18`
- License：`MIT`

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
- WebAssembly SIMD 优化（AssemblyScript 当前 SIMD 支持有限）。

### Anti-Goals（一旦发现正在做，立刻停）

- 暴露大数 / 曲线点 / 模运算等底层接口给业务开发者（属于上一级抽象，开发者只能进 crypto.subtle 这种）；
- 内置 `随机数生成器` —— 永远用宿主 `crypto.getRandomValues` / `crypto.randomBytes`，不另起 RNG；
- 把任何私钥 / 中间状态序列化到磁盘 / 日志。

---

## 3. 范围算法清单

| 算法 | 规格 | 设计 API | 实际导出（2026-10-14 对账） |
|---|---|---|---|
| SM2 | GM/T 0003-2014（含密钥交换协议、加密、签名） | `sm2.encrypt / decrypt / sign / verify / keyExchange / generateKeyPair` | `generateKeyPair`（async，PEM 密钥对）、`encrypt`（`{ outputFormat: 'C1C3C2' \| 'C1C2C3' }`，默认 C1C3C2）、`decrypt`（自动识别两种顺序）、`sign / verify / getPublicKey`、`createExchangeInitiator / createExchangeResponder` |
| SM3 | GM/T 0004-2014 | `sm3.hash / sm3.hmac` | 同设计（另有 `ensureLoaded()` 预热） |
| SM4 | GM/T 0002-2014 | ECB / CBC / CTR / CFB / OFB / GCM | `encryptECB/decryptECB`、`encryptCBC/decryptCBC`、`encryptCFB/decryptCFB`、`encryptGCM/decryptGCM`、`cryptCTR`（别名 `encryptCTR` / `decryptCTR`）、`cryptOFB`（别名 `encryptOFB` / `decryptOFB`） |
| SM9 | GM/T 0044-2016（含签名、密钥封装、密钥交换） | `sm9.sign / verify / encrypt / decrypt / generateKeyPair` | `generateKeyPair`（async，PKCS#8/SPKI PEM）、`sign / verify / encrypt / decrypt`（主私钥可传 hex 或 PEM）、`kemEncrypt / kemDecrypt`、`getSignPublicKey / getEncPublicKey`、`createExchangeInitiator / createExchangeResponder` |
| ZUC | GM/T 0001-2012 + GM/T 0001.1-2012 128 比特 | `zuc.encrypt (EEA3) / zuc.mac (EIA3) / zuc.generateKeystream` | `zucKeystream`（别名 `generateKeystream`）、`zucEncrypt`（别名 `encrypt`，带 (key,iv,counter) 复用保护）、`zucDecrypt`、`zucMac`（别名 `mac` / `eia3`） |

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
├── package.json                  # version 0.1.0, engines ">=18", license MIT
├── README.md
├── LICENSE                       # MIT
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
- [x] `pnpm build` 产出 `dist/`，体积符合第 5 节（实际走 `asc` + `tsc`，未用 rollup）；
- [ ] `pnpm test` 在 Node 与浏览器两套 runner 全绿（**Node 端已全绿；浏览器 runner 不存在**）；
- [ ] `pnpm bench` 跑通，给出 micro-bench 报告（**`bench/` 不存在**）；
- [ ] README 含 5 大块算法的 5 分钟速查（**README 目前只有标题**）；
- [ ] GitHub Actions `ci.yml` + `release.yml` 都通过（**两个 workflow 均未创建**）；
- [ ] `npm publish --dry-run` 报出正确字段（name、version、license、engines、exports、types）。

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

- `bench/` 不存在，而 `package.json` 的 `bench` script 已指向 `bench/run.ts` → 命令直接失败；
- `vitest.browser.config.ts` 不存在 → `pnpm test:browser` 失败，浏览器 runner 缺位；
- `.github/workflows/ci.yml`、`.github/workflows/release.yml`、`.release-it.json` 全缺；
- fuzz 用例（`tests/fuzz/` + fast-check）零引用 —— Wycheproof 风格攻击向量未做；
- `biome.json` 缺失：`pnpm lint` 没有配置，且其目标包含不存在的 `bench/`；
- README 仅标题两行，四档速查未写；
- 打包仍为纯 `tsc` ESM：无 CJS 产物、`exports` 无 `require`、无 `rollup.config.mjs`；
- `tests/runtime/{loadWasm,convert,random}.spec.ts` 与 `tests/packaging/smoke.spec.ts` 缺失。

**P2 — 已实现但与本文档不符**

- `sm2.decrypt` 与 SM4-GCM 校验失败抛 `Error`，而不是 `errors.ts` 已定义的
  `DecryptionError` / `InvalidCiphertextError`；
- `InvalidPublicKeyError` 不存在（plan Review Focus #3 要求 encrypt 对不在曲线上的公钥抛它）；
- 空输入策略不一致：`sm3.hash('')` 会算出合法摘要，而 plan Review Focus #1 要求空输入抛 `TypeError`；
- 文件结构与 plan 有出入（plan 的 `pem/spki.ts`、`sm2/pem.ts`、`sm4/modes.ts`、
  `sm9/pairing.ts` 等不存在，功能合并到别处）；
- 向量文件清单与 plan Task 5 不一致（实际以 oracle 交叉验证为主）。

**本轮明确留作后续的缺口（2026-10-14）**

- `sm9.verify` / `sm9.encrypt` 尚不接受**主公钥** PEM：wasm 的 `sm9VerifyOut` /
  `sm9EncryptOut` 内部自行从主私钥派生主公钥，要支持点字节输入需新增 2 个 AS 导出
  并重编 `sm9.wasm`；
- `sm9.generateKeyPair` 不产出 `userPublicPem`：SM9 的用户公钥是 `(id, 主公钥)` 的
  确定函数，不是独立持有物。

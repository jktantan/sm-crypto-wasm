# SM2 / SM9 密钥封装与混合加密 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: 用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务执行。步骤用复选框（`- [x]`）跟踪。
>
> **状态：已定稿并实现（2026-10-17）。** 4 个 🔶 决策已由用户拍板并全部采用推荐项；实现记录与实测数字见文末。

**Goal:** 给 `sm2` / `sm9` 补上"公钥只保护短密钥、数据交给对称算法"的标准用法：SM2 新增 KEM，两个算法各加一对开箱的混合加密（hybrid / KEM+DEM）接口，使大消息加解密不再受公钥运算的数量级拖累。

**由来:** 2026-10-16 排查 JS↔WASM 内存缺陷时确认：SM2/SM9 直接加密大消息在算法上代价高（实测 SM2 1MB 29 MB/s、SM9 10KB 2 MB/s，而 SM4 约 170 MB/s），且整体把消息塞进 WASM 会推高常驻内存水位。正确解法是混合加密，而不是继续优化公钥加密长数据。

**Spec:** 无独立 spec；本计划自带设计。相关既有 spec：`docs/superpowers/specs/2026-10-13-sm-crypto-wasm-design.md`。

---

## 现状盘点（开工前核对）

| 能力 | SM2 | SM9 |
|---|---|---|
| 公钥加密数据本身 | ✅ `encrypt` / `decrypt` | ✅ `encrypt` / `decrypt` |
| **KEM（封装对称密钥）** | ❌ **缺** | ✅ `kemEncrypt` / `kemDecrypt`（GM/T 0044.4，已有） |
| **混合加密（KEM+DEM 一体化）** | ❌ 缺 | ❌ 缺 |
| 密钥交换 | ✅ `createExchangeInitiator` / `Responder` | ✅ 同上 |

**所以本计划不是"给两个算法加 KEM"** —— SM9 的 KEM 已经落地并有文档与 KAT（`tests/vectors/sm9/kem-exch-gmssl.json`）。真正要做的是：

1. SM2 的 KEM（新增，SM9 已有的对位能力）；
2. SM2 / SM9 各一对**混合加密**开箱接口（把「KEM + SM4-GCM」组装成一次调用，含序列化格式）。

---

## Global Constraints

沿用主 plan（`2026-10-13-sm-crypto-wasm.md`）的约束，另加：

- **同步优先**：`kemEncrypt`/`hybridEncrypt` 等都是同步函数（`.wasm` 由 `ensureLoaded()` 预热），与 `sm2.encrypt` / `sm9.encrypt` 一致。
- **随机数一律走宿主 CSPRNG**（`src/runtime/random.ts`），绝不内部实例化 RNG。
- **SM2 密文顺序默认 C1C3C2**；解密自动识别两种顺序（沿用现有约定）。
- **DEM 一律用 AEAD**（SM4-GCM），不用 CTR —— hybrid 的密文必须自带完整性。
- Conventional Commits；biome 格式化；新增公开 API 必须同时有三语 README 段落 + 测试。

---

## 密码学正确性红线（实现时必须满足，Review 时逐条核对）

| # | 红线 | 为什么 |
|---|---|---|
| 1 | **每次 `hybridEncrypt` 新生成 DEK 与 IV**，绝不跨调用复用 | DEK/IV 复用 = 密钥流复用 = 机密性直接失效 |
| 2 | DEK 来自宿主 CSPRNG（SM2）或 KEM 的 KDF 输出（SM9）；hybrid 的 DEM 密钥固定 16 字节（SM4-128） | 弱随机 = KEM 整体失效 |
| 3 | SM2 解封装必须校验 C3；SM9 KEM 的封装只有 C1，由 DEM 的 GCM tag 隐式认证（错误 id / 主公钥表现为 GCM 失败） | 否则 hybrid 退化成"无认证 KEM"，有 oracle 类攻击面 |
| 4 | AEAD 的 **AAD 必须绑定 encapsulation**（或等效的密钥/身份上下文） | 防"按键替换"/跨上下文重放 |
| 5 | DEK 复用给多个消息时，**每个消息必须换 IV** | 同 DEK 同 IV 在 GCM 下是灾难 |
| 6 | 序列化格式必须**版本化**（首字节含版本号） | 避免日后无法演进格式 |

---

## API 设计（已定稿）

### SM2

```ts
// KEM
const { key, encapsulation } = sm2.kemEncrypt(publicKey, 32);
const key2 = sm2.kemDecrypt(privateKey, encapsulation, 32);   // === key

// 混合加密（一次调用完成 KEM + SM4-GCM）
const sealed = sm2.hybridEncrypt(publicKey, message, { klen: 32 });
const plain  = sm2.hybridDecrypt(privateKey, sealed);          // → message hex
```

### SM9

```ts
// KEM 已存在（kemEncrypt / kemDecrypt），本计划只加混合加密
const sealed = sm9.hybridEncrypt(masterPublicKey, id, message, { klen: 32 });
const plain  = sm9.hybridDecrypt(masterPrivateKey, id, sealed);
```

### 待决问题（已裁决）

1. **`sealed` 的形态**：采用 (a) 单一 hex 字符串（版本化 TLV）；同时提供
   `sealedToObject()` / `sealedFromObject()` 作为自描述辅助形态。
2. **命名**：`hybridEncrypt` / `hybridDecrypt`。
3. **参数默认值**：hybrid 的 DEM 密钥固定 **16 字节**（SM4-128），IV 12 字节，
   tag 16 字节。KEM 接口自身的 `klen` 默认值仍为 32（SM9 既有行为不变）。
   > 草案原文的 `klen = 32` 与 `sm4.encryptGCM` 只接受 16 字节密钥冲突，已修正。
4. **SM9 一体化接口**：加；`hybridEncrypt` 第一参数同时接受加密主公钥与加密主私钥，
   与 `sm9.encrypt` 一致。发送方只需主公钥；`kemEncrypt` 已发布签名不变。

---

## File Structure (created/modified)

| 文件 | 动作 |
|---|---|
| `src/sm2/kem.ts` | **新增** —— `kemEncrypt` / `kemDecrypt` |
| `src/common/sealed.ts` | **新增** —— 版本化 sealed 编解码 + 对象互转 |
| `src/common/hybrid.ts` | **新增** —— 统一 message / IV 输入语义 |
| `src/sm2/hybrid.ts` | **新增** —— `hybridEncrypt` / `hybridDecrypt` |
| `src/sm2/index.ts` | 导出 KEM / hybrid |
| `src/sm9/core.ts` | **新增** —— WASM 模块访问层（拆出以避免循环依赖） |
| `src/sm9/input.ts` | **新增** —— 输入归一化与密钥参数校验 |
| `src/sm9/kem.ts` | **新增** —— KEM 实现 + 主公钥封装入口 |
| `src/sm9/hybrid.ts` | **新增** —— `hybridEncrypt` / `hybridDecrypt` |
| `src/sm9/assembly/index.ts` | 新增 `sm9KemEncryptPubOut` WASM 导出 |
| `src/sm9/index.ts` | 导出 KEM / hybrid，内部 helper 改为从 core/input 导入 |
| `tests/sm2-kem.spec.ts` | **新增** |
| `tests/sm2-hybrid.spec.ts` | **新增** |
| `tests/sm9-hybrid.spec.ts` | **新增** |
| `bench/sm2.bench.ts` / `bench/sm9.bench.ts` | 增 KEM / hybrid 项 |
| `README.md`（三语） | 增 hybrid 段落 + API 表补名 |
| `docs/performance-ceiling.md` | 增实测数字 |

---

## Task 1: SM2 KEM（封装 / 解封装）

- [x] `src/sm2/kem.ts`：`kemEncrypt(publicKey, klen = 32)` → `{ key: string; encapsulation: string }`
  - 内部：`randomBytes(klen)` → `encapsulation = sm2.encrypt(publicKey, dek)`；`key = dek` 的 hex。
  - 复用现有 `encrypt`（它每次内部重新取 `k`，无需额外处理）。
- [x] `kemDecrypt(privateKey, encapsulation, klen = 32)` → `key` hex
  - 内部：`sm2.decrypt(privateKey, encapsulation)`；长度不符 / C3 校验失败自然抛 `DecryptionError`。
- [x] `src/sm2/index.ts` 导出。
- [x] 测试 `tests/sm2-kem.spec.ts`：
  - round-trip：`kemDecrypt(kemEncrypt(pub)) === key`；
  - 篡改 encapsulation 抛 `DecryptionError`；错误私钥抛错；`safeMode` 语义与 `decrypt` 对齐；
  - 两次 `kemEncrypt` 产出不同 `key` 与 `encapsulation`（验证随机性）；
  - `klen` 非正 / 非整数抛 `RangeError`。
- [x] 验证：`vitest run tests/sm2-kem.spec.ts` 通过。

**注意**：SM2 无标准 KEM（GM/T 0003 未定义 "SM2-KEM"），本实现是"用 SM2 公钥加密一个随机对称密钥"的约定俗成做法，接口文档必须写清这一点，避免被误当成标准构造。

## Task 2: sealed 序列化 + AAD 约定

- [x] 定稿 🔶 问题 1/2 后的编码：建议 `version(1) || klen(1) || encapsulationLen(2, BE) || encapsulation || iv(12) || tag(16) || ct`，整体转 hex 字符串返回。
- [x] 提供 `sealedToObject()` / `sealedFromObject()`（供需要自描述形态的调用方）。
- [x] AAD 约定：`aad = encapsulation`（满足红线 #4）。
- [x] 单元测试：畸形 sealed（截断、版本未知、长度字段与实长不符）**必须抛错**，不得静默当成某种默认。
- [x] 验证：`vitest run tests/sm2-hybrid.spec.ts`（含畸形输入用例）。

## Task 3: SM2 混合加密

- [x] `src/sm2/hybrid.ts`：
  ```ts
  hybridEncrypt(publicKey, message, opts?: { klen?: number; iv?: Uint8Array })
    → sealed: string
  hybridDecrypt(privateKey, sealed, opts?: { safeMode?: boolean }) → string  // 明文 hex
  ```
  - 流程：`kemEncrypt` → `sm4.encryptGCM(dek, iv, message, aad = encapsulation)` → 组装 sealed。
  - `iv` 不传则由宿主 CSPRNG 生成 12 字节（红线 #1）。
- [x] 测试：
  - round-trip（含空消息、1 字节、10 KB、2 MB）；
  - 篡改 `ct` / `tag` / `encapsulation` 任一段 → 抛错；
  - **错误私钥 → 抛错**（不是返回垃圾）；
  - 同一个 `(pub, message)` 两次加密产出不同 sealed（DEK + IV 双随机）；
  - 显式传同一个 `iv` 两次 → 文档说明风险（是否拒绝由 🔶 决策，默认**不拒绝但文档警告**，与 `zuc` 的复用保护策略区分开）。
- [x] 验证：`vitest run tests/sm2-hybrid.spec.ts` 通过。
- [x] 交叉验证：与"`kemEncrypt` + `sm4.encryptGCM` 手工组装"的结果可互相解开（证明封装是纯组装，无隐藏状态）。

## Task 4: SM9 混合加密

- [x] `src/sm9/hybrid.ts`：同 Task 3，但 KEM 走**已有**的 `sm9.kemEncrypt` / `kemDecrypt`。
- [x] 测试 `tests/sm9-hybrid.spec.ts`：同 Task 3 的用例集；另加"不同 `id` 解不开"。
- [x] 验证：`vitest run tests/sm9-hybrid.spec.ts` 通过。

## Task 5: bench + 文档 + 导出

- [x] `bench/run.ts` 增：`SM2 hybrid 1MB` / `SM9 hybrid 10KB`，与现有的 `SM2 encrypt 1MB` / `SM9 encrypt 10KB` 并列，量化收益（预期 hybrid ≈ SM4 速度 + 一次公钥运算）。
- [x] README 三语（中文 / English / Русский）各增一段 hybrid 用法 + API 表补 `kemEncrypt`（SM2）/ `hybridEncrypt` / `hybridDecrypt`。
- [x] 跑通全量：`pnpm test`（含 browser 配置）绿；`biome check` / `tsc --noEmit` 干净。
- [x] 记录实测数字到 `docs/performance-ceiling.md`（新增一节或附录）。

---

## Review Focus（新增的输入类别）

| # | 输入 / 失败模式 | 期望行为 |
|---|---|---|
| H1 | `sealed` 被截断 / 版本号未知 / 长度字段说谎 | 抛 `CiphertextError` 支的错误，**不**静默降级 |
| H2 | 用错误私钥解 hybrid | 抛错（KEM 的 C3 校验挡住），不返回垃圾明文 |
| H3 | 同一 `(pub, msg)` 连续加密 | 每次 sealed 都不同（DEK 与 IV 皆随机） |
| H4 | 显式复用同一 IV 配不同消息 | 文档明确警告；不复用保护（与 ZUC 的语义区分，见下方"取舍"） |
| H5 | 空消息 | 可加密 / 可解密，返回空明文 hex（`''` → 与 `toBytes` 的空输入契约对齐，需明确） |
| H6 | 超大消息（≥ 几十 MB） | 功能正确；文档提示"数据仍整段进出 WASM，常驻内存水位由最大消息决定" |

---

## 取舍与风险

- **不引入流式**：hybrid 解决的是"公钥运算不划算"，不是"内存水位"。若日后要 GB 级流式，另开计划（见下方 Non-Goals）。
- **IV 复用：警告而非拒绝**。ZUC 的复用保护是基于 `(key, iv, counter)` 的显式拒绝；hybrid 里 DEK 每次都是新随机，正常路径天然不会撞 IV，因此不做全局状态表（否则又引入一个需要清理的进程内状态）。显式传 `iv` 属于专家用法，用文档警告 + 测试固定行为。
- **格式版本化成本**：加 1 字节版本换来未来可演进，值。
- **新公开 API 是承诺**：三语文档 + 测试 + bench 三件套齐了才算完成，否则不留半成品接口。

## Non-Goals（本计划明确不做）

- **流式 / 分块 API**（`update/final`、CTX 对象）—— 需要时另开计划；hybrid 不依赖它。
- **SM2/SM9 的签名侧改动** —— 签名无此问题（消息只进哈希一次，见 `docs/performance-ceiling.md` 与实测）。
- **国标之外的 KEM 构造**（如基于 SM2 的 HPKE 风格变体）—— 只做约定俗成的"加密随机密钥"。
- **修改 `sm9.kemEncrypt` 现有签名 / 行为** —— 它是已发布且有 KAT 的接口，只在其上组装。

---

## 执行前检查

- [x] 🔶 四个待决问题有用户裁决。
- [x] 是否新建独立 spec（若设计分歧大）或直接以本计划为准。
- [x] 决定 `sealed` 是否复用 `src/common/`（若 SM2/SM9 两份编码逻辑重复度高）。

---

## 实现记录（2026-10-17）

已按定稿实现并验证：

- SM2 KEM：`src/sm2/kem.ts`，`kemEncrypt` / `kemDecrypt`，支持 `safeMode`。
- SM2 hybrid：`src/sm2/hybrid.ts`，KEM + SM4-GCM，sealed 版本化。
- SM9 hybrid：`src/sm9/hybrid.ts`，第一参数接受加密主公钥或主私钥。
- SM9 主公钥 KEM：`sm9KemEncryptPubOut`（`src/sm9/assembly/index.ts`）。
- 共享层：`src/common/sealed.ts`、`src/common/hybrid.ts`。
- 测试：`tests/sm2-kem.spec.ts`（7）、`tests/sm2-hybrid.spec.ts`（11）、
  `tests/sm9-hybrid.spec.ts`（10），连同既有 SM9 KEM 4 个用例共 32 个通过。
- 输入语义：message 统一按 hex / Uint8Array 解释；空消息传 `new Uint8Array(0)`。
- `sealed` 布局：`version(1) || klen(1) || encapLen(2) || encapsulation || iv(12) || tag(16) || ct`，
  AAD = encapsulation；当前版本 `klen = 16`。

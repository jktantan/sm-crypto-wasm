# AGENTS.md

> 本文件是 `sm-crypto-wasm` 仓库内所有 agent（以及人类贡献者）的默认工作约定。
> 用户即时指令与本文件冲突时，以用户指令为准；涉及公开 API、算法语义、安全取舍、
> 依赖或发布流程的变更，先说明方案并征得确认。

## Project

国密算法（SM2 / SM3 / SM4 / SM9 / ZUC）的 **TypeScript + AssemblyScript → WebAssembly** 实现。
ESM-only，Node.js >= 18，支持现代浏览器与 Web Worker；算法按子包懒加载。

- 聚合入口：`src/index.ts`
- 算法门面：`src/<algo>/index.ts`（`sm2` / `sm3` / `sm4` / `sm9` / `zuc`）
- AssemblyScript 源：`src/<algo>/assembly/`，共享域运算在 `src/common/assembly/`
- 支撑模块：`src/runtime/`、`src/asn1/`、`src/pem/`、`src/x509/`、`src/cms/`、`src/webcrypto/`
- 构建产物：`dist/`（**生成物，不提交、不手改**）
- 文档：根 `README.md`（中文主）、`docs/README.en.md`、`docs/README.ru.md`、`website/`（VitePress + Playground）

## Commands

| 目的 | 命令 | 说明 |
|---|---|---|
| 安装 | `pnpm install` | 运行时 Node >= 18；测试需 Node 20+（vitest 4） |
| 全量构建 | `pnpm build` | clean + 5 个 wasm + tsc |
| 只构建 wasm | `pnpm build:wasm:all` | 改 AssemblyScript 后必须执行 |
| 只编译 TS | `pnpm build:ts` | `tsc -p tsconfig.build.json` |
| 单测（快） | `pnpm test:unit` | 直接用已有 `dist/*.wasm`，**不重建** |
| 单测（含构建） | `pnpm test` | 先 `build:wasm:all`，再跑 `test:unit` |
| 浏览器测试 | `pnpm test:browser` | 先构建 wasm，再跑 happy-dom runner |
| Fuzz 测试 | `pnpm test:fuzz` | 先构建 wasm，再跑解析器 / ASN.1 / X.509 / CMS |
| Lint / 格式检查 | `pnpm lint` | Biome，覆盖 `src tests bench` |
| 自动格式化 | `pnpm format` | Biome 写回 |
| 类型检查 | `pnpm typecheck` | `tsc --noEmit` |
| 基准 | `pnpm bench` | mitata |
| 文档站 | `pnpm docs:dev` / `pnpm docs:build` | 脚本会先执行 `pnpm build` |
| 发布预检 | `pnpm prepack` | build + test:unit |
| 发布包检查 | `npm pack --dry-run --ignore-scripts` | 确认只含预期文件 |

**关键顺序**：修改 `src/**/assembly/**` 后，必须先 `pnpm build:wasm:all`（或 `pnpm build`），
再跑 `pnpm test:unit`；否则测试加载的是旧的 wasm，结果不可信。

## Architecture

- `src/runtime/loadWasm.ts`：Node 加载器；`loadWasm.browser.ts` 由 `package.json` 的
  `browser` 字段在打包时替换；共享逻辑在 `loadWasm.core.ts`。
- `src/runtime/convert.ts`：hex / base64 / bytes 输入嗅探与转换；输出默认 hex。
- `src/runtime/random.ts`：只调用宿主 CSPRNG，库内不实现 RNG。
- `src/runtime/errors.ts`：`SmCryptoError` 层级；密钥支 / 密文支的划分是公开 API 的一部分。
- 每个 `src/<algo>/`：TS 门面负责参数解析、编码、错误映射；`assembly/` 负责算法核心。
- `src/pem/`、`src/asn1/`、`src/x509/`、`src/cms/`：DER/PEM 编解码与证书/CMS 层。
- `src/webcrypto/`：`subtle` 风格子集，不是原生 `crypto.subtle` 的 polyfill。
- `tests/`：按模块分组；`tests/vectors/` 是公开测试向量（证书/密钥文件是测试资产，保留）。
- `website/`：面向用户的详细文档与 Playground；不要把它当作源码目录的重复副本。

## 注释规范（强制）

算法代码必须有注释，且**至少中英双语**。项目面向国内与国际读者，采用“中文注释块在前、
英文注释块在后”的结构：先写完整的中文段落，空一行后再写英文段落；**不要在同一行用
`/` 分隔中英文**（技术列表如 `CBC / CTR` 除外）。同一文件内保持一致。
注释解释“为什么、依据什么标准、有哪些不变量”，不要复述代码。

### 必须双语的场景

- 文件头：模块职责、数据流、标准依据、线程/内存/安全约束；
- 所有导出的公开 API（TS 门面、AssemblyScript 导出）；
- 算法步骤、轮函数、域运算、点运算、协议轮次；
- 常量表、S 盒、曲线参数、OID、测试向量来源；
- 内存布局、指针范围、字节序、编码格式；
- 安全相关分支（密钥校验、MAC/tag 比较、错误映射、`safeMode`）；
- 测试中引用的标准向量来源。

平凡 getter 或一目了然的赋值可以不写双语，但公共 API 与算法核心没有例外。

### TS 示例

```ts
/**
 * 从私钥派生公钥。
 *
 * 接受 32 字节裸私钥或 PKCS#8 / SEC1 PEM；返回未压缩点 hex。
 *
 * @param privateKey 私钥。
 * @returns 公钥。
 *
 * Derive the public key from a private key.
 *
 * Accepts a 32-byte raw private key or PKCS#8 / SEC1 PEM; returns an
 * uncompressed point as hex.
 *
 * @param privateKey The private key.
 * @returns The public key.
 */
export function getPublicKey(privateKey: KeyInput): string;
```

### AssemblyScript 示例

```ts
// SM4 S 盒，GB/T 32907-2016 §6.2 表 1。
// 用 memory.data 裸指针避免 StaticArray 的边界检查开销。
//
// SM4 S-box, GB/T 32907-2016 §6.2 table 1.
// Use a raw memory.data pointer to avoid StaticArray bounds-check overhead.
const SBOX: usize = memory.data<u8>([...]);
```

### 迁移策略

- 新增或修改的代码必须双语；
- 旧代码在触碰时补齐，不做一次性全量翻译（避免巨大 diff 与审查噪音）；
- 修改公共 API 时，至少同步：JSDoc 双语、根 README、`docs/README.en.md`、
  `docs/README.ru.md`（如涉及）、website 对应页面。

### 外部文档与模板

- `.github/ISSUE_TEMPLATE/*`、`.github/PULL_REQUEST_TEMPLATE.md`、`SECURITY.md`、
  `CONTRIBUTING.md` 面向外部贡献者，必须中英双语；
- 小节标题使用 `中文 / English`，字段名也保持双语；
- 两种语言都应能独立理解，不要把英文写成中文的逐字机器翻译；
- README 保持“中文主文档 + `docs/README.en.md` + `docs/README.ru.md`”的结构。

## 代码规范

### TypeScript

- ESM-only；相对导入带 `.js` 后缀（NodeNext）；类型导入用 `import type`。
- `tsconfig.json` 已开启 `strict` 与 `noUncheckedIndexedAccess`；不要用 `any`、
  `@ts-ignore`、无理由的非空断言。确需抑制时用 `@ts-expect-error` 并写原因。
- Biome 是格式与 lint 的唯一来源：2 空格、单引号、分号、尾逗号、100 列、LF。
  不手工格式化，不关闭规则；确需例外时在 `biome.json` 中按目录配置并说明原因。
- 命名沿用现有风格：函数/变量 `camelCase`，类型 `PascalCase`，模块级常量
  `UPPER_SNAKE_CASE`。
- 错误：库语义错误抛 `SmCryptoError` 子类；宿主误用（类型/长度越界）抛
  `TypeError` / `RangeError`。不要吞异常，不要改变 `safeMode` 的返回约定。
- 输入：hex / base64 / PEM / `Uint8Array` 由 `runtime/convert` 统一处理；
  必须校验长度与格式，不静默截断。字节序在注释中写明。
- 安全：不实现 RNG（只用 `runtime/random`）；密钥、明文、MAC 不写日志/错误消息；
  MAC/tag 比较使用常量时间实现，不用 `===`；尽量避免秘密相关的分支与查表。
- 公开 API：新增/改名/改签名时同步 `src/index.ts`、`package.json` 的 `exports`
  （含 `types` 与子路径）、README 和文档站。破坏性变更必须先征得同意。
- 依赖：不新增运行时依赖；新增 devDependency 需说明用途与替代方案。
- 不在库代码中使用 `console.*`；不要编辑 `dist/` 或 `.wasm`。

### AssemblyScript

- `asc` 0.28；只带 `--optimize`，不启用 SIMD；不要用 `import { type X }`，
  不要让格式化器重排 import。
- `src/**/assembly/**` 被根 `tsconfig.json` 排除；每个目录的 `tsconfig.json` 只继承
  `tsconfig.assembly.json` 供 IDE 使用。
- 内存：`alloc` / `freeAll` / `pinned` 模式；指针范围、长度、重叠规则必须注释；
  不要把固定小地址（如 0）当缓冲区；不要把 WASM 内存视图长期交给上层，
  取出字节时拷贝。
- 常量表必须注明标准号、章节或生成方式；查找表要说明性能理由。
- 新增/删除 wasm 导出时，同步 TS 侧 `WebAssembly.Exports` 接口、门面调用和测试。
- 改完必须重新构建 wasm；不要把 `.wasm` 提交进 git。

### 测试

- 测试按模块放在 `tests/<module>/`；使用 `@/` 别名，不写脆弱的深层相对路径。
- 新算法行为至少要有：官方向量 / 标准 KAT，或 OpenSSL / GmSSL / gmkitx 交叉验证；
  同时覆盖失败路径（`safeMode`、非法密钥、篡改密文）。
- 不删除、不弱化现有测试；不把断言改成永远为真。
- 不联网、不使用真实密钥/证书；临时文件用 `mkdtempSync` 并清理。
- 修改 AssemblyScript 后按上面的顺序先构建再测试；解析器改动加 fuzz 用例；
  加载器 / 浏览器分支改动跑 `test:browser`。

## 多 Agent 协作

### 角色

- **Planner**：拆任务、识别标准依据与风险、给出验证矩阵；不直接改代码。
- **Implementer**：按计划实现，保持改动聚焦；负责补测试与双语注释。
- **Reviewer**：独立审查正确性、API 兼容性、密钥/随机数/MAC 处理、WASM 内存边界、
  双语注释与测试；不直接改同一批文件。
- **Verifier**：运行验证命令，记录实际结果；不接受“应该能过”。
- **Docs**：维护 README / docs / website，确保公共 API 变更同步。

同一文件同一时间只由一个 agent 修改；需要并行时按文件/模块划分所有权。
安全敏感改动（密钥解析、签名/验签、解密、MAC/tag、随机数、内存布局）至少经过一次
独立 review，不能由实现者自审后直接合并。

### 工作顺序

1. 读 `AGENTS.md` → `CONTRIBUTING.md` → 相关 `docs/design/` 文档 → 源码与测试；
2. 复现或确认当前行为，检查是否有既有实现可复用；
3. 明确假设、改动范围、验证命令；不确定的标准/常量/向量先停下来问；
4. 实现 + 补测试 + 补双语注释；
5. 运行验证矩阵，报告实际执行的命令与结果；
6. 交接时列出改动文件、行为变化、未验证项与风险。

### 交接模板

```text
Task:
Files:
Behavior:
Verification:
Risks / open questions:
```

### Review 清单

- [ ] 算法与标准 / KAT 一致，边界条件覆盖；
- [ ] 公开 API 与 `exports` 兼容，文档已同步；
- [ ] 密钥、随机数、MAC/tag、`safeMode` 处理正确；
- [ ] WASM 指针、长度、字节序、内存增长后的视图安全；
- [ ] 新增/修改代码有中英双语注释，常量有标准来源；
- [ ] 测试可复现，未弱化既有断言；
- [ ] 没有提交生成物、临时文件或敏感信息。

## 验证矩阵

| 改动类型 | 至少运行 |
|---|---|
| 仅文档 / 注释 | `git diff --check`；改 website 时 `pnpm docs:build` |
| 纯 TypeScript（非算法） | `pnpm lint` + `pnpm typecheck` + `pnpm test:unit` |
| AssemblyScript / 算法核心 | `pnpm build:wasm:all` + `pnpm test:unit`；必要时 `pnpm test:fuzz` |
| 加载器 / 浏览器 / Worker | `pnpm test:unit` + `pnpm test:browser` |
| ASN.1 / PEM / X.509 / CMS | `pnpm test:unit` + `pnpm test:fuzz` |
| `package.json` / exports / files | `pnpm build` + `npm pack --dry-run --ignore-scripts` |
| 依赖变更 | `pnpm lint` + `pnpm typecheck` + `pnpm test:unit`，并检查 lockfile |
| 发布 | `pnpm prepack`；打 tag / publish 必须先获得用户确认 |

## Git 与提交

- 不提交：`dist/`、`node_modules/`、`website/.vitepress/dist/`、`.idea/`、`.reasonix/`、
  `.superpowers/`、`tmp-probe/`、`bench/.vendor/`、小程序 `vendor/`、
  `project.private.config.json`。`tests/vectors/` 下的测试向量应保留。
- 不提交 `.env` 或任何密钥材料；不要读取或回显用户的密钥文件。
- 保持改动聚焦：行为变更、重构、格式化、文档分开提交；不要顺手改无关文件。
- 提交信息沿用现有风格：`feat(scope): ...`、`fix(scope): ...`、`docs: ...`、
  `chore(ci): ...`。
- 未经明确同意，不 force-push、不重写历史、不执行 `npm publish` / `release-it`。

## Notes

- 工具特定文件（如 `CLAUDE.md`、`.github/copilot-instructions.md`）只做转发，
  不要复制规则；统一维护本文件。
- 本文件保持精炼，新增规则优先写“必须遵守的约束”，细节放在 `CONTRIBUTING.md`
  或 `docs/design/` 中并在此引用。

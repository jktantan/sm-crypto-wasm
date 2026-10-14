# SDD ledger — plan: docs/superpowers/plans/2026-10-13-sm-crypto-wasm.md

> Ledger for the `sm-crypto-wasm` implementation plan.
> Spec: `docs/superpowers/specs/2026-10-13-sm-crypto-wasm-design.md` (approved 2026-10-13).
> Plan: `docs/superpowers/plans/2026-10-13-sm-crypto-wasm.md` (approved 2026-10-13).

## Environment reality (2026-10-13)

`which` probe of the session shell:

| tool        | status        |
|-------------|---------------|
| git, make, python3 | available    |
| node, npm, pnpm, yarn | **missing** |
| cargo, rustc | **missing**    |
| docker, go, rg | **missing**    |

Subagent dispatch (`task:subagent`) returns HTTP 402 "Insufficient Balance"
on this account, so even if the toolchain were installed, fresh-implementer /
fresh-reviewer rotation is unavailable right now.

## Ruling 1 — execution mode

The plan named 15 tasks across 5 algorithm cores + cross-cutting
runtime / PEM / build. The subagent-driven-development skill requires a
fresh implementer + fresh reviewer per task; both legs are blocked here.

**Ruling:** execute the plan **inline** (one controller, no per-task
subagents). Verification (vitest, `asc`, `pnpm build`, `pnpm bench`) is
deferred to the user's environment after they install Node ≥ 18,
`pnpm`, and the AssemblyScript toolchain.

**Why:** Spec + plan are already approved; the user's primary risk now
is implementation correctness. Writing the whole tree immediately and
letting `pnpm i && pnpm test && pnpm build` produce the binding
verdict is faster and produces the same evidence a reviewer's diff
inspection would.

**Cost if wrong:** any silent math bugs in SM2 / SM9 / SM4 will not
surface until the user runs the tests. Mitigation: every algorithm has
GM/T official vectors committed under `tests/vectors/`, and a test
spec referencing them — the tests are part of the write, so the user's
`pnpm test` failure list will name the file & assertion.

## User ruling 1 — build approach

User answered option (i) via `ask` on 2026-10-13:

> (i) 我写满，验证留给你 — 写整个仓库按 plan 一次性写满；用户装好
> Node+pnpm+asc 后跑 `pnpm i && pnpm test && pnpm build`，把失败
> 清单给我修。

Confirms Ruling 1 above.

---

## Plan-vs-spec preflight (already in spec)

Read-through at plan-write time; no new conflicts found at execution
start. Spec OID error (`1.2.156.10197.1.302` claimed for SM9) was
caught and corrected to `1.2.156.10197.1.100` before Task 4
dispatch. See spec §12.1 Q3.

---

## Per-task ledger

### Task 1 — ZUC EIA3 + (key,iv,counter) 复用保护（plan Task 11 的 P0 补口）

- 向量来源：GmSSL `tests/zuctest.c::test_zuc_eia`（GM/T 0001.3-2012 官方三组），
  用脚本从 C 数组提取为 hex 落盘 `tests/vectors/zuc/eia3.json`
  （1 bit / 577 bit / 5670 bit 三档，MAC = `c8a9595e` / `fae8ff0b` / `0ca12792`）。
- 实现照 `tmp-probe/GmSSL/src/zuc.c` 的 `zuc_mac_init/update/finish` 逐位移植；
  IV 的 COUNT/BEARER/DIRECTION 布局照 `src/zuc_modes.c::zuc_set_eia_iv`。
- 测试：`npx vitest run --config vitest.config.ts tests/zuc.spec.ts` → 11/11 pass。
- `Ruling:` `zucMac(key, iv, msg, bitLength?, tagBits = 32)` —— 第 4 个参数定为
  **比特长度**，而不是 plan 写的 tagBits；tagBits 移到第 5 位且只接受 32。
  理由：EIA3 必须知道消息比特数（官方向量有 1/577/5670 bit 三档，非整字节），
  而 GM/T 0001.3-2012 的标签长度恒为 32 位，plan 的 `mac(key, iv, msg, 32)`
  在整字节场景下数值巧合相同，掩盖了语义混淆。代价：将来若要支持 ZUC-256 的
  64/128 位标签，需重新设计参数位。
- `Ruling:` 复用保护加在 `zucEncrypt` 上，并新增 `zucDecrypt`，解密路径豁免；
  原 round-trip 测试改用 `zucDecrypt`。理由：Review Focus #5 要求重复 (key, iv)
  抛错，但 EEA3 加解密同构，同一密钥流必然要用于解密，"加密一次 / 可重复解密"
  是唯一自洽的形态。代价：`zucEncrypt` 成为有状态 API，长生命周期调用方需
  `resetReuseGuard()`。

### Task 2 — SM2 generateKeyPair + C1C2C3（plan Task 6/8 的 P0 补口）

- 新增 `generateKeyPair(): Promise<{ privateKeyPem, publicKeyPem }>`（spec §6、§12.1 Q2），
  复用已有 `encodeSm2PrivateKeyPem` / `encodeSm2PublicKeyPem` + `randomScalarBelow(n)`。
- `encrypt(pub, msg, { outputFormat })`：默认 C1C3C2，可选 C1C2C3（spec §12.1 Q1）。
- `decrypt(priv, ct, { inputFormat })`：默认 `auto` —— 先按 C1C3C2，C3 校验失败
  且密文含 C2 时按 C1C2C3 重排重试。
- 测试：`npx vitest run --config vitest.config.ts tests/sm2.spec.ts` → 11/11 pass；
  相邻 6 个 SM2 spec + pem 合计 42/42 pass；`npx tsc --noEmit` 干净。
- `Ruling:` C1C2C3 的重排放在 TS 层，wasm 的 `encryptOut` / `decryptOut` 仍只认
  C1C3C2。理由：重排是纯字节搬运，放 TS 层不动已验证的曲线代码。代价：多一次
  97+n 字节拷贝。
- `Ruling:` 自动识别用"试错"（先 C1C3C2 再 C1C2C3），空 C2 时不重试。理由：C3 是
  SM3 校验值，失败即说明顺序或密钥不对，这是唯一无需外部提示的判别方式。
  代价：错误密文多跑一次解密（常数级）。
- 注：plan Task 6 写的 `DecryptionError` 仍按现状抛 `Error` —— 属 P2 项，未在本轮范围。

### Task 3 — SM9 facade 导出 + generateKeyPair（PKCS#8/SPKI + SM9 OID）

- `src/index.ts` 补上 `export * as sm9`：spec §6 要求 `import { sm2, sm3, sm4, sm9, zuc }`，
  此前 facade 漏了 sm9，`tests/facade.spec.ts` 也没断言它。
- `src/pem/sm9.ts`：`encodeSm9PrivateKeyPem` / `parseSm9PrivateKeyPem` /
  `encodeSm9PublicKeyPem` / `parseSm9PublicKeyPem`，统一 OID `1.2.156.10197.1.100`；
  解析时校验 OID，不符抛 `InvalidKeyError`。
- `src/sm9/index.ts`：新增 `generateKeyPair({ id, purpose })`，把 wasm 已有的
  `signPubOut`/`signDsOut`（或 `encPubOut`/`encDeOut`）接到 JS 层并编码为 PEM；
  所有以主私钥为第一参数的入口（sign / verify / encrypt / decrypt / kem* / exchange*）
  现在也接受 PKCS#8 PEM —— 在模块内的 `toBytes` 里统一嗅探 `-----BEGIN`。
- 测试：`npx vitest run --config vitest.config.ts tests/sm9-keys.spec.ts` → 8/8 pass；
  `npx tsc --noEmit` 干净。（`Sm9Exports` 接口原先没声明 `signDsOut`/`encDeOut`，一并补上。）
- `Ruling:` `generateKeyPair` 返回 **3** 个 PEM（masterPrivate / masterPublic /
  userPrivate），不返回 plan Task 10 写的 `userPublicPem`。理由：SM9 的用户公钥是
  `(id, 主公钥)` 的确定函数、不是独立持有物，且 wasm 侧没有"任意 G1 点标量乘"入口可算
  `[H1(id)]P1 + Ppub-e`。代价：对接方若期望显式的用户公钥文件，需自行约定或多加一个
  wasm 入口。
- `Ruling:` PEM 嗅探放在 sm9 模块的 `toBytes` 里（一处），而不是改 10 个调用点。
  理由：SM9 各入口第一参数一律是主私钥，`-----BEGIN` 守卫不会误伤 id/msg。
  代价：将来若要传"以 PEM 表示的 id"，得改回显式分支。
- `Ruling:` 本轮**未**让 `verify` / `encrypt` 接受主公钥 PEM。理由：wasm 的
  `sm9VerifyOut` / `sm9EncryptOut` 内部自行从主私钥派生主公钥，没有接受点字节的入口；
  补它要新增 2 个 AS 导出并重编 sm9.wasm，属新功能而非 P0 缺口。
  代价：spec §6 示例里的 `verify(masterPublicPem, ...)` 形态目前仍需传主私钥 PEM，
  已记入后续缺口清单。

### Task 4 — 命名别名（SM4 / ZUC）

- 用户裁决："两边都留" —— 现名保留为主名，另加 spec/plan 里写的方法名。
- `src/sm4/index.ts`：`encryptCTR` / `decryptCTR` / `encryptOFB` / `decryptOFB` 指向
  `cryptCTR` / `cryptOFB`（CTR/OFB 加解密同构）。
- `src/zuc/index.ts`：`encrypt` / `decrypt` / `generateKeystream` / `mac` / `eia3`
  分别指向 `zucEncrypt` / `zucDecrypt` / `zucKeystream` / `zucMac`。
- 测试：`npx vitest run --config vitest.config.ts tests/aliases.spec.ts` → 4/4 pass，
  用 `toBe` 钉住"同一函数引用"，避免别名日后悄悄漂移。
- `Ruling:` 用 `export { x as y }` 而不是 `const y = x; export { y }`。理由：前者不产生
  新绑定，`toBe` 断言与 tree-shaking 行为都更直白。代价：无。

### Task 5 — 文档同步（spec / plan ↔ 实现）

- spec：§3 表格加"实际导出"列；§13 DoD 标注勾选状态；新增 §14「实现状态对账」，
  分四块列出：已完成 / P1 工程化未完成 / P2 已实现但与文档不符 / 本轮明确留下的缺口。
- plan：开头新增「执行状态（2026-10-14 对账）」表，15 个 Task 逐条标 ✅ / ◐ / ❌。
- `Ruling:` 本轮不动 README。理由：README 速查属 P1，用户只选了 P0 功能性缺口；
  spec §13 已把它的缺失记为未完成。代价：README 仍是两行标题，npm 页面上没有信息量。
- `Ruling:` 不改写 spec 的历史决策章节（§4 工程栈的 rollup、§5 的 ESM+CJS 双产物），
  只在 §14 记录"实际走 `asc` + `tsc` 单产物"。理由：spec 是已批准的决策记录，改历史
  会让 plan/spec 的对照失去意义。代价：读 §4/§5 的人要读到 §14 才知道现状。

---

## Final review

`Final review: self-review (no subagent tool)` —— 审查范围 `01d466d..HEAD`（5 个提交，
15 文件 +1021/-49），按 `requesting-code-review/code-reviewer.md` 的清单自查。

### Strengths

- 每个新能力都先写了会失败的测试：EIA3 用 GM/T 0001.3-2012 三组官方向量
  （1 / 577 / 5670 bit，覆盖非整字节），复用保护用随机 key 避免用例互相污染；
- C1C2C3 的重排留在 TS 层，wasm 里已验证的曲线 / pairing 代码一行未动；
- 别名用 `toBe` 钉住"同一函数引用"，避免日后悄悄漂移。

### Issues

- **Important**：`src/zuc/index.ts` 的复用记录用 `Set` 且无上限 —— 长生命周期进程里
  会无界增长（每条约 100 字符）。已进入 fix pass。
- Minor（deferred，见下）。

### Fix pass

`Final: fixed 复用记录无界增长` —— 新增测试
"keeps the guard bounded — the oldest entry is evicted, recent ones still protected"
先 RED（旧实现不淘汰），改成 `Map` + FIFO 淘汰（上限 `REUSE_GUARD_CAPACITY = 4096`）后
GREEN；全量套件 112/112。

### Deferred minors

- `eia3Iv`（COUNT/BEARER/DIRECTION → 16 字节 IV）目前只存在于测试里，调用方要自己拼
  比特布局；可考虑导出成 `zucEia3Iv()`。
- `zucDecrypt` 的 `counter` 参数被忽略（`void counter`），仅为与 `zucEncrypt` 签名对称。
- `generateKeyPair` 产出的 PEM 是明文 PKCS#8（与 SM2 一致；spec 未要求加密私钥）。

### Declined to judge（自查时列出并裁决的项）

- `zucEncrypt` 变成有状态 API（同 (key,iv,counter) 二次加密抛错）—— 裁决：按 plan
  Review Focus #5 保留；0.1.0 尚未发布，破坏性可控，代价已记在 Task 1 的 ruling 里。
- `sm2.decrypt` 的 auto 模式会为错误密文多跑一次解密 —— 裁决：常数级开销，
  换来"无需外部提示即可识别两种顺序"，保留。
- spec §4/§5 与 §13 与实际的 rollup / CJS 差异 —— 裁决：已写入 spec §14，不再改历史章节。

---

# P2 批次（2026-10-14，plan 关闭后的新工作）

用户裁决："先处理 P2"。范围＝ spec §14 的 P2 清单 + 本轮新留的缺口。

### Task 1 — SM3 摘要类接受空输入

- 起因：spec §14 的 P2 第 3 条。核对后**更正一处事实**：`toBytes('')` 本来就抛
  `TypeError`（`src/runtime/convert.ts:44`），真正的不一致是 `hash('')` 抛而
  `hash(new Uint8Array(0))` 能算出摘要。
- 用户裁决："摘要类接受空输入（对齐 SM3 定义）"。依据：SM3 的输入是任意比特串
  （GM/T 0004-2012），空串 `l = 0` 填充后恰好是一个完整 512 比特块；实测
  `SM3("") = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b`
  （Node v26.7.0 / OpenSSL 3.5.7；同一 oracle 复现了 GM/T 0004 附录 A 的 `SM3("abc")`）。
- 实现：`src/sm3/index.ts` 新增 `digestInput()`，只对 SM3 的 msg/key 放行零长度输入；
  `toBytes` 的"空输入抛错"保持原样（那是给密钥 / IV / 密文这类固定长度契约用的）。
- 测试：`npx vitest run --config vitest.config.ts tests/sm3-oracle.spec.ts` → 9/9 pass。
- `Ruling:` 与 plan Task 7 的 `expect(() => hash('')).toThrow(TypeError)` 相反 ——
  算法定义优先于 plan 的 Review Focus #1，该条已在 spec §14 更正。代价：按 plan
  原文写用例的调用方会看到不同行为；plan 正文本轮不改，只在 §14 记录。
- 过程备注：首次写 hmac 用例时踩了字符串嗅探的坑（`'abc'` 奇数长度非 hex → 被当
  base64），改用字节输入后通过；该坑在同文件顶部注释里本来就有警告。

### Task 2 — 校验失败统一抛 DecryptionError

- 三处"校验未通过"由裸 `Error` 改为 `errors.ts` 已定义的 `DecryptionError`：
  `sm2.decrypt`（C3 校验）、`sm4.decryptGCM`（认证标签）、`sm9.decrypt`（C3 HMAC）。
- 错误消息文本保持原样，只换类型 —— 调用方从 `instanceof Error` 升级到
  `instanceof DecryptionError` 是纯增量（后者继承前者）。
- 新增 `tests/errors.spec.ts` 作为契约测试：3 条失败路径 + 错误层级 + facade 再导出。
- 测试：`npx vitest run --config vitest.config.ts tests/errors.spec.ts` → 6/6 pass。
- `Ruling:` 长度/结构类错误（密文太短、签名长度不对）**保持** `RangeError`，不改
  `InvalidCiphertextError`。理由：`src/runtime/errors.ts` 的文档明确写了"TypeError /
  RangeError 保留宿主原生类型，不包装为 SmCryptoError"，那是既有且刻意的设计；plan
  Review Focus #4 要求密文长度错也抛 DecryptionError，照做会让 errors.ts 自相矛盾。
  代价：调用方要同时 catch `RangeError` 与 `DecryptionError` 才覆盖"密文有问题"的全部路径。
- `Ruling:` `sm9.kemDecrypt` 的失败（封装非法 / K 全 0）本轮不纳入。理由：其失败原因
  包含"K 全 0"这种非校验性退化，不纯是"解密校验未通过"。代价：SM9 KEM 调用方暂时拿不到
  统一类型（记为 deferred minor）。

### Task 3 — SM2 公钥曲线校验 + InvalidPublicKeyError

- `src/runtime/errors.ts` 新增 `InvalidPublicKeyError extends InvalidKeyError`（plan
  Review Focus #3 指定的名字）；facade 一并导出。
- `src/sm2/index.ts` 新增曲线常量（p / a / b）与 `isOnCurve()`：校验
  `y² ≡ x³ + ax + b (mod p)` 且两坐标都 < p。
- `encrypt` 在构造密文前拒绝坏点（抛 `InvalidPublicKeyError`）；`verify` 对坏点返回
  false 而不抛（plan 明确要求）。
- 测试：`npx vitest run --config vitest.config.ts tests/sm2.spec.ts tests/errors.spec.ts
  tests/sm2-kex-official.spec.ts` → 25/25 pass。
- `Ruling:` 用新的子类而不是把坏点塞进 `InvalidKeyError`。理由：plan 指定了
  `InvalidPublicKeyError` 这个名字，而继承 `InvalidKeyError` 让既有的
  `catch (e) { e instanceof InvalidKeyError }` 调用方不受影响。代价：错误层级多一层。
- `Ruling:` 曲线判定用 TS 层 BigInt，不下沉到 wasm。理由：每次调用只做一次常数级模运算，
  而改 wasm 要重编 sm2.wasm。代价：校验不在常数时间内完成（输入是公开公钥，无秘密依赖）。
- 附带修正：`InvalidKeyError.name` 补 `: string` 标注 —— 原先被推断成字面量类型，
  子类无法覆盖 `name`（TS2416）。

### Task 4 — 文档同步（P2）

- spec §14：P2 段标记三条已修，并新增「P2 批次（2026-10-14 修复）」小节；同时更正
  了原先对空输入那条的**错误描述**（说 `hash('')` 会算出摘要 —— 实际它抛错，
  不抛的是 `hash(new Uint8Array(0))`）。
- plan：Review Focus 表后加注 —— #1 的"The all algorithms throw"按 SM3 定义更正为
  "摘要类除外"；#3 / #4 / #5 标注现状（#4 的 `safeMode` 选项仍未实现）。
- `Ruling:` 只加注、不改写 plan 的表格原文。理由：plan 是当时批准的记录，改原文会让
  "当时怎么定的、现在怎么做的"这条线索断掉。代价：读表的人要读表下的注记。

---

## Final review（P2 批次）

`Final review: self-review (no subagent tool)` —— 审查范围 `de6647c..HEAD`
（4 个实现/文档提交），按 `requesting-code-review/code-reviewer.md` 的清单自查。

### Strengths

- 每条修复都先写了会失败的测试：空输入 2 条、错误类型 4 条、公钥合法性 5 条。
- `isOnCurve` 带**对照用例**（真公钥仍能 encrypt / verify 通过）—— 没有它，公式写错
  也会"全部通过"（坏点被拒的原因可能只是公式恒 false）。
- 错误类型只做增量收紧：`DecryptionError` / `InvalidPublicKeyError` 分别继承
  `SmCryptoError` / `InvalidKeyError`，既有的 `instanceof` 捕获路径不受影响。

### Issues

- **Critical**：无。
- **Important**：无。
- **Minor（deferred）**：
  - `InvalidCiphertextError` 与 `NotImplementedError` 至今没有任何代码抛出 —— 调用方
    catch 它们会永远落空。（`NotImplementedError` 情有可原：已过 stub 阶段。
    `InvalidCiphertextError` 本可用于"密文长度 / 结构错"，但按 `errors.ts` 的约定
    那类保留了 `RangeError`。）
  - `sm9.kemDecrypt` 的失败仍是裸 `Error`（Task 2 的 ruling）。
  - `hash('')` 由抛错改为返回摘要是**破坏性**变更 —— 已在 spec §14 与 plan 注记里说明。

### Fix pass

`Final: fixed 重复 import` —— `src/sm9/index.ts` 中两行同源 `../runtime/errors.js`
合并为一行（本批次我自己引入的瑕疵，零风险）。验证：`npx tsc --noEmit` +
`tests/{sm9-keys,errors}.spec.ts` → 14/14 仍绿；纯导入整理，无新增测试。

### Declined to judge

- `InvalidKeyError.name` 类型由字面量放宽为 `string` —— 裁决：要让子类能覆盖 `name`
  必须如此，运行时字符串未变、无行为影响，保留。
- `sm2.encrypt` 现在会拒绝以前"能跑通"的坏公钥 —— 裁决：这正是加强校验的目的，保留。
- sm9 的 `kemDecrypt` 与 exchange 状态机仍抛裸 `Error` —— 裁决：超出本轮 P2 清单
  （用户只选了空输入、错误类型、公钥校验三条），保留。

---

# 扩展性批次（2026-10-14）

用户裁决：把"对以后扩展有影响"的 ruling 都改成能平滑过渡的形态；SM9 那两项一并做；
另外补 `safeMode`。

### Task 1 — 错误体系统一

- 用户裁决："现在就统一"。新增 `CiphertextError`（密文支基类），`InvalidCiphertextError`
  与 `DecryptionError` 都继承它；密钥支仍为 `InvalidKeyError`（`InvalidPublicKeyError` 是其子类）。
  于是 `errors.ts` 里那句"所有公开 API 抛出的错误都是 `SmCryptoError` 子类"终于自洽。
- 归位：
  - 密钥 / IV / 标量长度错 → `InvalidKeyError`（`sm2/keyInput`、`sm4` 各模式、`zuc`、
    `sm9` 的 `requireLen` 默认支）；
  - 密文 / 签名 / 协议消息 → `InvalidCiphertextError`（sm2 短密文与签名长度、sm4
    ECB/CBC 密文长度与 GCM tag 长度、sm9 的 ct 长度与 sig/SA/SB）；
  - 解密校验失败 → `DecryptionError`（sm4 CBC 的 PKCS#7 填充错也归此类）；
    `sm9.kemDecrypt` 由裸 `Error` 改过来。
- facade 导出 `CiphertextError`。
- 测试：`npx vitest run tests/errors.spec.ts` → 14/14；全量 → 20 文件 133/133 pass。
- `Ruling:` **明文**长度错（如 `sm4 ECB: 明文长度必须是 16 的非零倍数`）保留 `RangeError`。
  理由：它是"调用方传参形状不对"，不是"收到的密文有问题"，`InvalidCiphertextError` 的
  名字与语义都套不上。代价：要判定"数据块有问题"得覆盖两类，但该类错误在加密侧属编程
  错误、不该被业务逻辑 catch。
- `Ruling:` `sm9.requireLen` 默认走密钥支，只有 4 个调用点显式传 `'cipher'`。理由：SM9 的
  长度校验点绝大多数是主私钥 / 标量；改默认值只动 1 处，改调用点要动 10+ 处且文本重复。
  代价：`r`（随机标量）长度错现在抛 `InvalidKeyError` 而非 `RangeError` —— 已在
  `errors.ts` 注释里把密钥支定义为"密钥 / 标量输入"以对齐。

### Task 2 — ZUC 平滑化

- `zucMac(key, iv, msg, bitLengthOrOptions?, tagBits?)`：第 4 参现在也接受
  `ZucMacOptions` 对象（`{ bitLength?, tagBits? }`），位置参数写法保持有效。
  将来 ZUC-256 的参数（密钥长度、字长…）加进 options 即可，不必再动位置参数。
- 复用保护可配置：`zucEncrypt(..., opts?: { reuseGuard?: boolean })` +
  `configureReuseGuard({ enabled?, capacity? })`；容量默认 4096，FIFO 保持有界。
- 新增 `zucEia3Iv(count, bearer, direction)`：把原先只活在测试里的 IV 布局（照 GmSSL
  `zuc_set_eia_iv`）提升为公共 API，并校验 count/bearer/direction 的取值范围。
- 复用拒绝的错误类型由裸 `Error` 改为 `InvalidKeyError`（属"密钥使用策略"问题），
  消息里仍保留"复用"字样，故既有断言不受影响。
- 测试：`tests/zuc.spec.ts` → 17/17；全量 → 20 文件 138/138 pass。
- `Ruling:` `zucMac` 第 4 参保留"位置参数与 options 双形态"，而不是直接改成纯 options。
  理由：spec §6 写的是 `zuc.mac(key, iv, 'msg', 32)`，纯 options 会让文档示例失效。
  代价：签名是联合类型，比单一形态啰嗦。
- `Ruling:` 复用保护同时提供"调用级"与"全局级"开关。理由：有的调用方按协议保证不重复
  使用密钥流（外部计数器严格管理），不该被库拦死；而默认仍站在安全一侧。
  代价：`configureReuseGuard` 是进程级状态，同进程多租户场景需谨慎。

### Task 3 — SM9 PEM 嗅探收紧

- 把 PEM 解析从通用 `toBytes` 里移出，改为显式的 `masterPrivateBytes(input, label)`：
  只在**密钥参数**上嗅探 PEM，`toBytes` 回归纯 hex / base64 / UTF-8。
- 10 个入口（getSignPublicKey / getEncPublicKey / sign / verify / encrypt / decrypt /
  kemEncrypt / kemDecrypt / createExchangeInitiator / createExchangeResponder）改用它；
  该 helper 内部已含长度校验，调用点上原有的 `requireLen(..., 32, 'ks')` 一并去掉。
- 测试：`tests/sm9-keys.spec.ts` 新增「id 里出现 `-----BEGIN` 不会被误当 PEM 私钥」；
  `sm9-keys` + `sm9/sm9` + `errors` 三文件 27/27 pass。
- `Ruling:` helper 按"参数角色"命名而非"看起来像不像 PEM"。理由：Task 4 要加主公钥
  PEM 支持，届时新增 `masterPublicBytes` 即可，`toBytes` 不必再改第二次。
  代价：多一层 helper 间接。

### Task 4 — SM9 主公钥支持 + userPublicPem（含 wasm 改动）

- wasm（`src/sm9/assembly/index.ts`）新增 4 个导出，全部是对既有函数的薄封装：
  - `sm9VerifyPubOut`：用签名主公钥（G2 仿射）验签；
  - `sm9EncryptPubOut`：用加密主公钥（G1 仿射）加密；
  - `sm9UserEncPubOut`：`Q = [H1(id,hid=3)]P1 + Ppub-e`；
  - `sm9UserSignPubOut`：`Q = [H1(id,hid=1)]P2 + Ppub-s`。
  只新增导出、未改既有导出；`sm9.wasm` 已重编（输出仅余既有的 AS201 警告）。
- TS 层：
  - `keyArg()` 让 `verify` / `encrypt` 的密钥参数同时接受主私钥（32B / PKCS#8）与
    主公钥（点字节 / SPKI）—— 两者长度不重叠（32 vs 64/128），按长度判别即可；
  - `generateKeyPair` 增出 `userPublicPem`；新增 `getUserPublicKey(masterPublicKey, id)`
    供第三方自行复算。
- 测试：`tests/sm9-keys.spec.ts` 新增 5 条 → 14/14；全量 → 20 文件 144/144 pass。
- `Ruling:` 签名场景也产出 `userPublicPem`（`[H1(id,hid=1)]P2 + Ppub-s`），即使 SM9
  验签本身不需要它。理由：plan 要求四件套形状固定，且该点数学上良定义；只给 enc 返回
  会让 `purpose: 'sign'` 的形状与 enc 不同。代价：该字段在签名场景是"便利信息"，
  并非标准定义的对象。
- `Ruling:` 主公钥用**长度**判别而不是新增显式参数。理由：spec §6 的形态就是"同一位置
  传主私钥或主公钥"，加参数会破坏它；长度区间不重叠使判别无歧义。代价：若将来出现
  32 字节的主公钥（SM9 里不存在），需换判别方式。
- `Ruling:` wasm 只加薄封装、不动既有函数。理由：既有导出的行为已被 KAT 向量钉住，
  改它们的风险大于收益。代价：wasm 多 4 个仅供 TS 层调用的入口。

### Task 5 — safeMode

- `sm2.decrypt(priv, ct, { inputFormat?, safeMode? })`、`sm9.decrypt(ke, id, ct, { safeMode? })`、
  `sm4.decryptGCM(key, iv, ct, tag, aad | { aad?, safeMode? })` 三处支持 `safeMode`：
  失败时返回 `null` 而不是抛错（plan Review Focus #4）。
- 返回类型用**重载**保持兼容：只有显式写 `{ safeMode: true }` 的调用点拿到 `string | null`，
  既有调用点的类型仍是 `string`。实现拆为 `decrypt*Unsafe()` 实作 + 外层 try/catch。
- 判定用 `err instanceof CiphertextError` —— 正是 Task 1 统一错误体系的直接收益：
  "密文结构错"与"校验失败"一个守卫即可覆盖，而参数类型错（TypeError / RangeError）仍抛。
- 测试：`tests/safe-mode.spec.ts` 新增 6 条；与 `sm4` / `errors` 合计 34/34 pass。
- `Ruling:` `sm4.decryptGCM` 用"第 5 参双形态"而不是新增第 6 个位置参数。理由：否则会
  出现 `decryptGCM(k, iv, ct, tag, undefined, { safeMode: true })` 这种写法；对象形态把
  aad 与 safeMode 收拢到一处。代价：第 5 参是联合类型，内部要用 instanceof 判别。

### Task 6 — 文档同步 + 全量回归 + self-review

- spec：§3 表的 SM2 / SM3 / SM4 / SM9 / ZUC 五行按现状更新；§14 的"留作后续的缺口"
  两条标为已实现，并新增「扩展性批次（2026-10-14）」小节。
- plan：Review Focus 表后的注记更新（#4 已全部实现，含 `safeMode`）。
- 测试：全量 21 文件 150/150 pass；`npx tsc --noEmit` 干净。

---

## Final review（扩展性批次）

`Final review: self-review (no subagent tool)` —— 审查范围 `de6647c..HEAD`（6 个实现/文档提交）。

### Strengths

- 每个扩展点都有测试钉住：错误体系 6 条、ZUC 5 条、SM9 主公钥 5 条、safeMode 6 条。
- wasm 改动是**纯新增导出**，既有导出一行未动 —— 既有 KAT 向量继续通过，说明密码学核心
  没有被碰。
- `safeMode` 用重载而非改返回类型：返回值变化只波及显式写 `{ safeMode: true }` 的调用点。

### Issues

- Critical：无。
- Important：无。
- Minor（deferred）：
  - `zucMac` 的 options 判别用 `typeof === 'object'`，若运行时强传 `Uint8Array` 会静默取
    默认值（类型系统已拦，属防御性缺口）。
  - `configureReuseGuard` 是进程级状态，同进程多租户需自行协调。
  - `keyArg` 的 PEM 判定仍是字符串 `includes`，不是结构化 ASN.1 判定。

### Fix pass

`Final: fixed PEM 判定收紧` —— `keyArg` 判"是不是公钥 PEM"由 `'PUBLIC KEY'` 收紧为
`'BEGIN PUBLIC KEY'`（避免 PEM body 偶然命中）。验证：`npx tsc --noEmit` + 全量 150/150
（纯判定收紧，无新增测试）。

### Declined to judge

- `zucEncrypt` 的有状态性 —— 裁决：已提供调用级与全局级开关，保留。
- 签名场景的 `userPublicPem` 并非标准定义的对象 —— 裁决：返回值形状一致性优先，
  已在 Task 4 的 ruling 里说明。
- 明文长度错保留 `RangeError` —— 裁决：加密侧的明文形状错属编程错误，保留。

---

# P1 批次（2026-10-14）

用户裁决："接着做 P1"。范围 = spec §14 的 P1 清单。

### Task 1 — biome（lint + format）

- 新增 `biome.json`。踩到两个 biome 2.5 配置坑（`linter.rules.recommended` 已废弃 → `preset`；
  `useImportExtensions` 的选项是 `forceJsExtensions` 而非 `fixStyle`），用 `biome migrate` 修好。
- 修净仓库既有 100+ 处违规，分两个 commit（`22316ad` 批量格式化、`23c8663` 规则违反）便于 review。
- `Ruling:` 对 `src/**/assembly/**` 关闭 `useImportExtensions` —— AS 模块互引用不带 `.js` 后缀，
  而非 assembly 源带后缀是 NodeNext 的要求。

### Task 2 — bench/

- `bench/`（`run.ts` + 5 个 `.bench.ts`），`pnpm bench` 可跑通并输出 mitata 报告。
- `Ruling:` 单 entry 串 5 个 group（与 plan 形态一致），而不是拆 5 个可执行入口。

### Task 3 — 浏览器 runner

- `vitest.browser.config.ts`（happy-dom）+ `tests/browser/smoke.spec.ts`（6 条）。
- `vitest.config.ts` 的 exclude 增加 `tests/browser/**`：两套 runner 必须严格独立
  —— 这里踩过坑（Node runner 一开始吃进了浏览器测试，`window` undefined 导致失败）。
- `Ruling:` 用 happy-dom 而非 Playwright/Chromium（库对外只暴露纯 wasm + TS API）。
  已知差异：happy-dom 下 `loadWasm` 的 `isNode` 仍为 true，浏览器分支走不到 —— 已在测试注释写明。

### Task 4 — runtime 单测 + fuzz

- `tests/runtime/{loadWasm,convert,random}.spec.ts`（32 条）+ `tests/fuzz/wycheproof-style.spec.ts`（3 条）。
- 过程中修了 `src/runtime/loadWasm.ts` 两个真 bug：
  1. sync 路径 instantiate 缺 `env` stub（ASC 产物需要）→ 提取 `ASC_ENV` 常量供 sync/async 共用；
  2. 非法算法名会漏到文件系统、抛 ENOENT → 新增 `WASM_ALGOS` 白名单 + `rejectBadName`（RangeError）。
- `Ruling:` 非法算法名走**同步 throw**（`loadWasm` 不是 async function）—— 错误越早抛越好，
  不增加一次 microtask 调度。

### Task 5 — CI / 发布

- `.github/workflows/ci.yml`（2 个 job）+ `release.yml`（tag → `--provenance` 发布）+ `.release-it.json`。
- **关键阻塞**：`pnpm build` 原本跑不通 —— 见下面 Final review 的 fix pass。
- `Ruling:` CI 分 2 个 job（而非 plan 写的 5 个）—— 避免重复 5 次 asc 编译。
- `Ruling:` CI 用 `--frozen-lockfile` —— `pnpm-lock.yaml` 实际被 git 跟踪。

### Task 6 — README

- 从两行标题扩为完整速查（安装 / 6 档示例 / API 表 / 子路径 / 跨运行时 / 错误层级 / 安全 / 开发）。
- **每个示例都提取成脚本实跑验证**，抓出 3 处文档错误（ECB 输入不足 16 字节、GCM 的 aad 用中文
  被当 base64、`sm9.kemEncrypt` 的第一参数其实是加密主私钥）。

### Task 7 — 文档同步 + 回归 + 自审

- spec §13 DoD 全部勾选、§14 的 P1 段改为已完成并新增「P1 批次」小节；
  plan 的执行状态表 Task 12–15 更新为 ✅。
- `.gitignore`：删掉 `pnpm-lock.yaml` / `pnpm-workspace.yaml` 两行死配置（文件本就跟踪）。
- 最终链路：`lint → typecheck → build → test(182) → test:browser(6) → pack` 全绿。

---

## Final review（P1 批次）

`Final review: self-review (no subagent tool)`。

### Strengths

- 每条新增能力都有测试：runtime 32 条、fuzz 3 条、browser 6 条。
- README 的示例不是"看着对"，而是逐条执行验证过（23/23）。
- 发布链路从"根本跑不通"修到全绿，且定位到根因（格式化器介入 AssemblyScript 语义），而非绕过。

### Issues

- Critical：无。
- Important：无。
- Minor（deferred）：spec §14「本批次新发现」两条；rollup/CJS 双产物未做（ESM-only，已文档化）；
  `tests/packaging/smoke.spec.ts` 未单独建；biome 不能校验 workflow 的 YAML（交给 GitHub）。

### Fix pass

- `Final: fixed 发布链路` —— biome 的 `useImportType` 把 assembly 源的 import 改成
  `import { type X }`，`asc` 0.28 不认类型修饰符，`pnpm build`（进而 `prepack`）完全断掉。
  修复：对该目录关闭 `useImportType` 与 `organizeImports`，恢复 23 处 import（commit `c509319`）。
- `Final: fixed loadWasm 两个真 bug` —— sync 路径 env stub 缺失、非法算法名抛 ENOENT 而非 RangeError。

### Declined to judge

- ~~5 条 `noNonNullAssertion` warning 保留在 tests~~ → 后续已消除：`tests/sm2-kex-official.spec.ts`
  的 `mul(...)!` 改为 `mulDef(...)` 辅助函数（内部做 null 检查、抛带上下文的错），
  biome warning 归零，且"返回无穷远点"这种失败从 `Cannot read properties of null`
  变成可读的诊断信息。
- biome 修复拆两个 commit 而非一个（便于 review）。

---

## 许可统一（2026-10-14）

用户提问触发排查，发现三处声明互不一致且存在法律冲突：`LICENSE` 文件是 **GPL-2.0** 全文、
`package.json` 与 README 写 **MIT**、`src/zuc/assembly/index.ts` 声明"逐行移植自 gmkitx
（Apache-2.0）"并指向一个不存在的 `NOTICE`。GPL-2.0 与 Apache-2.0 不兼容（专利条款冲突），
三者不可能同时成立。

用户裁决：**统一为 Apache-2.0**；NOTICE 版权主体用 `jktantan`。

- `LICENSE`：从本地 Apache-2.0 依赖（gmkitx）取标准全文覆盖（201 行，无上游夹带信息）；
- `package.json`：`license` → `"Apache-2.0"`，`files` 加 `NOTICE`；
- `README.md`：License 段改 Apache-2.0 + 上游归属；
- 新增 `NOTICE`：按 Apache-2.0 §4(d) 声明 GmSSL 与 gmkit / gmkitx；
- spec §1/§5 与 plan 的 Global Constraints 里的 `MIT` 一并改掉（共 5 处）。

`Ruling:` 选 Apache-2.0 而不是 MIT。理由：`src/zuc/assembly/index.ts` 自述"逐行移植"，
属 Apache-2.0 的 derivative work；与上游同许可最干净，且 Apache-2.0 允许再许可与商业使用。
代价：比 MIT 多了 NOTICE 与归属义务（已在 NOTICE 里履行）。

---

## AS201 警告清零（2026-10-14）

用户报告 `asc` 输出大量 `WARNING AS201: Conversion from type 'usize' to 'i32' ...`。

**是什么**：前瞻性警告。`usize` 的宽度随目标变化（32-bit wasm → 32 位，wasm64 → 64 位）；
把 `usize` 用在要求 `i32` 的位置（数组下标、`StaticArray<T>(len)` 的长度）时，AS 现在隐式
转换，并提醒"切 64-bit 目标时这里需要显式 cast"。当前目标是 32-bit，隐式转换无损 ——
所以 build 一直是成功的、182 个测试一直全绿。

用户裁决：**加显式 `<i32>` cast**（而不是用 `asc --disableWarning 201` 抑制，也不是放着不管）。
规模：56 条警告 = **28 个唯一位置**（多个 wasm 都会编译同一文件），分布在 3 个文件。

做法（先做最小实验定规则，再动手）：

- 实验证明 `arr[<i32>i]` 与 `new StaticArray<u8>(<i32>len)` 都无警告，且 **i32 循环变量参与
  `ptr + i`（usize 指针运算）不会引入新警告**；
- **踩到的坑**：`buf[<i32>(32 + i)]` **仍会警告** —— cast 包住整个表达式，而表达式内部
  （`i32 + usize`）已经发生类型提升。正确写法是把 cast 放到**最内层**：`buf[32 + <i32>i]`；
- 落地：`field256.ts`（改 `o` 的声明类型，一次消掉 4 个下标警告）、
  `sm2/assembly/crypto.ts`（12 处）、`sm3/assembly/sm3-core.ts`（12 处）。

验证：`pnpm run build:wasm:all` 的 AS201 计数 = **0**；用重建后的产物跑
`npx tsc --noEmit` + 全量测试 **182/182**（KAT 全绿，说明 cast 未改变语义）。

---

## AS 源与 TS 的 IDE 冲突（2026-10-14）

用户报告 `TS2304: Cannot find name 'usize'`。排查结论：**命令行一直是干净的**（根
`tsconfig.json` 的 `exclude` 让 `tsc` 完全不碰 `src/**/assembly`，实测 `--listFiles` 收
210 个文件、0 个来自 assembly），错误来自 **IDE**（仓库含 `.idea/`，JetBrains 的 TS 服务
按"就近 tsconfig"检查文件，不按 `exclude` 跳过）——AS 专有类型 `usize` / `u32` /
`StaticArray` / `changetype` 等在 TS 标准库里不存在，裸 TS 检查会报 1045 个 `TS2304`。

用户裁决：**集中式**解决。落地：

- 根 `tsconfig.assembly.json`：`extends` AS 官方的 `assemblyscript/std/assembly.json`
  + `skipLibCheck: true`（后者用于消掉 AS 的 `index.d.ts` 与 TS 7 的 `TS2316` 冲突）；
- 6 个 `src/{common,sm2,sm3,sm4,sm9,zuc}/assembly/tsconfig.json`：各自只有一行
  `{ "extends": "../../../tsconfig.assembly.json" }`。

`Ruling:` 配置主体集中到根的一个文件，各目录只留一行指针 —— 改配置只需改一处。
代价：仍需要 6 个指针文件（IDE 与 tsc 都按"就近 tsconfig"决定作用域，没有文件就没有作用域）。
`Ruling:` 不用"在根 tsconfig 里塞 AS 类型"的办法 —— AS 需要 `noLib` + `types: ["assembly"]`，
与 TS 胶水层需要的标准库 + `types: ["node"]` 互斥（两者都声明 `Number`/`Array` 等全局名），
一套配置无法同时成立。

验证：6 个子配置各自 `tsc -p` → 均 0 错误；`pnpm lint` / `typecheck` / `build` / 全量测试
（182/182）全部不受影响。

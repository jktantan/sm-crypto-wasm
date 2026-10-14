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

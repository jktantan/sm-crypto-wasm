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

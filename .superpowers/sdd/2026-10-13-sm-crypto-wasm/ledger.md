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

(Filled in below as tasks complete.)

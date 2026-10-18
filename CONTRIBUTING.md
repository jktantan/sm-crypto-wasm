# 贡献指南 / Contributing

> Agent / 自动化贡献者请先阅读 [AGENTS.md](./AGENTS.md)。本文件是人类贡献者的快速入口，
> 注释规范、多 agent 协作和验证矩阵以 AGENTS.md 为准。
>
> Agent / automated contributors: read [AGENTS.md](./AGENTS.md) first. This file is a
> quick start for human contributors; the comment rules, multi-agent workflow, and
> verification matrix are defined in AGENTS.md.

## 环境 / Requirements

- Node.js >= 18（推荐 20+）/ Node.js >= 18 (20+ recommended)
- pnpm（CI 当前固定使用 pnpm 10.34.7）/ pnpm (CI currently pins pnpm 10.34.7)

## 安装与构建 / Setup and build

```bash
pnpm install
pnpm build        # 清空 dist，构建 5 个 wasm + tsc / clean, build 5 wasm files, run tsc
pnpm build:wasm:all
pnpm build:ts
```

## 开发检查 / Checks before submitting

提交前至少运行 / Run at least the following before submitting:

```bash
pnpm lint
pnpm typecheck
pnpm test:unit
```

- `pnpm test` 会先重建 wasm，再运行 Node 测试；
  `pnpm test` rebuilds the wasm files first, then runs the Node tests.
- `pnpm test:unit` 直接使用已有的 `dist/` 产物，适合日常快速回归；
  `pnpm test:unit` uses the existing `dist/` artifacts and is intended for quick local feedback.

浏览器与 fuzz 测试 / Browser and fuzz tests:

```bash
pnpm test:browser
pnpm test:fuzz
```

## 目录结构 / Repository layout

- `src/<algo>/` —— 算法门面；`src/<algo>/assembly/` —— AssemblyScript 源；
  algorithm facades; AssemblyScript sources live in `src/<algo>/assembly/`.
- `src/runtime/` —— 编解码、WASM 加载、随机数与错误类型；
  encoding/decoding, WASM loading, randomness, and error types.
- `tests/` —— 按模块分组，`tests/vectors/` 为测试向量；
  tests are grouped by module; test vectors live in `tests/vectors/`.
- `website/` —— VitePress 文档站与 Playground；
  VitePress documentation site and Playground.
- `docs/design/` —— 设计规格与历史计划。计划中的技术栈和命令可能过时，
  当前工具链以 `package.json`、`pnpm-workspace.yaml` 和 `.github/workflows/` 为准；
  design specs and historical plans. Plans may describe outdated toolchains;
  the current toolchain is defined by `package.json`, `pnpm-workspace.yaml`,
  and `.github/workflows/`.
- `docs/README.en.md`、`docs/README.ru.md` —— README 的英文 / 俄文版本；
  English and Russian versions of the README.

## 提交与 PR / Commits and pull requests

- 保持改动聚焦；行为变更请附测试；
  keep changes focused; add tests for behavior changes.
- 不要提交 `dist/`、`node_modules/`、`website/.vitepress/dist/` 等生成物；
  do not commit generated artifacts such as `dist/`, `node_modules/`, or
  `website/.vitepress/dist/`.
- 提交信息沿用现有风格，例如 `feat(sm2): ...`、`fix(runtime): ...`、`docs: ...`；
  follow the existing commit style, e.g. `feat(sm2): ...`, `fix(runtime): ...`,
  `docs: ...`.
- PR 描述中说明动机、行为变化和实际运行过的验证命令；
  describe the motivation, behavior changes, and the verification commands you ran.
- 安全问题请按 [SECURITY.md](./SECURITY.md) 报告，不要开公开 Issue；
  report security issues through [SECURITY.md](./SECURITY.md), not a public issue.

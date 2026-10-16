# 浏览器可分发性：Vite 已通，Webpack 待补 — 后续计划

> **状态：backlog。** 不是当前迭代项；等出现真实 Webpack 用户需求、或发布 1.0 前再动。
>
> **由来**：2026-10-16 用真 Chromium + Vite 实测浏览器可分发性时发现并**已修复 Vite 侧**（commit `408c36b`）；Webpack 侧当时判定为邻接缺口，用户裁定「记进计划，以后再做」。

**Goal:** 让库在 Vite / Webpack 5 / 原生 ESM 三种消费方式下都能构建并运行，且随机数始终来自宿主 CSPRNG。

---

## 现状（2026-10-16 实测）

| 消费方式 | 状态 | 说明 |
|---|---|---|
| Node（ESM） | ✅ | 全量 28 文件 196 用例绿 |
| **Vite 5** | ✅ | 真 Chromium 端到端通过（`isNode=false` 分支）；wasm 由 Vite 自动归档进 `assets/` |
| **Webpack 5** | ❌ | 无法解析 `node:fs/path/url/crypto`，`Module not found` 构建失败 |
| 原生 `<script type="module">` | ❌ | 裸 specifier `node:*` 无法解析（无打包器时本就不支持，见 Non-Goals） |
| happy-dom（vitest browser runner） | ⚠️ | 不抹掉 `process`，走 **Node 分支**，**不覆盖**真浏览器路径 |

已在 `408c36b` 完成的修复：

- `loadWasm.ts` / `random.ts`：`node:*` 改 namespace 导入（`import * as`）—— Vite 由 `build failed` 变 `succeeded`；
- `random.ts`：取不到宿主 CSPRNG 时**显式抛错**（fail-closed），绝不静默降级到弱随机；
- `tests/runtime/browser-imports.spec.ts`：禁止 `src/` 下再出现 `node:*` 具名导入。

---

## 缺口：Webpack 5

Webpack 不做 Vite 式的外部化，而是**解析期**直接报 `Can't resolve 'node:path'`。namespace 导入救不了它（具名/namespace 都在解析期失败）。

**修法（待实施）**：给浏览器一份不含 node 依赖的实现，用 package.json 条件导出切换：

```json
"exports": {
  "./runtime/loadWasm.js": {
    "browser": "./dist/runtime/loadWasm.browser.js",
    "default": "./dist/runtime/loadWasm.js"
  },
  "./runtime/random.js": {
    "browser": "./dist/runtime/random.browser.js",
    "default": "./dist/runtime/random.js"
  }
}
```

（或等价的 `"browser"` 字段。）

需要的改动：

- [ ] 拆出 `loadWasm.browser.ts` / `random.browser.ts`：浏览器版只用 `globalThis.crypto` + `fetch(new URL(...))`，零 `node:*` 引用；Node 版保持现状。
- [ ] 构建产出两份并进 `dist/`（`tsc` 两次或按文件覆写）。
- [ ] 验证：Webpack 5 + 真 Chromium 端到端；Node 全量测试不回归。
- [ ] 保守项：`loadWasmSync` 是 Node-only 同步 API（依赖 `readFileSync`），浏览器版必须给出明确抛错路径。

---

## 触发条件（何时值得做）

- 出现真实 Webpack 用户报告；
- 或发布 `1.0` 前要求「三大打包器全支持」。

在此之前，最小兜底是 **README 注明 Webpack 需配 `resolve.fallback`**（例如 `{ fs: false, path: false, url: false, crypto: false }`）。

---

## Non-Goals

- **原生 ESM 直载（无打包器）**：与「Node 侧需要 `node:*`」无法两全，除非彻底重构加载器；不在本项范围。
- **放弃 Node 支持**：Node 是一等公民，不能为浏览器让路。
- **改随机数策略**：无论哪条路径，都必须「宿主 CSPRNG，取不到就抛错」—— 这条不能因打包器便利而放松。

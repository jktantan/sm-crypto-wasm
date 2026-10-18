# 浏览器可分发性：四打包器全通 — 实施记录与遗留

> **状态：已实施。** 原为 backlog（用户先裁定"记进计划"，后在新证据下改判"现在就修"）。
> 落地于 2026-10-16。**实测**：Node / Vite 5 / esbuild / Webpack 5 全部构建通过，
> 真 Chromium 端到端跑通；Node 全量 198 用例绿。

**Goal:** 让库在 Vite / esbuild / Webpack 5 / Node 下都能构建并运行，且随机数始终来自宿主 CSPRNG。

---

## 问题

浏览器构建的模块图里出现了 `node:*`。三个打包器在**解析期**就因此构建失败
（tree-shaking 救不了 —— 解析先于摇树）：

| 打包器 | 修前 | 根因 |
|---|---|---|
| Vite 5（Rollup） | ⚠️ 具名导入下失败，namespace 导入可过 | 它把 `node:*` 外部化成只有 default 的空 stub；具名导入找不到导出即中止 |
| esbuild | ❌ `Could not resolve "node:fs"` | 不做外部化 |
| Webpack 5 | ❌ `Can't resolve 'node:fs'` | 不做外部化 |
| 原生 `<script type="module">` | ❌ | 裸 specifier 无法解析（属 Non-Goals，见下） |

关键：**5 个算法入口无一例外都引 `runtime/loadWasm.js`**（sm2/sm9 另引 `runtime/random.js`），
所以哪怕只用 SM3 也会把 `node:fs` 拉进模块图；而 Vite 恰是唯一容忍这写法的特例，
不能作为"已经修好了"的依据。

---

## 修法

拆成 Node / 浏览器两份实现，打包时按条件替换：

```
src/runtime/
  loadWasm.core.ts       零 node:* —— 类型、ASC_ENV、instantiate、记忆化（两边共用）
  loadWasm.ts            Node 版：node:fs / node:path / node:url 读文件
  loadWasm.browser.ts    浏览器版：静态 URL 表 + fetch，零 node:*
  random.core.ts         零 node:* —— 拒绝采样（两边共用）
  random.ts              Node 版：node:crypto（Node 19+ 用 globalThis.crypto）
  random.browser.ts      浏览器版：只认 globalThis.crypto，零 node:*
```

package.json 用 `browser` 字段做文件替换：

```json
"browser": {
  "./dist/runtime/loadWasm.js": "./dist/runtime/loadWasm.browser.js",
  "./dist/runtime/random.js": "./dist/runtime/random.browser.js"
}
```

要点：

- **`browser` 字段只有在包位于 `node_modules` 时才会被 Vite 应用** —— 库放在普通目录里
  测会得到假阴性（本次排查踩过这个坑）。
- 浏览器版的 wasm URL **显式列出** 5 条 `new URL('../<algo>/<algo>.wasm', import.meta.url)`，
  而不是模板拼路径：打包器只能静态识别字面量形式，才会把 wasm 归档进产物并重写 URL。
- 两版的**导出面必须一致**，否则替换后调用方拿到 `undefined`（有测试钉住）。
- 安全姿态两版一致：**取不到宿主 CSPRNG 就抛错（fail-closed）**，绝不降级到非密码学随机源。

---

## 验证矩阵（2026-10-16 实测）

| 消费方式 | 结果 | 证据 |
|---|---|---|
| Node（ESM，全量测试） | ✅ | 28 文件 / 198 用例 |
| **Vite 5** | ✅ | 构建零 `node:*` 警告，5 个 wasm 自动进 `assets/`；真 Chromium 端到端 |
| **esbuild 0.28.2** | ✅ | `--platform=browser` 产物 `node:` 计数 0 |
| **Webpack 5.111.1** | ✅ | `compiled successfully`，5 个 wasm 作为 asset 产出 |
| 真浏览器行为 | ✅ | `hasProcess=undefined`；SM3/SM4-GCM/ZUC/SM2/SM9 全对；`getRandomValues` 计数 6 |
| 抹掉 WebCrypto | ✅ | 抛错（fail-closed），未静默弱降级 |

自动化防护：`tests/runtime/browser-imports.spec.ts` 钉住三件事 ——
`src/` 下无 `node:*` 具名导入、浏览器变体与 core 零 `node:` 引用、两版导出面一致。

---

## 遗留（未做，已知）

1. **esbuild 不复制 wasm**。Vite 与 Webpack 会自动归档 `new URL(..., import.meta.url)`
   指向的 wasm，esbuild 不改写也不复制 —— 用户需自行把 `dist/<algo>/<algo>.wasm`
   放到产物中该相对位置，否则运行时 `fetch` 404。**构建本身是通过的。**
   - 缓解方向：文档写清；或提供"调用方注入 wasm 字节"的入口。
2. **原生 `<script type="module">` 直载仍不支持** —— 与 Node 侧需要 `node:*` 无法两全，
   属 Non-Goals。

---

## Non-Goals

- 放弃 Node 支持（Node 是一等公民）。
- 为打包器便利放松"宿主 CSPRNG，取不到即抛错"这条红线。
- 原生 ESM 直载（无打包器）支持。

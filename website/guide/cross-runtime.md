# 跨运行时

同一份 API 在 Node、浏览器和 Web Worker 下都能用。差异只在 **`ensureLoaded()` 从哪里
取到 `.wasm` 字节**：

| 环境 | 加载路径 |
| --- | --- |
| **Node 18+** | `node:fs/promises` 读 `dist/<algo>/<algo>.wasm`；可用 `loadWasmSync()` 同步预热 |
| **浏览器（经打包器）** | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`，由打包器归档并重写 URL |
| **Web Worker** | 加载器不依赖 DOM，Worker 内可直接用 |
| **Deno / Bun** | 复用 Node 路径（都暴露 `node:fs`） |

## 浏览器

WASM 实例化是异步的，所以**浏览器里必须在首次业务调用前** `await ensureLoaded()`：

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();   // 必须先 await 一次
sm3.hash('616263');
```

### 打包器支持

库按环境提供两份实现（Node 版读文件、浏览器版 `fetch`），由 `package.json` 的
`browser` 字段在打包时**自动切换**。这带来一个重要的性质：**浏览器产物里不会出现
`node:*`**，所以 Webpack / esbuild / Rspack 这类不做 node 内置模块外部化的打包器也
不会构建失败（它们会在解析期直接报 `Can't resolve 'node:fs'`）。

| 打包器 | 需要配置吗 | wasm 资源 |
| --- | --- | --- |
| **Vite 5** | 零配置 | 自动归档进产物（`assets/*.wasm`） |
| **Webpack 5** | 零配置 | 作为 asset 自动产出 |
| **esbuild** | 加一行插件（见下） | esbuild 不处理 `new URL(..., import.meta.url)` 指向的文件 |
| **Node 18+** | 零配置 | 读 `dist/<algo>/<algo>.wasm` |

> 浏览器需要**安全上下文**（`https://` 或 `localhost`）才能拿到
> `crypto.getRandomValues`。拿不到时库会**抛错**（fail-closed），**不会**退化成
> 非密码学随机源。

#### esbuild：加一行插件

esbuild 不会把 `new URL('../<algo>/<algo>.wasm', import.meta.url)` 指向的文件搬进产物
（`--outfile` 和 `--outdir` 都不会）。本包自带一个小插件补上这一步：

```ts
import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outdir: 'dist/assets',        // 产物 JS 落这里
  plugins: [smCryptoWasm()],    // → wasm 复制到 dist/<algo>/<algo>.wasm
});
```

插件的落点与运行时一致（产物 JS 的**上级目录**下的 `<algo>/`）。建议把 `outdir` 指到
子目录（如 `dist/assets`），这样 wasm 落在 `dist/<algo>/` 而不是产物目录的上级。
只用部分算法时可传 `algorithms: ['sm3']` 少复制几个。

不想用插件也行：手动把 `node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc}`
复制到产物 JS 的上级目录（上例即 `dist/`）。

## Node

Node 下 `await loadWasm('sm3')` 会走 `fs` 读文件。想要零开销的同步取用，可以先在启动时
预热，再用 `loadWasmSync`：

```ts
import { loadWasm, loadWasmSync } from 'sm-crypto-wasm';

await loadWasm('sm3');            // 预热（memoize）
const mod = loadWasmSync('sm3');  // 同步拿引用，仅 Node 可用
```

`loadWasmSync` 在浏览器里会抛错 —— 那里必须 `await loadWasm()`。

## Web Worker

Worker 里没有 DOM，但加载器只用 `fetch` / `WebAssembly`，因此可直接用：

```ts
// worker.ts
import { sm4 } from 'sm-crypto-wasm';

self.onmessage = async (e) => {
  await sm4.ensureLoaded();
  const ct = sm4.encryptGCM(e.data.key, e.data.iv, e.data.msg, e.data.aad);
  self.postMessage(ct);
};
```

## 并发与缓存

同一个算法的 `loadWasm()` / `ensureLoaded()` 是 **memoize** 的：并发调用共用同一个
Promise，`.wasm` 不会实例化两次。

```ts
// 两个并发调用 → 一次实例化
await Promise.all([sm3.ensureLoaded(), sm3.ensureLoaded()]);
```

## 不在当前范围

- **Cloudflare Workers / Vercel Edge** 这类"严格流式 WASM"环境不在支持范围内 ——
  它们的 WASM 模块加载模型与 `WebAssembly.instantiate(ArrayBuffer)` 不兼容。
- **`<script type="module">` 直载（不经打包器）**不在支持范围内：Node 侧要用
  `node:*`，无法与浏览器共用一份裸 ESM 产物。请使用上表中的打包器。

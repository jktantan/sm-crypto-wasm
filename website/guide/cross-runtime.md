# 跨运行时

同一份 API 在 Node、浏览器和 Web Worker 下都能用。差异只在 **`ensureLoaded()` 从哪里
取到 `.wasm` 字节**：

| 环境 | 加载路径 |
| --- | --- |
| **Node 18+** | `node:fs/promises` 读 `dist/<algo>/<algo>.wasm`；可用 `loadWasmSync()` 同步预热 |
| **浏览器 / Vite / Webpack / Rollup** | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`，由打包器负责重写 URL |
| **Web Worker** | 加载器不依赖 DOM，Worker 内可直接用 |
| **Deno / Bun** | 复用 Node 路径（都暴露 `node:fs`） |

## 浏览器

WASM 实例化是异步的，所以**浏览器里必须在首次业务调用前** `await ensureLoaded()`：

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();   // 必须先 await 一次
sm3.hash('616263');
```

打包器需要能解析 `new URL(..., import.meta.url)` 这种资源引用。Vite、Webpack 5、Rollup
都支持；如果用的是更老的打包器或自定义产物布局，改用显式的加载入口（见下）。

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

**Cloudflare Workers / Vercel Edge** 这类"严格流式 WASM"环境不在支持范围内 ——
它们的 WASM 模块加载模型与 `WebAssembly.instantiate(ArrayBuffer)` 不兼容。

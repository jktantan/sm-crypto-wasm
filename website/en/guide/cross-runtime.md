# Cross-runtime

The same API works in Node, browsers and Web Workers. The only difference is **where
`ensureLoaded()` reads the `.wasm` bytes**:

| Environment | Loading path |
| --- | --- |
| **Node 18+** | `node:fs/promises` reads `dist/<algo>/<algo>.wasm`; `loadWasmSync()` is available |
| **Browsers / Vite / Webpack / Rollup** | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`, rewritten by the bundler |
| **Web Workers** | the loader does not touch the DOM, so it works as-is |
| **Deno / Bun** | reuse the Node path (both expose `node:fs`) |

## Browser

WASM instantiation is asynchronous, so **always `await ensureLoaded()`** before the first call:

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');
```

Your bundler must resolve `new URL(..., import.meta.url)`. Vite, Webpack 5 and Rollup do.

## Node

```ts
import { loadWasm, loadWasmSync } from 'sm-crypto-wasm';

await loadWasm('sm3');            // warm up (memoised)
const mod = loadWasmSync('sm3');  // synchronous handle, Node only
```

`loadWasmSync` throws in browsers — there you must `await loadWasm()`.

## Concurrency

`loadWasm()` / `ensureLoaded()` are memoised: concurrent callers share one Promise, so the
`.wasm` is never instantiated twice.

## Out of scope

"Strictly streaming WASM" runtimes such as **Cloudflare Workers / Vercel Edge** are not
supported — their module-loading model is incompatible with
`WebAssembly.instantiate(ArrayBuffer)`.

::: info Full reference
The [Chinese page](/guide/cross-runtime) has the same material plus a Worker example.
:::

# Cross-runtime

The same API works in Node, browsers and Web Workers. The only difference is **where
`ensureLoaded()` reads the `.wasm` bytes**:

| Environment | Loading path |
| --- | --- |
| **Node 18+** | `node:fs/promises` reads `dist/<algo>/<algo>.wasm`; `loadWasmSync()` is available |
| **Browsers (via a bundler)** | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`, archived and rewritten by the bundler |
| **Web Workers** | the loader does not touch the DOM, so it works as-is |
| **Deno / Bun** | reuse the Node path (both expose `node:fs`) |

## Browser

WASM instantiation is asynchronous, so **always `await ensureLoaded()`** before the first call:

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');
```

### Bundler support

The package ships **two implementations** (a Node one that reads files, a browser one that
uses `fetch`) and `package.json`'s `browser` field switches between them at build time. The
upshot: **`node:*` never appears in a browser bundle**, so bundlers that do *not* externalise
node built-ins — Webpack, esbuild, Rspack — no longer fail at resolve time with
`Can't resolve 'node:fs'`.

| Bundler | Configuration | wasm asset |
| --- | --- | --- |
| **Vite 5** | none | archived into the output automatically (`assets/*.wasm`) |
| **Webpack 5** | none | emitted as an asset automatically |
| **esbuild** | you must copy the wasm yourself (below) | esbuild does not handle files pointed at by `new URL(..., import.meta.url)` |
| **Node 18+** | none | reads `dist/<algo>/<algo>.wasm` |

> Browsers need a **secure context** (`https://` or `localhost`) for `crypto.getRandomValues`.
> When it is unavailable the library **throws** (fail-closed) and will **not** fall back to a
> non-cryptographic source.

#### esbuild: copy the wasm yourself

esbuild does not move the files referenced by `new URL('../<algo>/<algo>.wasm',
import.meta.url)` into your output (neither `--outfile` nor `--outdir` does). The output JS
needs `<algo>/<algo>.wasm` in its **parent** directory:

```bash
# output lands in dist/assets/ → runtime resolves ../<algo>/<algo>.wasm → dist/<algo>/<algo>.wasm
esbuild src/main.ts --bundle --platform=browser --format=esm --outdir=dist/assets
cp -r node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc} dist/
```

Copy only the algorithms you use (e.g. just `cp -r node_modules/sm-crypto-wasm/dist/sm3 dist/`).

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

- **"Strictly streaming WASM" runtimes** such as Cloudflare Workers / Vercel Edge — their
  module-loading model is incompatible with `WebAssembly.instantiate(ArrayBuffer)`.
- **Loading the raw ESM output directly via `<script type="module">`** — the Node side needs
  `node:*`, so a single bare-ESM artifact cannot serve both. Use one of the bundlers above.

::: info Full reference
The [Chinese page](/guide/cross-runtime) has the same material plus a Worker example.
:::

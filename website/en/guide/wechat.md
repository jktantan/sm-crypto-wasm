# WeChat & Mini Programs

`sm-crypto-wasm` works in both WeChat environments, but the integration differs:

| Environment | How to integrate |
| --- | --- |
| **WeChat built-in browser (H5)** | Same as a normal browser; use your bundler |
| **WeChat Mini Program** | Needs a Mini Program runtime adapter: `WXWebAssembly` + `wx.getRandomValues` |

## WeChat built-in browser

The WeChat in-app browser is a full WebView: `fetch`, `WebAssembly` and
`crypto.getRandomValues` are available. Follow the browser setup in
[cross-runtime](/en/guide/cross-runtime):

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');
```

Notes:

- The page must be **HTTPS** (or localhost) so `crypto.getRandomValues` is available. The
  library fails closed otherwise — it never falls back to `Math.random`.
- Bundle it with Vite / Webpack / esbuild. Do not load `dist/*.js` directly with
  `<script type="module">`.

## WeChat Mini Program

A Mini Program is a different runtime. The browser entry cannot be used as-is:

- no `fetch`, and `import.meta.url` cannot locate wasm files;
- no standard `WebAssembly`; base library **2.13.0+** provides `WXWebAssembly`;
- no `globalThis.crypto`; base library **2.15.0+** provides `wx.getRandomValues` (async);
- no `btoa` / `atob` (the library has a built-in JS fallback); older base libraries also lack `TextEncoder` / `TextDecoder`.

### Quick start

The repository contains a minimal project that can be imported into WeChat DevTools:

```bash
pnpm build
pnpm example:wechat:prepare
```

Then import `examples/wechat-miniprogram` into WeChat DevTools and select base library
**2.15.0+**. The demo runs self-checks for SM2 / SM3 / SM4 / SM9 / ZUC and renders the
results on the page.

Keep only the algorithms you use (native Mini Programs do no tree-shaking):

```bash
pnpm example:wechat:prepare --algos sm3,sm4
```

`sm2` / `sm9` automatically pull in their `sm4`, `pem` and `common` dependencies.

### Why not "Build npm"

The DevTools "Build npm" step does not honour `package.json`'s `browser` field. It resolves
the Node `loadWasm.js` (`node:fs`) and `random.js` (`node:crypto`), and the browser entry's
`import.meta.url` fails with `Cannot use 'import.meta' outside a module`. It also does not
copy the wasm assets into the code package.

Instead, put `dist/` into the Mini Program package, load wasm with `WXWebAssembly`, and add
the three adapters below. The example's `prepare` script does the copy and overrides
automatically.

### Adapter 1: loading wasm

`WXWebAssembly.instantiate(path, imports)` only accepts a **code-package path** (starting
with `/`). Put `dist/` under `miniprogram/vendor/sm-crypto-wasm/dist/`, then replace
`dist/runtime/loadWasm.js` with:

```js
const WASM_PATHS = {
  sm2: '/vendor/sm-crypto-wasm/dist/sm2/sm2.wasm',
  sm3: '/vendor/sm-crypto-wasm/dist/sm3/sm3.wasm',
  sm4: '/vendor/sm-crypto-wasm/dist/sm4/sm4.wasm',
  sm9: '/vendor/sm-crypto-wasm/dist/sm9/sm9.wasm',
  zuc: '/vendor/sm-crypto-wasm/dist/zuc/zuc.wasm',
};

const ENV = {
  env: {
    abort() { throw new Error('wasm: abort'); },
    trace() {},
    __assert_fail() { throw new Error('wasm: assert_fail'); },
  },
};

const cache = new Map();

export function loadWasm(name) {
  const path = WASM_PATHS[name];
  if (!path) return Promise.reject(new RangeError(`loadWasm: unknown algo ${String(name)}`));

  let p = cache.get(name);
  if (!p) {
    p = (async () => {
      if (typeof WXWebAssembly === 'undefined') {
        throw new Error('WXWebAssembly requires base library 2.13.0+');
      }
      // The return value may be an Instance or { instance } — support both.
      const r = await WXWebAssembly.instantiate(path, ENV);
      const inst = r && r.instance ? r.instance : r;
      return Object.freeze({ exports: inst.exports, memory: inst.exports.memory });
    })();
    cache.set(name, p);
  }
  return p;
}

export function loadWasmSync() {
  throw new Error('loadWasmSync: await loadWasm(name) in Mini Programs');
}

export function getCachedWasm(name) { return loadWasm(name); }
export function _resetCacheForTests() { cache.clear(); }
```

### Adapter 2: randomness

`wx.getRandomValues` is asynchronous, while the library's `randomBytes` /
`randomScalarBelow` are synchronous. Pre-fetch 64 KiB at startup and hand out slices
synchronously; throw when the pool is exhausted (fail-closed):

```js
let pool = new Uint8Array(0);
let offset = 0;

export function primeRandom(length = 65536) {
  return new Promise((resolve, reject) => {
    if (typeof wx === 'undefined' || typeof wx.getRandomValues !== 'function') {
      reject(new Error('wx.getRandomValues requires base library 2.15.0+'));
      return;
    }
    wx.getRandomValues({
      length,
      success: (res) => {
        pool = new Uint8Array(res.randomValues);
        offset = 0;
        resolve();
      },
      fail: reject,
    });
  });
}

export function randomBytes(n) {
  if (!Number.isInteger(n) || n < 0 || n > 65536) {
    throw new RangeError(`randomBytes: length must be integer in [0, 65536], got ${n}`);
  }
  if (n > pool.length - offset) {
    throw new Error('random pool exhausted: await primeRandom() first');
  }
  const out = pool.slice(offset, offset + n);
  offset += n;
  return out;
}

export function randomScalarBelow(order) {
  if (order <= 1n) throw new RangeError('randomScalarBelow: order must be > 1');
  for (;;) {
    const buf = randomBytes(32);
    let candidate = 0n;
    for (let i = 0; i < 32; i++) candidate = (candidate << 8n) | BigInt(buf[i] ?? 0);
    if (candidate > 0n && candidate < order) return candidate;
  }
}
```

> **Call `await primeRandom()` before SM2 / SM9 key generation or signing.** SM3 / SM4 / ZUC
> do not need randomness.

### Adapter 3: text encoding

base64 needs **no** host polyfill: `runtime/convert.ts` has a built-in JS fallback
(`Buffer` → `btoa`/`atob` → pure JS), used automatically in Mini Programs.

`TextEncoder` / `TextDecoder` may still need a fallback (SM9 and SM2 key exchange use them).
The example ships one as
[`polyfills/textEncoding.js`](https://github.com/jktantan/sm-crypto-wasm/blob/main/examples/wechat-miniprogram/miniprogram/polyfills/textEncoding.js).
Import it in `app.js`:

```js
import './polyfills/textEncoding.js';
```

### Calling the library

```js
import * as sm3 from '../../vendor/sm-crypto-wasm/dist/sm3/index.js';
import * as sm2 from '../../vendor/sm-crypto-wasm/dist/sm2/index.js';
import { primeRandom } from '../../vendor/sm-crypto-wasm/dist/runtime/random.js';

export async function run() {
  await sm3.ensureLoaded();
  const digest = sm3.hash('616263');

  await sm2.ensureLoaded();
  await primeRandom(65536);           // fill the synchronous random pool
  const kp = await sm2.generateKeyPair();
  const sig = sm2.sign(kp.privateKeyPem, '616263');
  return { digest, verified: sm2.verify(kp.publicKeyPem, '616263', sig) };
}
```

Use subpath imports (`dist/sm3/index.js`, ...) rather than the aggregate
`dist/index.js`, so unused algorithms stay out of the JS module graph.

### Bundle size and trimming

Native Mini Programs do **not** tree-shake: every file under `miniprogramRoot` goes into the
code package, and `import * as` does not remove unused exports. The full example `vendor`
directory is about **297 KB**; trimming by algorithm gives:

| Preparation | Size |
| --- | ---: |
| All (default) | ~297 KB |
| `--algos sm3` | ~33 KB |
| `--algos zuc` | ~38 KB |
| `--algos sm3,sm4` | ~59 KB |
| `--algos sm2` (adds sm4/pem/common) | ~160 KB |
| `--algos sm9` (adds sm4/pem/common) | ~195 KB |

If you use Taro / uni-app / esbuild / Rollup / Webpack, let the bundler do real ESM
tree-shaking first:

- use **named imports**, not namespace imports:
  ```ts
  import { hash } from 'sm-crypto-wasm/sm3';   // shakeable
  import * as sm3 from 'sm-crypto-wasm/sm3';   // unused exports cannot be removed
  ```
- the package declares `"sideEffects": false`;
- `.wasm` is a separate binary and is **not** tree-shaken — copy the algorithms you use;
- keep the `loadWasm` / `random` shims on the Mini Program side.

Other options: enable "compress code" when uploading, put rarely used algorithms into a
subpackage, and use `.wasm.br` on base library 2.14+.

### FAQ

- **`WXWebAssembly is not defined`**: base library below 2.13.0.
- **`wx.getRandomValues is not defined`**: base library below 2.15.0.
- **`TextEncoder is not defined`**: text-encoding polyfill missing, or `app.js` was not copied.
- **Random pool exhausted**: call `await primeRandom()` before SM2 / SM9.
- **ZUC says reuse rejected**: the same `(key, iv, counter)` may only encrypt once; increment
  the counter or use a fresh IV.
- **WXWebAssembly missing in the simulator**: use "Real device debugging" or "Preview".

Full example:
[`examples/wechat-miniprogram`](https://github.com/jktantan/sm-crypto-wasm/tree/main/examples/wechat-miniprogram).

# 微信与小程序

`sm-crypto-wasm` 在两种微信环境里都能用，但接入方式不同：

| 环境 | 接入方式 |
| --- | --- |
| **微信内置浏览器（H5）** | 与普通浏览器一致，按打包器正常接入 |
| **微信小程序** | 需要小程序运行时适配：`WXWebAssembly` + `wx.getRandomValues` |

## 微信内置浏览器

微信内置浏览器是完整的 WebView，`fetch`、`WebAssembly`、`crypto.getRandomValues` 都可用，
按[跨运行时](/guide/cross-runtime)里的浏览器方式接入即可：

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');
```

注意事项：

- 页面必须是 **HTTPS**（或 localhost）才能拿到 `crypto.getRandomValues`；拿不到时库会
  fail-closed 直接抛错，不会退化成 `Math.random`；
- 用 Vite / Webpack / esbuild 等打包器，不要把 `dist/*.js` 用
  `<script type="module">` 直接加载。

## 微信小程序

小程序是另一套运行时，**不能直接使用浏览器版入口**：

- 没有 `fetch`，也不能用 `import.meta.url` 定位 wasm；
- 没有标准 `WebAssembly`，只有基础库 2.13.0+ 的 `WXWebAssembly`；
- 没有 `globalThis.crypto`，只有基础库 2.15.0+ 的 `wx.getRandomValues`（异步回调）；
- 没有 `btoa` / `atob`（库内已内置纯 JS 兜底）；旧基础库也没有 `TextEncoder` / `TextDecoder`。

### 快速开始

仓库里有一个可直接导入微信开发者工具的最小示例：

```bash
pnpm build
pnpm example:wechat:prepare
```

然后用微信开发者工具导入 `examples/wechat-miniprogram`，调试基础库选 **2.15.0+**。
示例会自动跑 SM2 / SM3 / SM4 / SM9 / ZUC 的自检，并把结果显示在页面上。

只保留用到的算法（原生小程序没有 tree-shaking，裁剪是最直接的减包方式）：

```bash
pnpm example:wechat:prepare --algos sm3,sm4
```

`sm2` / `sm9` 会自动带上它们依赖的 `sm4`、`pem`、`common`。

### 为什么不能「构建 npm」

小程序开发者工具的「构建 npm」不会读取 `package.json` 的 `browser` 字段，会解析到 Node 版
`loadWasm.js`（`node:fs`）和 `random.js`（`node:crypto`）；浏览器版里的
`import.meta.url` 也会让编译器报 `Cannot use 'import.meta' outside a module`，wasm 资源
也不会被自动搬进代码包。

正确做法是：把 `dist/` 复制进小程序代码包，用 `WXWebAssembly` 加载，并提供下面三个
适配层。示例的 `prepare` 脚本已经自动完成复制和覆盖。

### 适配点一：wasm 加载

小程序里 `WXWebAssembly.instantiate(path, imports)` 的第一个参数只接受**代码包内路径**
（`/` 开头）。把 `dist/` 放到 `miniprogram/vendor/sm-crypto-wasm/dist/`，然后用下面的
实现替换 `dist/runtime/loadWasm.js`：

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
        throw new Error('WXWebAssembly 不可用：请把基础库升到 2.13.0+');
      }
      // 返回值可能是 Instance，也可能是 { instance }，两种都兼容。
      const r = await WXWebAssembly.instantiate(path, ENV);
      const inst = r && r.instance ? r.instance : r;
      return Object.freeze({ exports: inst.exports, memory: inst.exports.memory });
    })();
    cache.set(name, p);
  }
  return p;
}

export function loadWasmSync() {
  throw new Error('loadWasmSync: 小程序里请先 await loadWasm(name)');
}

export function getCachedWasm(name) { return loadWasm(name); }
export function _resetCacheForTests() { cache.clear(); }
```

### 适配点二：随机数

`wx.getRandomValues` 是异步回调，而库的 `randomBytes` / `randomScalarBelow` 是同步 API。
启动时先预取 64 KiB 到内存池，业务调用从池里同步取用；池耗尽时抛错（fail-closed）：

```js
let pool = new Uint8Array(0);
let offset = 0;

export function primeRandom(length = 65536) {
  return new Promise((resolve, reject) => {
    if (typeof wx === 'undefined' || typeof wx.getRandomValues !== 'function') {
      reject(new Error('wx.getRandomValues 不可用：请把基础库升到 2.15.0+'));
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
    throw new Error('随机数池不足：请先 await primeRandom()');
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

> **SM2 / SM9 生成密钥、签名之前必须 `await primeRandom()`**。SM3 / SM4 / ZUC 不需要随机数。

### 适配点三：文本编码

base64 **不需要**宿主 polyfill：库的 `runtime/convert.ts` 已内置纯 JS 兜底
（`Buffer` → `btoa`/`atob` → 纯 JS），小程序里会自动走最后一级。

`TextEncoder` / `TextDecoder` 仍可能需要兜底（SM9 和 SM2 密钥交换会用到）。示例实现见
[`polyfills/textEncoding.js`](https://github.com/jktantan/sm-crypto-wasm/blob/main/examples/wechat-miniprogram/miniprogram/polyfills/textEncoding.js)。
在 `app.js` 里引入：

```js
import './polyfills/textEncoding.js';
```

### 页面调用

```js
import * as sm3 from '../../vendor/sm-crypto-wasm/dist/sm3/index.js';
import * as sm2 from '../../vendor/sm-crypto-wasm/dist/sm2/index.js';
import { primeRandom } from '../../vendor/sm-crypto-wasm/dist/runtime/random.js';

export async function run() {
  await sm3.ensureLoaded();
  const digest = sm3.hash('616263');

  await sm2.ensureLoaded();
  await primeRandom(65536);           // 关键：填同步随机数池
  const kp = await sm2.generateKeyPair();
  const sig = sm2.sign(kp.privateKeyPem, '616263');
  return { digest, verified: sm2.verify(kp.publicKeyPem, '616263', sig) };
}
```

页面里按子路径导入（`dist/sm3/index.js` 等），不要用聚合入口 `dist/index.js`，这样
未用到的算法不会出现在 JS 模块图里。

### 体积与裁剪

原生小程序**不做 tree-shaking**：`miniprogramRoot` 下的文件都会进代码包，`import * as`
也不会让编译器删掉未使用的导出。示例的全量 `vendor` 约 **297 KB**，按算法裁剪后：

| 准备方式 | 生成体积 |
| --- | ---: |
| 全部（默认） | 约 297 KB |
| `--algos sm3` | 约 33 KB |
| `--algos zuc` | 约 38 KB |
| `--algos sm3,sm4` | 约 59 KB |
| `--algos sm2`（自动补 sm4/pem/common） | 约 160 KB |
| `--algos sm9`（自动补 sm4/pem/common） | 约 195 KB |

如果使用 Taro / uni-app / 自建 esbuild / Rollup / Webpack，可以让打包器先做真正的 ESM
tree-shaking：

- **用具名导入**，不要用命名空间导入：
  ```ts
  import { hash } from 'sm-crypto-wasm/sm3';   // 可以摇树
  import * as sm3 from 'sm-crypto-wasm/sm3';   // 不能删未使用导出
  ```
- 包内已声明 `"sideEffects": false`；
- `.wasm` 是独立二进制，不参与 JS 摇树，仍要按算法复制到代码包；
- 小程序侧仍需保留上面的 `loadWasm` / `random` shims。

其他手段：上传时勾选「压缩代码」、把不常用算法放独立分包、基础库 2.14+ 使用 `.wasm.br`。

### 常见问题

- **`WXWebAssembly is not defined`**：基础库低于 2.13.0，升级基础库/微信版本。
- **`wx.getRandomValues is not defined`**：基础库低于 2.15.0。
- **`TextEncoder is not defined`**：没有引入文本编码 polyfill，或只复制了页面没复制 `app.js`。
- **`随机数池不足`**：SM2/SM9 调用前没有 `await primeRandom()`，或预取量太小。
- **ZUC 报「(key, iv, counter) 复用拒绝」**：同一组 `(key, iv, counter)` 只能加密一次；
  让 counter 随数据包递增，或每次使用新的 IV。
- **模拟器里 WXWebAssembly 不可用**：换「真机调试」或「预览」扫码。

完整的示例代码见
[`examples/wechat-miniprogram`](https://github.com/jktantan/sm-crypto-wasm/tree/main/examples/wechat-miniprogram)。

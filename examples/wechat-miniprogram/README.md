# sm-crypto-wasm · 微信小程序示例

在**原生微信小程序**里跑 `sm-crypto-wasm` 的最小可运行示例。用微信开发者工具导入
本目录（`examples/wechat-miniprogram`）即可在模拟器和真机上测试 SM2 / SM3 / SM4 /
SM9 / ZUC。

> 注意：微信内置浏览器（手机微信打开网页）和小程序是两套运行时。浏览器版
> `loadWasm.browser.js` 依赖 `fetch` + `import.meta.url`，`random.browser.js` 依赖
> `globalThis.crypto`；小程序里这些都不存在，所以本示例用两份小程序版 runtime
> 替换它们。

## 前置条件

- 仓库根目录已执行 `pnpm install && pnpm build`（需要 `dist/` 和 5 个 `.wasm`）；
- 微信开发者工具，调试基础库 **≥ 2.15.0**（`WXWebAssembly` 需要 2.13.0+，
  `wx.getRandomValues` 需要 2.15.0+）。

## 准备 wasm 与 runtime

在仓库根目录执行：

```bash
pnpm example:wechat:prepare
```

脚本会把 `dist/` 复制到 `miniprogram/vendor/sm-crypto-wasm/dist/`，并用
`miniprogram/shims/` 下的两份小程序实现覆盖 `runtime/loadWasm.js` 与
`runtime/random.js`。`vendor/` 是生成产物，已在 `.gitignore` 中忽略。

只准备用到的算法（原生小程序没有 tree-shaking，这一步就是最有效的裁剪）：

```bash
pnpm example:wechat:prepare --algos sm3,sm4
# 或
SM_ALGOS=sm3,sm4 pnpm example:wechat:prepare
```

`sm2` / `sm9` 会自动带上它们依赖的 `sm4`、`pem`、`common`。

## 用开发者工具打开

1. 微信开发者工具 → 导入项目 → 选择 `examples/wechat-miniprogram`；
2. AppID 选「测试号」（`project.config.json` 里是 `touristappid`）；
   > 开发者工具可能把真实 AppID 回写到 `project.config.json`。提交前请检查并改回
   > `touristappid`，真实 AppID 不要进仓库。
3. 详情 → 本地设置 → 调试基础库选 **2.15.0 或更高**；
4. 编译。首页会自动跑一遍测试，结果显示在页面上。

模拟器里如果 `WXWebAssembly` 不可用，直接点「预览」扫码，或使用「真机调试」。

## 测试内容

| 算法 | 测试项 |
|---|---|
| SM3 | `hash('616263')` 与标准向量比对 |
| SM4 | CBC 往返、GCM 往返 |
| ZUC | EEA3 加解密往返 |
| SM2 | 生成密钥、签名/验签、加解密 |
| SM9 | 生成签名主密钥、签名/验签（需要 `TextEncoder`，`app.js` 里已 polyfill） |

真机「预览」默认看不到 `console`，页面会把每一行 PASS/FAIL 渲染出来；也可以开
「真机调试」看 console。

## 包体积与裁剪（tree-shaking）

**原生小程序不做 tree-shaking**：`miniprogramRoot` 下的文件都会进代码包，`import * as sm2`
也不会让编译器删掉未使用的导出。能进包的东西只有两招：少放文件、或者先让打包器摇树再放
bundle。

### 方案一：按算法裁剪（推荐，零依赖）

`prepare` 支持 `--algos`，只复制选中的算法目录和运行时：

```bash
pnpm example:wechat:prepare --algos sm3        # 只保留 SM3
pnpm example:wechat:prepare --algos sm3,sm4    # SM3 + SM4
pnpm example:wechat:prepare --algos sm2        # 自动带 sm4 / pem / common
```

| 准备方式 | 生成体积 |
|---|---:|
| 全部（默认） | 约 297 KB |
| `--algos sm3` | 约 33 KB |
| `--algos sm3,sm4` | 约 59 KB |
| `--algos zuc` | 约 38 KB |
| `--algos sm2` | 约 160 KB |
| `--algos sm9` | 约 195 KB |

裁剪后要**同步删掉页面里未选算法的 `import` 和测试块**（示例页面默认测试全部 5 个算法），
否则编译期会找不到模块。业务页面通常只 import 自己用到的算法，天然匹配。

### 方案二：用打包器做真正的 ESM tree-shaking

原生小程序没有打包器；如果你用 Taro / uni-app / 自建 esbuild / Rollup / Webpack，可以
先打包再放进小程序：

- 用具名导入，不要用命名空间导入，否则打包器无法删掉未使用的导出：
  ```ts
  // 可以摇树
  import { hash } from 'sm-crypto-wasm/sm3';
  // 不能摇树（整个 namespace 都可能被使用）
  import * as sm3 from 'sm-crypto-wasm/sm3';
  ```
- 包内已声明 `"sideEffects": false`，ESM 入口可被正常摇树；
- **`.wasm` 是独立二进制，不参与 JS 摇树**：仍要按算法把 `.wasm` 复制到代码包，
  并保留本示例的 `loadWasm` / `random` shims（或等价实现）；
- 聚合入口 `dist/index.js` 会 re-export 全部算法，体积敏感时直接用子路径导入。

其他减小包体的手段：

- 微信开发者工具上传时勾选「压缩代码」；
- 只有少数算法常用时，把它们和 wasm 放独立分包，按需下载；
- 基础库 2.14+ 支持 `.wasm.br`（brotli 压缩的 wasm），但代码包本身也会压缩，收益视场景而定；
- `app.json` 的 `lazyCodeLoading` 只影响自定义组件注入，**不解决代码包体积**。

## 为什么是复制 dist，而不是「构建 npm」

- 小程序「构建 npm」不会读取 `package.json` 的 `browser` 字段，会解析到 Node 版
  `loadWasm.js`（`node:fs`）和 `random.js`（`node:crypto`）；
- 浏览器版里的 `new URL(..., import.meta.url)` 在微信编译器里会报
  `Cannot use 'import.meta' outside a module`；
- wasm 资源不会被自动搬进小程序代码包。

所以示例直接把 `dist` 放进代码包，并用 `WXWebAssembly.instantiate('/代码包路径')`
加载。页面按子路径导入（`dist/sm3/index.js` 等），避开聚合入口里的
`export * as sm2` 语法对旧版开发者工具的兼容性问题。

## 两个运行时适配点

base64 不需要宿主 polyfill：库的 `runtime/convert.ts` 已内置纯 JS 兜底
（`Buffer` → `btoa`/`atob` → 纯 JS），小程序里会自动走最后一级。下面两个适配点
才是小程序运行时真正需要补的。

### wasm 加载：`miniprogram/shims/loadWasm.js`

- 小程序没有 `fetch` / `WebAssembly.Module`，改用全局 `WXWebAssembly`；
- `WXWebAssembly.instantiate(path, imports)` 的第一个参数只接受**代码包内路径**
  （本示例是 `/vendor/sm-crypto-wasm/dist/<algo>/<algo>.wasm`）；
- 不同基础库/平台上返回值可能是 `Instance` 或 `{ instance }`，shim 两种都兼容。

### 随机数：`miniprogram/shims/random.js`

`wx.getRandomValues` 是**异步回调**，而库的 `randomBytes` / `randomScalarBelow`
是同步 API，所以启动时用 `primeRandom()` 预取 64 KiB 到内存池，之后同步取用。
池耗尽时直接抛错（fail-closed），不会退化到 `Math.random`。

因此 **SM2 生成密钥/签名、SM9 生成密钥之前必须 `await primeRandom()`**。本示例在
SM2 测试块开始前调用了一次；如果你的业务代码在别处用 SM2/SM9，请在自己的启动流程
里同样预先调用。

## 常见问题

- **`WXWebAssembly is not defined`**：基础库太低。升到 2.13.0+（随机数需要 2.15.0+）。
- **`随机数池不足`**：SM2/SM9 调用前没有 `await primeRandom()`，或预取量太小。
- **`TextEncoder is not defined`**：SM9 或 SM2 密钥交换需要。`app.js` 已引入
  `polyfills/textEncoding.js`；如果你只复制了页面而没复制 `app.js`，请手动引入。
- **ZUC 报「(key, iv, counter) 复用拒绝」**：ZUC 的复用保护是模块级状态，同一组
  `(key, iv, counter)` 只能加密一次。示例每次运行会递增 `counter`；业务代码中请让
  `counter` 随数据包递增，或每次使用新的 IV。
- **包体积**：5 个 wasm 合计约 145 KB（sm2 38K、sm3 6.6K、sm4 14.5K、sm9 78K、
  zuc 6.6K），主包 2 MB 限制下没有问题。
- **wasm 放 CDN**：不推荐。`WXWebAssembly.instantiate` 只接受代码包路径；远程 wasm
  需要先下载到本地文件，再按本地路径加载，且要配置 `downloadFile` 合法域名。
- **iOS**：`WXWebAssembly` 不支持导出 `Global`；本库的 wasm 只导出函数和 `memory`，
  不受影响。

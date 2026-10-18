---
layout: home

hero:
  name: sm-crypto-wasm
  text: 国密算法，编译进 WebAssembly
  tagline: SM2 / SM3 / SM4 / SM9 / ZUC —— 同一份 API 跑在 Node 18+ 与现代浏览器，按算法分包、按需懒加载。
  image:
    src: /logo.svg
    alt: sm-crypto-wasm
  actions:
    - theme: brand
      text: 快速开始
      link: /guide/getting-started
    - theme: alt
      text: 算法 API
      link: /algorithms/sm3
    - theme: alt
      text: GitHub
      link: https://github.com/jktantan/sm-crypto-wasm

features:
  - title: 快一个数量级
    details: 椭圆曲线与双线性对跑在 WASM 里。SM4 六种模式比纯 JS 参考实现快 3.6–11.2×，SM2 快 1.8–7.6×，SM3 快 3.1–3.5×、ZUC 快 2.3×。
  - title: 零工具链
    details: 发布物是 .wasm 加一层薄 TS 胶水。使用者不需要 node-gyp、Rust 或编译器，五个算法按需下载。
  - title: 跨运行时
    details: Node 18+、现代浏览器、Web Worker 用同一份 API。Deno / Bun 走 Node 同路径。
  - title: 国标对齐
    details: 实现遵循 GM/T 0003 / 0004 / 0002 / 0044 / 0001 系列，以官方向量、OpenSSL、GmSSL、gmkitx 交叉验证。
  - title: 每种算法都有 Playground
    details: 每个算法页都可以在浏览器里真实加载 wasm、填参数、点运行看结果 —— 出错时库抛出的错误类型也照实显示。
  - title: 输入嗅探
    details: hex / base64 / PEM / Uint8Array 自动识别，输出默认 hex，省掉一层手写编解码。
---

## 从这里开始

- **[安装与快速开始](/guide/getting-started)** —— 装上包，五行代码跑通第一个摘要。
- **[SM3](/algorithms/sm3)** · **[SM4](/algorithms/sm4)** · **[SM2](/algorithms/sm2)** · **[SM9](/algorithms/sm9)** · **[ZUC](/algorithms/zuc)** —— 每个算法一页：完整参数表、用法示例、可直接运行的 Playground。
- **[只用一个算法](/guide/subpath-imports)** —— 体积敏感时用子路径导入，绕开聚合入口。
- **[错误处理](/guide/error-handling)** —— 哪些错误是密钥问题、哪些是密文问题，怎么分流。
- **[性能](/performance)** —— 每个公开操作的实测数字，以及为什么这么实现。

::: tip 关于这个库的形状
每个算法是一个独立命名空间，各自暴露 `ensureLoaded()` 与业务函数。wasm 按算法分包，
**调用哪个算法才加载哪个 wasm**；首次使用前 `await algo.ensureLoaded()`，之后所有业务
函数都是同步的。
:::

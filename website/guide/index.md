# 简介

`sm-crypto-wasm` 把国密算法的热点部分编译进 **WebAssembly**：前端与 Node 后端用同一份
API 就能调用 **SM2 / SM3 / SM4 / SM9 / ZUC**，不需要懂 ASN.1、大数运算或 WASM 桥接。

AssemblyScript 编译成 `.wasm`，外面只包一层很薄的 TypeScript 胶水。相比纯 JS 实现，
椭圆曲线与双线性对这类热点快一个数量级；相比 C++ / Rust 实现，分发出 npm 包不需要
用户装任何编译工具链。

## 五个算法

| 算法 | 标准 | 是什么 | 文档 |
| --- | --- | --- | --- |
| **SM3** | GM/T 0004-2012 | 256 位杂凑，与 SHA-256 同级别 | [SM3](/algorithms/sm3) |
| **SM4** | GM/T 0002-2012 | 128 位分组密码，六种模式 | [SM4](/algorithms/sm4) |
| **SM2** | GM/T 0003-2012 | 椭圆曲线公钥密码（签名 / 加密 / KEM / 混合加密 / 密钥交换） | [SM2](/algorithms/sm2) |
| **SM9** | GM/T 0044-2016 | 标识密码（签发 / 加密 / KEM / 混合加密 / 密钥交换） | [SM9](/algorithms/sm9) |
| **ZUC** | GM/T 0001-2012 | 序列密码，EEA3 机密性 + EIA3 完整性 | [ZUC](/algorithms/zuc) |

## 设计上的几个取舍

- **按算法分包、懒加载**：每个算法一个 `.wasm`，调用哪个才加载哪个。只做摘要的页面
  不会为 SM9 的 pairing 付出体积代价。
- **同步业务 API + 异步预热**：`ensureLoaded()` 是异步的（WASM 实例化必须异步），
  之后所有业务函数都是同步的 —— 调用方不必给每一处加密都套 `await`。
- **随机数永远走宿主**：`crypto.getRandomValues` / `crypto.randomBytes`。
  本库**不内置 RNG**，也不会把私钥或中间状态写到磁盘、日志。
- **输入嗅探**：`hex` / `base64` / `PEM` / `Uint8Array` 自动识别，输出默认 hex。
- **错误分层**：所有"因输入而拒绝"的错误都是 `SmCryptoError` 的子类，分**密钥支**与
  **密文支**两条；参数类型本身就错的（`TypeError` / `RangeError`）保留宿主原生类型。

## 不在范围里

以下是有意不做的（保持包小而聚焦）：

- **ZUC-256**（GM/T 0001.1-2021）—— 与 ZUC-128 不是参数化关系，是另一套算法；
- WebCrypto（`crypto.subtle`）风格的适配层；
- 国密机 / HSM / PKCS#11 句柄；
- X.509 / PKCS#7 / CMS 协议封装；
- Cloudflare Workers / Vercel Edge 这类"严格流式 WASM"环境。

## 接下来

- [**安装与快速开始**](/guide/getting-started) —— 装上包，跑通第一段代码；
- [**性能**](/performance) —— 每个公开操作的实测数字与实现取舍。

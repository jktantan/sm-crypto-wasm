# 性能

热点（大整数模运算、hash 压缩函数、分组密码轮函数、双线性对）在 WASM 内执行。
下表覆盖每个算法的**全部公开操作**，`gmkitx` 一列是同机、同参数、同消息的纯 JS 参考实现
（**它没有的操作留 `—`**）。实测环境 AMD Ryzen 7 7800X3D / Node 24.15 / Windows 11，
可用 `pnpm bench` 复现。

| 算法 | 操作 | sm-crypto-wasm | 纯 JS 参考（gmkitx） | 对比 |
|---|---|---|---|---|
| SM3 | hash 32 B / 1 KB / 64 KB | 1.04 µs / 6.27 µs / 330 µs | 13.7 µs（1 KB） | 快 2.2× |
| SM3 | hmac 1 KB | 10.1 µs | 17.9 µs | 快 1.8× |
| SM4 | ECB 16 B / 1 KB | 0.94 µs / 6.98 µs | 37.3 µs（1 KB） | 快 5.3× |
| SM4 | CBC 1 KB | 10.5 µs | 41.6 µs | 快 4.0× |
| SM4 | CTR 1 KB | 7.43 µs | 36.5 µs | 快 4.9× |
| SM4 | CFB 1 KB | 10.0 µs | 37.9 µs | 快 3.8× |
| SM4 | OFB 1 KB | 9.98 µs | 36.3 µs | 快 3.6× |
| SM4 | GCM 1 KB | 19.8 µs | 221 µs | 快 11.2× |
| SM2 | 密钥对生成 | 151 µs | — | — |
| SM2 | 公钥派生 | 110 µs | 197 µs | 快 1.8× |
| SM2 | 签名 64 B | 142 µs | 446 µs | 快 3.1× |
| SM2 | 验签 64 B | 402 µs | 2.85 ms | 快 7.1× |
| SM2 | 加密 64 B | 499 µs | 2.96 ms | 快 5.9× |
| SM2 | 解密 64 B | 343 µs | 2.59 ms | 快 7.6× |
| SM2 | 密钥交换（完整 A↔B） | 1.52 ms | 11.4 ms | 快 7.5× |
| SM9 | 主密钥对生成（签名 / 加密） | 2.07 / 1.73 ms | — | — |
| SM9 | 主公钥派生（签名 / 加密） | 97.1 / 49.1 µs | — | — |
| SM9 | 用户公钥派生 | 563 µs | — | — |
| SM9 | 签名 32 B | 4.11 ms | — | — |
| SM9 | 验签 32 B | 8.00 ms | — | — |
| SM9 | 加密 32 B | 3.69 ms | — | — |
| SM9 | 解密 32 B | 5.40 ms | — | — |
| SM9 | KEM 封装 / 解封装 | 3.42 / 4.92 ms | — | — |
| SM9 | 密钥交换（完整 A↔B） | 19.6 ms | — | — |
| ZUC | EEA3 加密 1 KB | 9.07 µs | 20.5 µs | 快 2.3× |
| ZUC | EEA3 密钥流 1 KB | 6.15 µs | — | — |
| ZUC | EIA3 MAC 1 KB | 11.2 µs | — | — |

::: warning SM2 那一行的波动
SM2 是 TS 门面层（签名走公钥派生缓存，加密每次仍要做 hex 与曲线点编解码、并调用宿主
CSPRNG），实测在多次运行之间波动可达 **±20%**，远大于 SM3 / SM4 / SM9 / ZUC。
上表 SM2 的数字取自同一次运行（`wasm` 与 `gmkitx` 两列同源）。
:::

## 为什么是这个形状

- **SM3 / SM4 / ZUC 已到顶**：瓶颈是算法结构与 wasm 指令集共同封死的 ——
  SM3 是 MD 链式（块间无法并行）且压缩函数 64 轮串行；SM4 与 ZUC 都卡在
  **8-bit S 盒查表**上，而 WebAssembly 不暴露 ARMv8 的 `SM4E` 或 AES-NI 这类
  用电路做 S 盒的指令。SM4 一度试过 `v128` SIMD，实测慢于 8 块标量交错（每块 4 条
  独立依赖链，由乱序执行盖住 L1 延迟），已全部移除。
- **SM4 的 CFB / OFB 曾经比纯 JS 慢**：这两个模式原先在 TS 侧逐块调用 wasm（1 KB 要
  64 次跨界）。补上批量导出后降到 10 µs 一带，反过来快 3.6~3.8×。
- **SM2 的计算层做过八件事**（Solinas 归约、Comba 平方、comb/wNAF 标量乘、点运算原地化、
  混合坐标、验签联合标量乘、局部字级求逆、`sign` 的公钥派生缓存），细节见仓库里的
  [性能上限评估](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/performance-ceiling.md)。
- **SM9 由 pairing 主导**：基域 Fp 改用 Montgomery 域（CIOS）后，单次模乘 179 → 98 ns，
  端到端 sign / verify / encrypt / decrypt / KEM / 密钥交换全面快 **1.6~1.8×**。
  纯 JS 生态没有可比的 SM9 实现（pairing 成本过高），故只给本库的绝对耗时。
- **hex 编解码**：改走 `Buffer.toString('hex')`（浏览器回落查表）后编码快约 27×；
  输入侧把"正则校验 + 解析"合并成一趟。两者合计让 hex 入参的 SM3 / SM4 / ZUC 端到端
  快 **27~32%**。

::: tip 数字随版本与机器变化
以上为特定机器上的实测值，请以本机 `pnpm bench` 为准。完整的实验记录与"还剩多少空间"
的评估见仓库 [`docs/performance-ceiling.md`](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/performance-ceiling.md)。
:::

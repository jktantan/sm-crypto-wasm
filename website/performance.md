# 性能

热点（大整数模运算、hash 压缩函数、分组密码轮函数、双线性对）在 WASM 内执行。
下表覆盖每个算法的**全部公开操作**，`gmkitx` 一列是同机、同参数、同消息的纯 JS 参考实现
（**它没有的操作留 `—`**）。实测环境 AMD Ryzen 7 7800X3D / Node 24.15 / Windows 11，
可用 `pnpm bench` 复现。

| 算法 | 操作 | sm-crypto-wasm | 纯 JS 参考（gmkitx） | 对比 |
|---|---|---|---|---|
| SM3 | hash 32 B / 1 KB / 64 KB | 872 ns / 4.75 µs / 245 µs | 14.7 µs（1 KB） | 快 3.1× |
| SM3 | hmac 1 KB | 5.58 µs | 19.4 µs | 快 3.5× |
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
| SM2 | KEM 封装 / 解封装（16 B key） | 496 / 328 µs | — | — |
| SM2 | hybrid 加密 / 解密 1 MB | 37.3 / 36.4 ms | — | — |
| SM2 | 密钥交换（完整 A↔B） | 1.52 ms | 11.4 ms | 快 7.5× |
| SM9 | 主密钥对生成（签名 / 加密） | 2.07 / 1.73 ms | — | — |
| SM9 | 主公钥派生（签名 / 加密） | 97.1 / 49.1 µs | — | — |
| SM9 | 用户公钥派生 | 563 µs | — | — |
| SM9 | 签名 32 B | 4.11 ms | — | — |
| SM9 | 验签 32 B | 8.00 ms | — | — |
| SM9 | 加密 32 B | 3.69 ms | — | — |
| SM9 | 解密 32 B | 5.40 ms | — | — |
| SM9 | KEM 封装 / 解封装 | 3.42 / 4.92 ms | — | — |
| SM9 | hybrid 加密 / 解密 10 KB | 3.21 / 4.77 ms | — | — |
| SM9 | 密钥交换（完整 A↔B） | 19.6 ms | — | — |
| ZUC | EEA3 加密 1 KB | 9.07 µs | 20.5 µs | 快 2.3× |
| ZUC | EEA3 密钥流 1 KB | 6.15 µs | — | — |
| ZUC | EIA3 MAC 1 KB | 11.2 µs | — | — |

::: warning SM2 那一行的波动
SM2 是 TS 门面层（签名走公钥派生缓存，加密每次仍要做 hex 与曲线点编解码、并调用宿主
CSPRNG），实测在多次运行之间波动可达 **±20%**，远大于 SM3 / SM4 / SM9 / ZUC。
上表 SM2 的数字取自同一次运行（`wasm` 与 `gmkitx` 两列同源）。
:::

::: tip SM2 固定公钥：再快 1.9×
`await sm2.preparePublicKey(pub)` 为公钥预计算 comb 表后，`encrypt` 的 `k·P` 从
wNAF（256 次倍点）切到 comb（52 次倍点）：64 B 加密 **486 → 260 µs**（本机 mitata）。
建表约 280 µs，**约 1.2 次加密回本**。缓存默认 **8 槽 + LRU**，8 把公钥轮换加密与
单把命中同档；只有显式 prepare 才建表，未命中自动回退 wNAF，不会变慢。
`kemEncrypt` / `hybridEncrypt` 走同一路径。bench 项：`encrypt 64B (prepared pk)`、
`encrypt 64B (8 prepared keys, rotating)`。
:::

## 与另外两个国密库横向对比

上表的参照物是纯 JS 的 `gmkitx`。若换成**另外两个真实的国密库**，在完全相同的参数、
消息与密钥下：

- **Cubelrti/sm-crypto-wasm** —— Rust + `wasm-bindgen` 编译到 WebAssembly（⚠️ 与本库
  同名，但不是同一个项目）；
- **sm-crypto-v2** —— TypeScript + [noble-curves](https://github.com/paulmillr/noble-curves)，
  当前纯 JS 生态里最快的一档。

三方各自使用**源码的 release 构建**，基准内置自检会逐字节比对三方输出（SM3 / SM4 必须
完全相等，SM2 交叉验签必须通过），不一致直接抛错。

**⚠️ Cubelrti 那一列给两个数字。** 它的 `Cargo.toml` 把 release 配置写成了**体积优先**
（`opt-level = "z"` + `wasm-opt = ["-Oz"]`），它官方提交的预构建产物正是这一版
（175 KB，与我按同配置构建的 177 KB 基本一致）。但若改成**速度优先**
（`opt-level = 3` + `wasm-opt = ["-O3"]`，产物 263 KB），它会快 **26%\~53%**（SM3 达 53%）。
所以两个口径都给：默认配置是"你拿到的是什么样"，`-O3` 才是"这套 Rust 代码的上限"。
倍数列为**本库比它快多少倍**。

| 操作 | sm-crypto-wasm | Cubelrti<br>默认 (-Oz) | Cubelrti<br>-O3 | sm-crypto-v2 | vs Cubelrti<br>(-Oz) | vs Cubelrti<br>(-O3) | vs v2 |
|---|---|---|---|---|---|---|---|
| SM2 签名 64 B | **143.6 µs** | 4.51 ms | 3.03 ms | 297 µs | 31.4× | 21.1× | 2.07× |
| SM2 验签 64 B | **406.6 µs** | 4.49 ms | 3.05 ms | 2.83 ms | 11.0× | 7.50× | 6.96× |
| SM2 加密 64 B | **506.5 µs** | 4.43 ms | 2.95 ms | 2.67 ms | 8.75× | 5.82× | 5.27× |
| SM2 解密 64 B | **337.0 µs** | 2.26 ms | 1.51 ms | 2.49 ms | 6.71× | 4.48× | 7.39× |
| SM2 密钥对生成 | **147.8 µs** | 2.25 ms | 1.54 ms | 210 µs | 15.2× | 10.4× | 1.42× |
| SM3 hash 1 KB | **4.75 µs** | 24.7 µs | 11.5 µs | 6.44 µs | 5.19× | 2.42× | 1.36× |
| SM3 hmac 1 KB | **5.61 µs** | 29.3 µs | 13.7 µs | 9.27 µs | 5.22× | 2.44× | 1.65× |
| SM4 ECB 加密 1 KB | **6.78 µs** | 12.6 µs | 8.83 µs | 12.6 µs | 1.85× | 1.30× | 1.85× |
| SM4 CBC 加密 1 KB | **10.4 µs** | 19.5 µs | 12.5 µs | 14.9 µs | 1.88× | 1.21× | 1.44× |
| SM4 CBC 解密 1 KB | **10.8 µs** | 22.2 µs | 16.3 µs | 14.0 µs | 2.06× | 1.51× | 1.30× |
| SM4 CTR 加密 1 KB | **7.09 µs** | 12.6 µs | 10.4 µs | —（未实现） | 1.77× | 1.46× | — |
| SM4 GCM 加密 1 KB | **19.9 µs** | 27.5 µs | 19.7 µs | 30.4 µs | 1.39× | **0.99×** | 1.53× |

注意最后一行：**换成 -O3 后，SM4-GCM 上 Cubelrti 与本库基本打平**。逐项看，SM4 那几个
在 -O3 下也都收敛到 1.2\~1.5× 了；真正拉开量级的只有 SM2（结构性差距，见下）和 SM3。

复现：

```bash
bash bench/build-cubelrti-wasm.sh                # 上游默认配置（-Oz）
SM_BUILD_O3=1 bash bench/build-cubelrti-wasm.sh  # 速度优先（-O3），供上面第 4 列
pnpm bench:cubelrti
```

::: details 三点值得注意的观察
- **Rust→WASM 未必更快**：Cubelrti 的 SM2 全线慢于纯 JS 的 `sm-crypto-v2`（签名慢 15×）。
  它的热点用 `num-bigint`（通用大整数、堆分配）而非定宽字段运算；每次 API 调用都重新
  派生公钥（其 `keypair` 2.20 ms ≈ `sign` 4.56 ms 的一半，说明 sign 里做了两次标量乘）；
  另外每个导出函数内部都执行一次 `console::log_1`。
- **`sm-crypto-v2` 是纯 JS 的天花板**：SM4 上它与 Cubelrti 基本打平，SM3 只比本库慢 1.35×。
- **批量签名有专门通道**：`sm2.createSignaturePointPool(n)` 把固定基点标量乘（占单次
  签名 56%）提前摊销，命中时单次签名从 141 µs 降到 **24 µs（5.9×）**。
:::

## 为什么是这个形状

- **SM3 又挤出一轮**：`compress` 原本每块单独跑一遍 64 store + 128 load 去物化
  W′（`W[j] ^ W[j+4]`），改为在轮循环里就地算；轮循环改用指针递增；填充缓冲改模块级复用
  （原先每次 `hash` 都 `new StaticArray<u8>(totalLen)` 并**清零整个长度**，而真正需要清零的
  只有 padding 区）。**HMAC 整体下沉进 WASM**（原先 ipad/opad 拼接与两次摘要调用都在
  JS 层，4 次跨边界 + 3 个临时数组），并新增两段输入接口让 `ipad ‖ msg` 直接参与填充。
  合计 hash 快 **26%**、hmac 快 **45%**。
- **SM4 / ZUC 卡在 S 盒**：两者都受限于 **8-bit S 盒查表**，而 WebAssembly 不暴露 ARMv8 的
  `SM4E` 或 AES-NI 这类用电路做 S 盒的指令。SM4 一度试过 `v128` SIMD，实测慢于 8 块标量
  交错（每块 4 条独立依赖链，由乱序执行盖住 L1 延迟），已全部移除。SM3 则是 MD 链式
  （块间无法并行）+ 64 轮串行压缩函数。
- **SM4 的 CFB / OFB 曾经比纯 JS 慢**：这两个模式原先在 TS 侧逐块调用 wasm（1 KB 要
  64 次跨界）。补上批量导出后降到 10 µs 一带，反过来快 3.6\~3.8×。
- **SM2 的计算层做过九件事**（Solinas 归约、Comba 平方、comb/wNAF 标量乘、点运算原地化、
  混合坐标、验签联合标量乘、局部字级求逆、`sign` 的公钥派生缓存、固定公钥 comb 表），细节见仓库里的
  [性能上限评估](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/performance-ceiling.md)。
- **SM9 由 pairing 主导**：基域 Fp 改用 Montgomery 域（CIOS）后，单次模乘 179 → 98 ns，
  端到端 sign / verify / encrypt / decrypt / KEM / 密钥交换全面快 **1.6\~1.8×**。
  纯 JS 生态没有可比的 SM9 实现（pairing 成本过高），故只给本库的绝对耗时。
- **hex 编解码**：改走 `Buffer.toString('hex')`（浏览器回落查表）后编码快约 27×；
  输入侧把"正则校验 + 解析"合并成一趟。两者合计让 hex 入参的 SM3 / SM4 / ZUC 端到端
  快 **27\~32%**。

::: tip 数字随版本与机器变化
以上为特定机器上的实测值，请以本机 `pnpm bench` / `pnpm bench:cubelrti` 为准。
完整的实验记录与"还剩多少空间"的评估见仓库
[`docs/performance-ceiling.md`](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/performance-ceiling.md)。
:::

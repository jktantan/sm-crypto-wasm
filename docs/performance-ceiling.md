# 性能上限评估：五个算法还剩多少空间

- 日期：2026-10-14
- 环境：AMD Ryzen 7 7800X3D / Node 24.15 / Windows 11
- 触发：一轮优化收尾后核对"是否已经到顶"，把结论固化下来，避免日后重复铺开同一批实验。
- 复现：`pnpm bench`（全量）；本文的 SM2 单操作数字来自附录 A / 附录 B 的临时 probe。
- 同日落地：第二节（SM2 门面层公钥缓存）与第三节（SM9 基域改 Montgomery 域）均已
  实装、实测；README 的三语性能表已按重跑结果同步。其余条目仍为评估结论。

## 结论速览

| 算法 | 状态 | 卡点 | 剩余空间 |
|---|---|---|---|
| SM3 | **到顶** | MD 链式 + 64 轮压缩函数串行 | 仅多消息批量并行（公开 API 用不上） |
| SM4 | **到顶** | 8-bit S 盒查表，wasm 无 SM4E/AES-NI | 需 wasm 暴露硬件指令 |
| ZUC | **到顶** | LFSR 字级串行 + F 函数 S 盒查表 | 同 SM4，受同一限制 |
| SM2 计算层 | **到顶（默认路径）** | 已 comb/wNAF/Solinas/混合坐标/局部字级求逆 | 个位数百分比 |
| SM2 固定公钥 | **已落地** | `encrypt` 的 `k·P` 每次重建 wNAF 表（256 次倍点） | `preparePublicKey` 后 2.1×（底层）/ 1.9×（端到端），建表 280 µs |
| SM2 门面层 | **已落地** | 每操作重复派生公钥与编解码 | 缓存公钥：sign **252 → 138 µs（−46%）**；可用 `configurePublicKeyCache` 关掉 |
| SM9 | **已落地** | 基域 p 原走 Barrett 归约 | 单次模乘 179 → 98 ns、端到端 1.6~1.8×；只剩百分比级余量 |
| SM9 标量乘 | **已落地** | 固定基点原走 wNAF（comb 仅用户公钥派生用） | 端到端 6~13%；首次 +1.09 ms 表构造 |

---

## 一、结构性到顶：SM3 / SM4 / ZUC

这三个的性能瓶颈同源，也都不是"还没优化"，而是算法结构与 wasm 指令集共同封死的。

### SM3 —— MD 链式，压缩函数无 ILP

`sm3-core.ts` 已用裸指针 + `load<u32>/store<u32>`（绕开 AS 的边界检查与 GC 写屏障）、
模块级 scratch（消掉每块 132 个 u32 的 `new`）、T0/T1 两段展开的轮循环、`memory.copy`
拷入。实测 1 KB = **6.15 µs**（附录 A 的 probe；`bench` 记 6.27 µs），16 块 ≈384 ns/块。

再往下的路只有两条，都不通：

- **单个消息块之间是链式的**（`H(i) = f(H(i-1), M(i))`），无法跨块并行；
- **压缩函数 64 轮本身是串行依赖链**，没有指令级并行可挖。消息扩展 W[16..67] 的递推
  依赖距离为 3（可并行度 3），能向量化，但压缩轮不并行的话总收益是个位数百分比，
  投入产出比不成立。

真正的 SM3 加速要靠"一次哈希多条独立消息"（把 4/8 条消息的同一块位置并行），
而本库的公开 API 是单消息语义，用不上。

### SM4 —— S 盒查表，且 wasm 没有硬件指令

这是全库记录得最清楚的一处瓶颈（README「性能」一节要点已写）：成本不在 ALU 而在
内存访问，每轮 4 次 8-bit S 盒查表。

- T-table 合并 S 盒与 L 变换：查表次数不变，只换来 8~10%；
- WASM SIMD 走不通：`v128` 没有 AVX2 的 gather（无法并行查 8→32 位表），
  `i8x16.swizzle` 只够 4-bit S 盒，够不着 SM4 的 8-bit S 盒；
- 最终手段是**8 块标量交错**（每个块 4 条独立依赖链，由乱序执行盖住 L1 延迟），
  不足 8 块退到 4 块、再退到单块。

剩下的唯一出路是硬件指令：C 实现靠 ARMv8 的 `SM4E` 用电路做 S 盒、根本不查表，
而 WebAssembly 不暴露该指令集。**这在 wasm 能力范围内到顶。**

### ZUC —— LFSR 字级串行

LFSR 每步依赖前 15 个状态（`s15/s13/s10/s4/s0`），且非线性函数 F 仍是 S 盒查表。
和 SM4 撞在同一面墙上：串行依赖 + 查表，wasm 两者都不给规避手段。

---

## 二、已落地：SM2 门面层 —— 缓存公钥

### 改前实测

附录 A 的 probe（min-of-5，32 字节私钥 + 64 字节消息）：

```
SM2 getPublicKey    105 µs
SM2 sign 64B        252 µs
SM2 verify 64B      394 µs
SM2 encrypt 64B     493 µs
SM2 decrypt 64B     331 µs
```

### 问题

`sign()` 原先每次调用都先 `getPublicKey(d)`，再把返回的 hex 用 `toBytes(..., 'pub')`
解析回字节，因为 Z 值需要公钥。但**公钥只依赖私钥**——`105 / 252 ≈ 42%` 的签名时间
花在一个每次都能从缓存拿到的量上。

数字是自洽的：`getPublicKey` 的 105 µs 几乎全是固定基点标量乘（README 记录的
"标量乘 G 138 → 105 µs"完全吻合）；`sign` 的 wasm 计算层是 122 µs
（一次 comb 标量乘 kG + 少量 mod n + SM3(Z)），加上门面层的公钥派生与
randomK/编解码，落到 252 µs。

### 落地与实测

已在 `src/sm2/index.ts` 落地：模块级 `PUB_CACHE`（私钥 hex → 64 字节公钥，默认上限
32、满时按插入顺序 FIFO 淘汰最旧一条）+ `derivePublicKeyBytes()`，`sign` 改走它
（顺带省掉原先 `getPublicKey → hex → toBytes` 的往返）。公开的 `getPublicKey` 仍每次
真算，以保持"派生公钥"这个操作的语义与 `bench` 里该项的可测性。

开关与上限（与 `zuc.configureReuseGuard` / `resetReuseGuard` 同形，用例见
`tests/sm2-cache.spec.ts`）：

- `configurePublicKeyCache({ enabled?, capacity? })` —— `enabled: false` 回到每次重算；
  `capacity` 默认 32（非正整数抛 `RangeError`）；
- `clearPublicKeyCache()` —— 清空已有条目，不改开关与上限。

附录 B 的 A/B（同进程、同时段；hit 用固定私钥、miss 轮换 40 个不同私钥，两组唯一
差异就是是否需要做那次固定基点标量乘）：

```
sign 64B (cache hit)    138 µs   med 142 µs
sign 64B (cache miss)   234 µs   med 235 µs
                        省 96 µs / 41%
```

对照项 getPublicKey 107 µs / verify 394 µs / encrypt 495 µs / decrypt 334 µs 与改前
一致，说明改动只作用于 `sign` 的派生路径。改前 `sign` 是 252~255 µs，所以对旧实现的
净收益是 **−46%**（比 41% 多出的部分来自顺带省掉的 hex 往返）。重跑 `bench` 后三语
README 表里的端到端数字是 **259 → 142 µs**，与上面的 A/B 同向。

事前的 42% 预测与实测 41% 吻合。对照 README 里"SM2 行波动 ±20%"：这个**比例**是稳定的，
因为分子分母对应的都是"一次固定基点标量乘"，不受门面层其余抖动影响。

### 取舍（实施时怎么定的）

- 缓存是**全局可变状态**：`Map` 无上限会长内存 → 默认上限 32（可调），满时按插入
  顺序淘汰最旧一条（FIFO 而非 LRU：密钥集合通常很小，不需要命中统计）；
- 私钥进缓存意味着**私钥的派生结果常驻内存**（键是私钥的 hex）——这是一个真实的
  安全语义变化：原先"每次都重算"是无状态的。当前实现接受这个取舍，并**提供了可关闭的
  开关**（`configurePublicKeyCache({ enabled: false })`）给不接受它的调用方；
- 顺带可缓存 Z 值（只依赖私钥 + 默认 ID），但 Z 只省一次 SM3(Z) ≈ <1 µs，
  **收益可忽略，不要为它引入额外复杂度**。

### 同类问题（未做）

- `exchange.ts` 有自己的一份 `derivePublicKey()`（为避免循环依赖，不 import `./index`），
  每次 `createExchangeInitiator/Responder` 都会重做一次标量乘来派生 `PA`/`PB`。
  要接入同一份缓存得先把缓存抽到共享位置（`keyInput.ts` 或新模块），本次**未做**——
  收益是 1 次标量乘（~105 µs）摊在 ~1.5 ms 的密钥交换上，约 7%，远小于 `sign` 的 41%；
- `encrypt` 收的是公钥，不涉及派生；`decrypt` / `verify` 同理。`verify` 的 `isOnCurve`
  走 BigInt 比较（非热点，但也是一次纯 JS 大数运算）。

### 已落地（五）：SM2 固定公钥的 comb 表

**动机**：`encrypt` 要做两次标量乘 —— `k·G` 走 comb（52 次倍点，97 µs），`k·P` 走 wNAF
（256 次倍点，309 µs）。底层 `encryptOut` 423 µs 里有 **73% 花在 `k·P`**，而 `P`
（对端公钥）在"同一接收方反复加密"的场景里是固定的。

**改动**：把 `scalarMulG` 的 comb 表推广到任意点 P：

- 表仍是 32 项（`COMB_W = 5`、`COMB_D = 52`），构建 = 260 次倍点 + 31 次点加；
- 固定 **8 槽**，所有槽落在永久区**一块固定的 24 KiB**（不走 `permAlloc` 逐次追加，
  否则反复换公钥会耗尽 1 MiB 永久区）；prepare 只覆盖槽位，满了按 **LRU** 淘汰最久未用；
- 每槽 64 字节公钥指纹：`encrypt` 每次线性扫描 ≤8 槽，命中走 comb，**不命中自动回退
  wNAF 且不会自动建表**；
- 显式入口 `preparePublicKey(pub)`，不默认对所有公钥建表；容量可配 1..8。

**实测**（同进程、同一实例内交替 A/B，同 k）：

```
底层 encryptOut      wNAF 423.6 µs → comb 201.4 µs   (2.10×)
端到端 encrypt        486 µs       → 260 µs          (1.86×，mitata)
单次 k·P             wNAF 309.4 µs → comb ≈ 85 µs
建表（一次性）        280 µs
8 公钥轮换 encrypt    278.9 µs（与单把命中同档）
```

密文逐字节一致（同一 k 下 wNAF / comb / 旧 dist 三方相同）。建表 280 µs、每次省
≈ 225 µs，**约 1.2 次加密回本**。

**与 sm-crypto-v2 的 precompute 不是一回事**：noble 的 `precomputePublicKey(pk, 8)`
构建 256 项 BigInt 表要 **29 ms**，且 wNAF 的倍点数不随窗口减少（仍是 256）——
它省的是"每次调用重建 255 次点加"，预计算后 encrypt 425 µs。本实现直接砍倍点
（256 → 52），建表便宜 100 倍，预热后 encrypt 260 µs。

**取舍**：

- 8 槽覆盖"少量固定对端"的常见工作集；超过容量仍会 LRU 覆盖，工作集 > 8 时退化为
  "每次 prepare"，此时不应开启；
- 不做隐式建表：外部可控的公钥不能反复触发 280 µs 建表；
- 公钥是公开信息，缓存它不引入新的密钥材料驻留；
- 8 槽共占永久区固定 24 KiB，不随调用增长。

---

## 三、已落地（二）：SM9 基域改 Montgomery 域

### 当时的判断

README 已记录：SM9 的 `p` / `n` 都不是伪 Mersenne 形状，因此 `field256.ts`
的归约分派里它们走 **Barrett**（只有 SM2 的 `p` 走 Solinas）。README 当时的话是：
SM9 若要再快需要换 Montgomery，而那意味着把该曲线全部常数搬进 Montgomery 域，
属重写级改动。

这是全库**唯一一个数量级**（而非百分比）的未开采空间：当时验签 12.9 ms、密钥交换
27.8 ms、签名 6.69 ms（README 表）。SM9 已做的配对值 4 槽缓存（`SIGN_G_CACHE` /
`ENC_G_CACHE`）也说明，同一主公钥反复调用的场景已被识别并摊薄过一次。

### 落地与实测

算式很清楚：Barrett 一次 512→256 归约要付 `q1·μ`(9×9) 与 `q3·m`(9×8) ≈153 次
32×32 乘法，加上 64 次部分积共约 217 次；CIOS Montgomery 只要 2×64 = 128 次。
`p` 是奇数，`n0' = -p⁻¹ mod 2³² = 0x2f2ee42b`，`R = 2²⁵⁶`。

同进程 micro-bench（同一 wasm 模块、同一套 arena 分配、min-of-9）：模乘 178.8 →
98.0 ns，**1.82×**；模平方 173.8 → 97.1 ns。顺带量到一个反例——每次乘法都临时
转换进/出 Montgomery 要 195.6 ns，比原来还慢。所以必须是**全链统一 Montgomery
域、只在边界转换一次**，这一条决定了改动的形态（`fpToMont` / `fpFromMont` 只出现在
字节边界与模块级常量上）。

端到端（`pnpm bench` 同一次运行）：签名 6.65 → 4.11 ms、验签 12.7 → 8.00 ms、加密
5.51 → 3.69 ms、解密 7.49 → 5.40 ms、KEM 4.90/7.50 → 3.42/4.92 ms、密钥交换
28.0 → 19.6 ms，普遍 **1.6~1.8×**，与单次模乘的 1.82× 基本一致——说明 SM9 的耗时
确实由基域模乘主导。

### 实施中的两个坑（编译器与类型都抓不到）

- **`fpInv` 少一个 R**：`modInv(a·R) = a⁻¹·R⁻¹`，要补回 `a⁻¹·R`，那一步必须是
  **标准域乘法**（`modMul` 乘 R²）；用 `montMul` 会自带 `·R⁻¹`，正好把要补的 R 又
  消掉。症状是所有点坐标掉出曲线——靠输出点是否满足 `y² = x³ + 5` 的独立对拍定位。
- **`FE_A2` / `FE_A3` 是指数、不是元素**：它们与 `ALPHA1..5` 长得很像，但喂给
  `fp12Pow` 的是**幂指数**，必须保持标准域整数；转成 Montgomery 会让最终幂整条错掉。

### 已落地（三）：固定基点标量乘改 comb

`sm9.ts` 里凡「标量 × 固定基点生成元」的标量乘（`g1Mul(x, g1Generator())` /
`g2Mul(x, g2Generator())`）此前走 **wNAF**，而基点固定、库里本就有 comb 版本
（`point.ts` 的 `g1MulG` / `g2MulG`）——但只有用户公钥派生那两条在用。改后
（`src/sm9/assembly/sm9.ts` 8 处；任意点的 `g1Mul(l, ds)` / `g1Mul(r, Q)` 保持不动）：

```
单次 G2 标量乘     wNAF 1058 µs → comb 415 µs   (2.5×)
verify              6.88 → 6.39 ms   (−7%)
sign                3.22 → 2.96 ms   (−8%)
encrypt             3.50 → 3.27 ms   (−7%)
decrypt             4.66 → 4.06 ms   (−13%)
```

同进程交替 A/B、满 256-bit 标量（`t2 = ks·(H1+ks)⁻¹ mod n` 等）。

**代价**：comb 表（`buildG1Comb` / `buildG2Comb`）首次调用才构造，**首次操作 +1.09 ms**；
之后每次调用省 0.4~0.8 ms，2~5 次调用回本。同一进程里反复使用（尤其主公钥固定的
场景）划算，一次性调用不划算。

**方法学的坑（记下来，避免重蹈）**：本轮被两个 probe bug 各带偏过一次——
（a）把 `Uint8Array` 对象当 `usize` 指针传给 wasm 导出，标量变成 0，测出「comb 快 19×」
的假信号；（b）用两次独立运行的绝对耗时对比，而**这台机器跨进程能差 4~11×**（同一个
`g2MulGOut` 在两次运行里分别测出 98 µs 与 425 µs）——「门面层有 1.7 ms 水分」也是这么
来的假结论。**只有同进程交替 A/B 的相对值可信**（同附录 C）。另外 bench 的
`KS = 'd0e0f'…` 是小标量，comb 对小标量因固定开销反而略慢，会掩盖/反转这项收益——
看 bench 的 `getSignPublicKey` 数字时要心里有数。

正确性：`sig` / `ct` 逐字节一致；SM9 39 个用例与全量 193 个用例全过。

### 已落地（四）：SM2 / SM9 混合加密（KEM + SM4-GCM）

**动机**：公钥加密长数据的成本由消息长度主导（计划阶段实测 SM2 1MB ≈ 29 MB/s、
SM9 10KB ≈ 2 MB/s），而对称加密快一个数量级。hybrid 把公钥运算固定为一次 KEM，
消息交给 SM4-GCM。

**实测**（同机 mitata，Node 24，`pnpm bench`；数字为 avg）：

| 用例 | 平均 |
|---|---:|
| SM2 KEM 封装（16B key） | 496 µs |
| SM2 KEM 解封装（16B key） | 328 µs |
| SM2 hybrid 加密 1MB | 37.25 ms（≈ 27 MB/s） |
| SM2 hybrid 解密 1MB | 36.39 ms（≈ 27 MB/s） |
| SM9 KEM 封装（32B key） | 2.85 ms |
| SM9 KEM 解封装（32B key） | 4.42 ms |
| SM9 hybrid 加密 10KB | 3.21 ms |
| SM9 hybrid 解密 10KB | 4.77 ms |

**解读**：

- SM2 hybrid 1MB 的 37 ms 里 KEM 只占约 0.5 ms，其余是 SM4-GCM 与 WASM 内存搬运；
  与直接 SM2 加密 1MB（计划阶段 ≈ 34 ms）相比，当前 GCM 实现下绝对耗时接近，
  但**封装段固定 113 字节**、公钥运算不再随消息长度增长，消息越大相对优势越明显。
- SM9 hybrid 10KB 的 3.21 ms 与一次 KEM 封装 2.85 ms 基本持平，SM4-GCM 的 10KB
  成本被 pairing 掩盖；封装段固定 65 字节。
- SM9 解封装比封装慢（4.42 vs 2.85 ms）与既有 KEM 基线一致，由解密侧 pairing 主导。
- 数据仍整段进出 WASM，常驻内存水位由最大消息决定；流式不在本计划范围内。

### 剩余空间

只剩百分比级，而且已经逐个量过：

- **平方特化**（`a²` 的交叉项只算一次，32×32 部分积 64 → 36）：`bb7c52a` 把 `fpSqr`
  从 `field256` 的 `sqr512Into` 改成 `montMul(a, a)` 时，丢掉了 SM9 原有的这份特化
  （SM2 至今还在用 field256 那份）。补回来的实测：**单个平方确实快 1.19×**
  （同模块 micro-bench 121.5 → 102.5 ns），但**端到端没有可测收益** ——
  `fp12Sqr` / `fp4Sqr` / `fp2Sqr` 这些热路径的平方都走 `fpMul`，不经过 `fpSqr`；
  用得上它的只有 G1 点运算（倍点 / 点加 / 转仿射）与 `fp2Inv` / `fp2SqrU`。
  同进程交替 A/B（两个 wasm 装进同一进程，两次）：G1 标量乘 50.1/51.2 → 49.8/50.2 µs
  （+0.8% / +2.1%），pairing 3443.8/3456.8 → 3475.8/3507.9 µs（−0.9% / −1.5%）。
  **净效果约等于零，而 pairing 是所有主操作的主导路径，不值得新增这条代码路径，
  已回退。** 教训：micro-bench 的单点加速（1.19×）不必然传递到工作负载，得先看
  热路径实际调用了哪个函数。
- `fpInv` 在域内求逆后要多付一次 `modMul` 去补 R（占比很小）。

数量级空间已经开采完。

**未验证的推断**（与本文其他条目一样只是推断）：SM2 的 `n` 也是伪 Mersenne 形状，
理论上可以补一条 Solinas 归约。但签名里 mod n 的运算只出现在固定基点标量乘之外的
一小段（`r`、`s`、一次 `modInv`），而计算层耗时的大头是 kG，预期收益很小——若要动，
先做 A/B 再决定。

---

## 四、架构级方向：WASM threads

SM9 验签 8.00 ms、密钥交换 19.6 ms 这种量级天然适合多核切分（独立的 Miller 循环、
批量求逆）。但 WASM threads 需要 `SharedArrayBuffer` + Worker，以及宿主侧的
COOP/COEP 响应头，属于加载层与部署形态的整套改造，收益与复杂度都远大于前两项。

判为**方向性预留**，不在近期范围内。

---

## 五、判断依据与局限

- **实测**：第二节的 SM2 数字来自附录 A / 附录 B 的 probe（本机、min-of-5）；
  其中 41% 的收益来自附录 B 的进程内 A/B，改动另经 SM2 全量用例（67 个含
  OpenSSL / gmkitx 交叉与官方 KEX 向量，外加 6 个缓存开关用例）确认无回归。
  第三节的 SM9 单次模乘数字来自同进程 micro-bench（临时 probe，已删；同一 wasm
  模块内 Barrett 与 CIOS 同口径对比，min-of-9），端到端数字来自 `pnpm bench` 的
  SM9 组；改动经 SM9 全部 39 个用例（含 GmSSL KAT 的 sign / encrypt / KEM /
  密钥交换逐字节对拍、扩域与 BigInt 等价性）确认无回归。
- **引用 README**：SM9 / SM4 / ZUC 的绝对耗时，以及各自的瓶颈分析。
- **未验证推断**：第三节末尾 SM2 `n` 做 Solinas 的收益估计。
- **波动**：SM2 门面层在多次运行间可波动 ±20%（README 已注明），文中用到的是比例
  而非绝对值；SM3 / SM4 / ZUC 的数字稳定。**SM9 的跨进程波动比这更甚**——本轮实测同一
  个 `g2MulGOut` 在两次独立运行里差到 98 µs / 425 µs（4~11×），所以 SM9 的绝对耗时对比
  一律走同进程交替 A/B，跨运行的数字只当方向参考。
- **不覆盖**：ZUC-256、SM9 的算法级（非域运算）改造、以及任何需要改公开 API 语义的
  方向（如多消息批量哈希）。
- **已办**（本文列为待决 / 评估的条目）：README 的三语性能表已按重跑结果同步
  （`sign` 259 → 142 µs、对比倍数 1.7× → 3.1×）；SM2 缓存的开关已落地
  （`configurePublicKeyCache` / `clearPublicKeyCache`）；第三节的 SM9 Montgomery
  域也已实装（单次模乘 179 → 98 ns、端到端 1.6~1.8×），并新增「固定基点标量乘改 comb」
  （端到端 6~13%、首次 +1.09 ms 表构造）。

## 附录 A：SM2 门面层 probe（临时，未入库）

放在 `$TMPDIR`，从仓库根执行：`node probe-sm2.mjs`。

```js
import { pathToFileURL } from 'node:url';

const ROOT = pathToFileURL('<repo>/dist').href;
const sm2 = await import(`${ROOT}/sm2/index.js`);
const sm3 = await import(`${ROOT}/sm3/index.js`);
const sm4 = await import(`${ROOT}/sm4/index.js`);

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const MSG = new Uint8Array(64).fill(0x5a);
const MSG1K = new Uint8Array(1024).fill(0x5a);
const KEY16 = new Uint8Array(16).fill(1);
const IV16 = new Uint8Array(16).fill(2);

function timeIt(label, fn, iters) {
  for (let i = 0; i < Math.floor(iters / 4); i++) fn(); // 预热
  const samples = [];
  for (let s = 0; s < 5; s++) {
    const t0 = performance.now();
    for (let i = 0; i < iters; i++) fn();
    samples.push(((performance.now() - t0) / iters) * 1000);
  }
  samples.sort((a, b) => a - b);
  console.log(`${label}  min ${samples[0].toFixed(2)}us`);
}

await sm2.ensureLoaded();
await sm3.ensureLoaded();
await sm4.ensureLoaded();

const pub = sm2.getPublicKey(D);
const sig = sm2.sign(D, MSG);
const ct = sm2.encrypt(pub, MSG);

timeIt('SM2 getPublicKey', () => sm2.getPublicKey(D), 2000);
timeIt('SM2 sign 64B', () => sm2.sign(D, MSG), 1000);
timeIt('SM2 verify 64B', () => sm2.verify(pub, MSG, sig), 500);
timeIt('SM2 encrypt 64B', () => sm2.encrypt(pub, MSG), 500);
timeIt('SM2 decrypt 64B', () => sm2.decrypt(D, ct), 500);
timeIt('SM3 hash 1KB', () => sm3.hash(MSG1K), 5000);
timeIt('SM4 ECB 1KB', () => sm4.encryptECB(KEY16, MSG1K), 5000);
```

> 注意：脚本读的是 `dist/*` 构建产物，跑之前先 `pnpm build`，且必须从仓库根运行
> （`loadWasm` 以 `process.cwd()` 定位 wasm）。

## 附录 B：公钥缓存 A/B probe（临时，未入库）

放在 `$TMPDIR`，从仓库根执行：`node probe-ab.mjs`（先 `pnpm build:ts`）。

```js
import { pathToFileURL } from 'node:url';

const ROOT = pathToFileURL('<repo>/dist').href;
const sm2 = await import(`${ROOT}/sm2/index.js`);

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const MSG = new Uint8Array(64).fill(0x5a);

// 40 个互不相同、且合法的私钥（0 < d < n）。
const KEYS = Array.from({ length: 40 }, (_, i) =>
  (BigInt('0x1234567890abcdef') * BigInt(i + 1)).toString(16).padStart(64, '0'),
);

function timeIt(label, fn, iters) {
  for (let i = 0; i < Math.floor(iters / 4); i++) fn();
  const samples = [];
  for (let s = 0; s < 5; s++) {
    const t0 = performance.now();
    for (let i = 0; i < iters; i++) fn();
    samples.push(((performance.now() - t0) / iters) * 1000);
  }
  samples.sort((a, b) => a - b);
  console.log(`${label.padEnd(28)} min ${samples[0].toFixed(2)}us  med ${samples[2].toFixed(2)}us`);
  return samples[0];
}

await sm2.ensureLoaded();

const pub = sm2.getPublicKey(D);
const sig = sm2.sign(D, MSG);
const ct = sm2.encrypt(pub, MSG);

// 正确性自检：两条路径产出的签名都必须能通过验签。
let ci = 0;
for (let i = 0; i < 8; i++) {
  const k = KEYS[i];
  if (!sm2.verify(sm2.getPublicKey(k), MSG, sm2.sign(k, MSG))) throw new Error('miss 路径验签失败');
}
if (!sm2.verify(pub, MSG, sig)) throw new Error('hit 路径验签失败');
console.log('正确性自检: 通过（hit / miss 两条路径的签名均可验签）');
console.log('---');

const hit = timeIt('sign 64B (cache hit)', () => sm2.sign(D, MSG), 1000);
const miss = timeIt('sign 64B (cache miss)', () => sm2.sign(KEYS[ci++ % KEYS.length], MSG), 1000);
console.log('---');
console.log(
  `缓存命中省下的派生: ${(miss - hit).toFixed(2)}us  (${(((miss - hit) / miss) * 100).toFixed(0)}% of sign)`,
);
console.log('---');
timeIt('getPublicKey (always real)', () => sm2.getPublicKey(D), 2000);
timeIt('verify 64B', () => sm2.verify(pub, MSG, sig), 500);
timeIt('encrypt 64B', () => sm2.encrypt(pub, MSG), 500);
timeIt('decrypt 64B', () => sm2.decrypt(D, ct), 500);
```

> 设计要点：hit / miss 两组在**同一进程、同一时段**内测量，miss 组轮换 40 个互不
> 相同的合法私钥（`0 < d < n`）以保证必然不命中，两组唯一差异就是 `sign` 内部是否
> 需要做那次固定基点标量乘。预热后取 5 组样本的 min。

## 附录 C：SM9 平方特化 A/B probe（临时，未入库）

第三节判断「平方特化不值得」用的就是它。要点：两个 SM9 wasm 必须**同时装进一个
进程**交替测 —— 这台机器上两次独立运行的差异可以到 ±20%（曾出现"纯点乘慢 22%、
pairing 快 8%"的假信号），足以盖过 1~2% 的真实差异。

先各构建一份（`dist/sm9/sm9.wasm` 分别是"现状"与"特化"）：

```bash
# 特化版（fpSqr 走 Comba 平方 + SOS 归约）
cp dist/sm9/sm9.wasm ab/sm9-sqr.wasm
# 现状（fpSqr = montMul(a, a)）：暂回未改的 fp.ts 后重新构建，再恢复
git stash push -- src/sm9/assembly/fp.ts
pnpm build:wasm:sm9 && cp dist/sm9/sm9.wasm ab/sm9-mul.wasm
git stash pop
```

runner（`ab.mjs`，放在 `$TMPDIR`，从仓库根执行）：

```js
const A = await load('sm9-mul.wasm'); // 现状
const B = await load('sm9-sqr.wasm'); // 特化
const bufA = A.exports.alloc(1024);
const bufB = B.exports.alloc(1024);
A.exports.g1MulSmall(1, bufA); // G1 基点（偏移 0，64B）
A.exports.g2MulSmall(1, bufA + 256); // G2 基点（偏移 256，128B）
B.exports.g1MulSmall(1, bufB);
B.exports.g2MulSmall(1, bufB + 256);

// 交替采样、各取 min：漂移对两组的影响相同
function timeAlt(fnA, fnB, iters, rounds) {
  let bestA = Infinity, bestB = Infinity;
  for (let r = 0; r < rounds; r++) {
    let t0 = performance.now();
    for (let i = 0; i < iters; i++) fnA();
    bestA = Math.min(bestA, (performance.now() - t0) / iters);
    t0 = performance.now();
    for (let i = 0; i < iters; i++) fnB();
    bestB = Math.min(bestB, (performance.now() - t0) / iters);
  }
  return [bestA, bestB]; // ms/op
}

timeAlt(
  () => A.exports.g1MulSmall(0x12345678, bufA),
  () => B.exports.g1MulSmall(0x12345678, bufB),
  100, 21,
);
timeAlt(
  () => A.exports.pairingOut(bufA + 256, bufA, bufA + 512),
  () => B.exports.pairingOut(bufB + 256, bufB, bufB + 512),
  8, 15,
);
```

> 注意 `A.exports` / `B.exports` 各自持有独立内存，指针不能跨实例传递；两组输入
> 各自由自己的实例的 `g1MulSmall` / `g2MulSmall` 生成，并逐字节比对过输出一致。

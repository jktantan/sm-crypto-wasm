# 性能上限评估：五个算法还剩多少空间

- 日期：2026-10-14
- 环境：AMD Ryzen 7 7800X3D / Node 24.15 / Windows 11
- 触发：一轮优化收尾后核对"是否已经到顶"，把结论固化下来，避免日后重复铺开同一批实验。
- 复现：`pnpm bench`（全量）；本文的 SM2 单操作数字来自附录 A / 附录 B 的临时 probe。
- 同日落地：第二节（SM2 门面层公钥缓存）已实装、实测，并补上了开关；README 的三语
  性能表已按重跑结果同步。其余条目仍为评估结论。

## 结论速览

| 算法 | 状态 | 卡点 | 剩余空间 |
|---|---|---|---|
| SM3 | **到顶** | MD 链式 + 64 轮压缩函数串行 | 仅多消息批量并行（公开 API 用不上） |
| SM4 | **到顶** | 8-bit S 盒查表，wasm 无 SM4E/AES-NI | 需 wasm 暴露硬件指令 |
| ZUC | **到顶** | LFSR 字级串行 + F 函数 S 盒查表 | 同 SM4，受同一限制 |
| SM2 计算层 | **到顶** | 已 comb/wNAF/Solinas/混合坐标/局部字级求逆 | 个位数百分比 |
| SM2 门面层 | **已落地** | 每操作重复派生公钥与编解码 | 缓存公钥：sign **252 → 138 µs（−46%）**；可用 `configurePublicKeyCache` 关掉 |
| SM9 | **没到顶** | p/n 走 Barrett 归约 | 数量级（换 Montgomery 域，重写级） |

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

---

## 三、没到顶（二）：SM9 的 Barrett 归约

README 已记录：SM9 的 `p` / `n` 都不是伪 Mersenne 形状，因此 `field256.ts`
的归约分派里它们走 **Barrett**（只有 SM2 的 `p` 走 Solinas）。README 原话是
"SM9 若要再快需要换 Montgomery，而那意味着把该曲线全部常数搬进 Montgomery 域，
属重写级改动"。

这是全库**唯一一个数量级**（而非百分比）的未开采空间：验签 12.9 ms、密钥交换 27.8 ms、
签名 6.69 ms（README 表）。SM9 已做的配对值 4 槽缓存（`SIGN_G_CACHE` /
`ENC_G_CACHE`）也说明"同一主公钥反复调用"的场景已被识别并摊薄过一次。

**未验证的推断**：SM2 的 `n` 其实也是伪 Mersenne 形状，理论上可以补一条 Solinas
归约。但签名里 mod n 的运算只出现在固定基点标量乘之外的一小段（`r`、`s`、一次
modInv），而计算层耗时的大头是 kG，因此预期收益很小——这条**没有实测**，若要动，
先做 A/B 再决定。

---

## 四、架构级方向：WASM threads

SM9 验签 12.9 ms、密钥交换 27.8 ms 这种量级天然适合多核切分（独立的 Miller 循环、
批量求逆）。但 WASM threads 需要 `SharedArrayBuffer` + Worker，以及宿主侧的
COOP/COEP 响应头，属于加载层与部署形态的整套改造，收益与复杂度都远大于前两项。

判为**方向性预留**，不在近期范围内。

---

## 五、判断依据与局限

- **实测**：第二节的 SM2 数字来自附录 A / 附录 B 的 probe（本机、min-of-5）；
  其中 41% 的收益来自附录 B 的进程内 A/B，改动另经 SM2 全量用例（67 个含
  OpenSSL / gmkitx 交叉与官方 KEX 向量，外加 6 个缓存开关用例）确认无回归。
- **引用 README**：SM9 / SM4 / ZUC 的绝对耗时，以及各自的瓶颈分析。
- **未验证推断**：第三节末尾 SM2 `n` 做 Solinas 的收益估计。
- **波动**：SM2 门面层在多次运行间可波动 ±20%（README 已注明），文中用到的是比例
  而非绝对值；SM3 / SM4 / ZUC 的数字稳定。
- **不覆盖**：ZUC-256、SM9 的算法级（非域运算）改造、以及任何需要改公开 API 语义的
  方向（如多消息批量哈希）。
- **已办**（本文原本列为待决的两项）：README 的三语性能表已按重跑结果同步
  （`sign` 259 → 142 µs、对比倍数 1.7× → 3.1×）；缓存的开关也已落地
  （`configurePublicKeyCache` / `clearPublicKeyCache`）。

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

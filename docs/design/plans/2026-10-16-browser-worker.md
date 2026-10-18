# 浏览器侧阻塞与 Web Worker — 后续计划

> **状态：backlog。** 2026-10-16 用户裁定「先记进计划，暂不实现」。
> **2026-10-18 修订：** 修正 1 MB 数据的 bench 口径（改用当前可复现的 hybrid 37.3 ms）、
> 补充批量操作与跨线程固定成本、把方案 b 的边界收窄到协议 handler，并量化触发条件。
> 结论不变：**暂不实现；文档项 a 可以随时先做。**
> **由来**：讨论"浏览器侧是不是该走异步 + Worker"时量化出的结论 —— 异步那半已经做了，
> 真正缺的是 Worker，值得搬的有三类：SM9 的重操作、大消息、批量循环。

**Goal:** 让消费者知道浏览器里**哪些**操作需要搬离主线程，并在确有需求时提供最薄的封装。

---

## 结论先行

浏览器侧的"异步"**已经做了**：wasm 加载走 `fetch`，消费者 `await ensureLoaded()` 预热一次，
之后业务调用是同步的。**而把业务 API 改成全异步并不能解决阻塞** —— Promise 只在 `await`
点让出控制权，CPU 密集那段仍在主线程上跑。

对照 `crypto.subtle`：它全异步，规范也**允许**浏览器把实现放到内部线程执行（不保证）。
我们的 wasm 没有这层待遇 —— **除了 Worker，没有别的手段能把运算移出主线程**。

---

## 量化：谁真的需要 Worker

一帧 = 16.7 ms（60fps）。数据与 `pnpm bench` 同源（见 `website/performance.md`）：

| 操作 | 耗时 | 判断 |
|---|---|---|
| SM3 / SM4 / ZUC 1 KB | 4.8 ~ 20 µs | 不用（远低于一帧的 1%） |
| SM2 签名 / 验签 64 B | 142 / 402 µs | 不用（一帧 ~2.4%） |
| SM2 加密 / 解密 64 B | 499 / 343 µs | 不用 |
| SM9 签名 / 验签 | 4.11 / 8.00 ms | 边缘（一帧的 25%~48%） |
| SM9 KEM 封装 / 解封装 | 3.42 / 4.92 ms | 边缘 |
| SM9 密钥交换（完整 A↔B） | 19.6 ms | ⚠️ 见下方口径说明 |
| **SM2 hybrid 加密 1 MB** | **37.3 ms** | ⚠️ 掉两帧（bench 项：`hybrid encrypt 1MB`） |
| **SM2 验签 × 100** | **≈ 40 ms** | ⚠️ 批量累积 |
| **SM9 验签 × 10** | **≈ 80 ms** | ⚠️ 批量累积 |

口径说明：

- **SM2 1 MB 用 37.3 ms，不是 34 ms。** 34 ms 是 `performance-ceiling.md` 里"计划阶段
  直接 SM2 加密 1 MB"的历史数，当前 `bench/sm2.bench.ts` 没有对应项，无法复现；
  现有可复现项是 `hybrid encrypt 1MB`。两者量级一致，不影响结论。
- **SM9 KEX 的 19.6 ms 是同一进程内跑完 A↔B 双方的总和**（`bench/sm9.bench.ts`
  的 `kex()`）。真实部署中两端通常在不同设备/进程，单侧只承担 `initiate/confirm`
  或 `respond` 的一部分，**单侧耗时尚未单独测量**，不应直接按 19.6 ms 估算掉帧。

**值得外包的是三类**：

1. **SM9 的重操作** —— 签名 / 验签 / 加解密 / KEM / 密钥交换；
2. **大消息** —— 1 MB 级的 hybrid 加解密；
3. **批量循环** —— 单次不慢，但 N 次累积超预算的验签 / 解密。这一条最容易被忽略，
   也最现实（证书链、CMS 多签名、批量报文校验）。

SM3 / SM4 / ZUC / 单次 SM2 的常规操作套 Worker 反而**净亏** —— 跨线程的固定成本
大于运算本身。

---

## 跨线程不是免费的

计划的判断必须把下面几项算进去，否则会把"主线程不卡"误当成"更快"：

- **启动成本**：创建 Worker + `fetch` wasm + `WebAssembly.instantiate`，通常是
  **几毫秒到十几毫秒**（`sm9.wasm` 78 KB、`sm2.wasm` 41 KB）。对一次 4 ms 的 SM9 签名，
  按任务新建 Worker 一定净亏。
- **`ensureLoaded()` 的 memoize 是 per-worker 的**：每个 Worker 各自持有独立的 wasm
  实例与内存，也各自加载一次。Worker 启动后应立刻预热，而不是等第一次消息。
- **必须复用 Worker**：池化，或在应用生命周期内持有固定数量的 Worker。
- **传输成本**：`postMessage` 默认走结构化克隆。小消息的固定开销（数十到数百 µs）
  相对运算本身不可忽略；1 MB 级的数据克隆成本尚可接受，但如果返回 **hex 字符串**，
  有效载荷会翻倍（1 MB → 2 MB 文本），编码/解码本身也会变成热点。
  协议层应优先支持 `Uint8Array` / `ArrayBuffer`，并对返回的 buffer 使用 transferable。
- **收益的定义**：Worker 的收益是**主线程保持响应**，不是降低总延迟。总延迟通常会
  更高（多一次线程切换与拷贝），这是可以接受的交换，但要在文档里说清楚。

---

## 为什么库不内建 Worker

Worker 是**宿主环境**的能力，不是算法的能力。库对外给的是"同步、可组合、无状态"的 API；
Worker 是套在外面的一层壳，而它的策略（消息协议、取消、Worker 数量与生命周期、传输格式）
因项目而异，硬封装容易绑手绑脚。

好消息是 wasm 在 Worker 里**天然安全**：每个 Worker 持有独立的 wasm 实例与内存，没有共享
状态问题。

`website/guide/cross-runtime.md` 的 Web Worker 一节已有最小可用例子：

```ts
// worker.ts
import { sm9 } from 'sm-crypto-wasm';
self.onmessage = async (e) => {
  await sm9.ensureLoaded();
  self.postMessage(sm9.sign(e.data.ks, e.data.id, e.data.msg));
};
```

注意：目前**只有中文页有 Worker 示例**，英文 / 俄文 `cross-runtime.md` 明确写了
"中文页有同样的内容加一个示例"，即示例被省略。做方案 a 时需要补齐三语。

---

## 可选方案（代价递增）

- [ ] **a. 文档补「Worker 适用阈值」** —— **可以立即做，零代码。** 内容清单：
      - 上面的量化表、"三类值得外包"、"不要外包"清单；
      - Worker 复用与启动预热；`ensureLoaded()` 是 per-worker 的；
      - 大消息传 `Uint8Array` / `ArrayBuffer` + transferable，不要用 hex；
      - 一个批量验签的示例；
      - 三语同步：中文示例已有，英文 / 俄文补齐并加阈值说明。
      写入 `website/**/guide/cross-runtime.md` 与三语 README。
- [ ] **b. 提供 `sm-crypto-wasm/worker` 子路径** —— **第一版只做协议 handler**：
      无状态单次调用 + 批量调用，用户自己创建 Worker、自己决定池大小与生命周期；
      库不提供完整的 Worker 客户端。**SM9 密钥交换排除在第一版之外**：它是
      `initiate → respond → confirm → getSharedKey` 的有状态四步协议，Worker 化需要
      会话 ID + 亲和性（或每一步都跨线程传中间消息），属于另一套设计。
      代价：新增子路径导出 + 打包器差异（`new Worker(new URL(...), { type: 'module' })`
      在 Vite / Webpack / esbuild 下行为不同、CSP 的 `worker-src`）+ 维护面。
- [ ] **c. 提供 `signAsync()` / `encryptAsync()` 等异步包装** —— 内部走 Worker，
      主线程不阻塞；同步 API 保留。代价：API 面积翻倍，两套语义需长期并存，
      且与 spec「业务方法同步暴露」的承诺冲突。**不推荐。**

推荐 a（必要时 a + b，b 按上面的收窄边界）。

---

## 触发条件

- 单次操作在主线程超过一帧（16.7 ms），且处于交互关键路径（动画 / 输入响应）；
- **批量 ≥ 50 次 SM2 验签，或 ≥ 10 次 SM9 验签**；
- X.509 / CMS 批量验签落地后出现可感知卡顿；
- 或有人明确要求开箱即用的 Worker 封装。

---

## Non-Goals

- **不把业务 API 改成全异步** —— 异步不解决阻塞（见上），只会让库内组合变难，并给每次调用
  加上 microtask 开销。
- **不引入 SharedArrayBuffer / COOP-COEP** —— 需要跨源隔离响应头，部署成本远超收益。
- **不替用户决定 Worker 策略**（数量、生命周期、消息协议、取消语义）。
- **不在 b 的第一版搬 SM9 KEX 会话** —— 有状态协议需要单独的会话亲和性设计。
- **不把 hex 作为跨线程协议的唯一格式** —— 大消息的 hex 往返会让有效载荷翻倍。

---

## 与其它计划的关系

- `2026-10-17-x509-cms-webcrypto.md` 会引入批量验签场景（CMS 多签名 / 证书处理），
  触发条件里的批量阈值按该计划落地后的实测数据校准。
- `docs/performance-ceiling.md` 的 WASM threads 是独立的并行化方向
  （需要 COOP/COEP），不复用本计划的 Worker 封装，也不因本计划而改变。

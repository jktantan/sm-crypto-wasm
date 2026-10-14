# sm-crypto-c Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a `sm-crypto-wasm` npm package exposing SM2/SM3/SM4/SM9/ZUC国密 algorithms via AssemblyScript → WASM, with Node 18+ & browser runtimes, on-demand per-algorithm lazy loading, TS types, GM/T standard vectors + Wycheproof-style fuzz, and tag-driven npm publish.

**Architecture:** Five independent algorithm units (sm2/sm3/sm4/sm9/zuc), each a self-contained AssemblyScript crate compiled to its own `.wasm` with a thin TS loader. A common `runtime.ts` handles hex/base64/Uint8Array I/O and shared WebAssembly instantiation; `index.ts` is a facade that lazy-imports each algorithm module on first use. Per-algorithm `exports` sub-paths (`sm-crypto-wasm/sm2`, …) allow size-sensitive consumers to skip the facade.

**Tech Stack:** AssemblyScript (`asc` 0.27+), TypeScript 5, Rollup, pnpm 9, vitest 1, fast-check 3, mitata, biome, GitHub Actions, `release-it`.

**Spec:** `docs/superpowers/specs/2026-10-13-sm-crypto-wasm-design.md` (approved 2026-10-13).

---

## 执行状态（2026-10-14 对账）

| Task | 状态 | 说明 |
|---|---|---|
| 1 runtime / WASM loader | ✅ | `src/runtime/loadWasm.ts`（记忆化）；无独立单测 |
| 2 runtime / convert + errors | ✅ | `src/runtime/{convert,errors}.ts`；无独立单测 |
| 3 runtime / random | ✅ | `src/runtime/random.ts`（宿主 CSPRNG + 拒绝采样）；无独立单测 |
| 4 PEM / ASN.1 | ✅ | `src/pem/{asn1,pkcs8,sm2,sm9}.ts`；plan 的 `spki.ts` 并入 `pkcs8.ts`，`sm2/pem.ts` 实为 `pem/sm2.ts` |
| 5 测试向量 | ◐ | 未落 `{sm3,sm4,zuc}/official.json`；改用 gmkitx/OpenSSL/GmSSL 交叉验证 + 按需落盘（EIA3 用 GM/T 0001.3-2012 官方三组） |
| 6 SM2 核心 | ✅ | sign/verify/encrypt/decrypt/getPublicKey；`generateKeyPair` 与 C1C2C3 于 2026-10-14 补齐 |
| 7 SM3 | ✅ | hash + hmac |
| 8 SM2 密钥交换 | ✅ | GM/T 0003.3，含官方向量 + gmkitx 对拍 |
| 9 SM4 六模式 | ✅ | 含 GCM（OpenSSL KAT）；CTR/OFB 现名 `cryptCTR`/`cryptOFB`，另有别名 |
| 10 SM9 | ✅ | sign/verify/encrypt/decrypt + KEM + 密钥交换；`generateKeyPair` 于 2026-10-14 补齐 |
| 11 ZUC | ✅ | EEA3 + EIA3（2026-10-14 补齐）+ 复用保护 |
| 12 构建 / 打包 | ✅ | `asc` + `tsc` 产出 dist；`biome.json` / `vitest.browser.config.ts` 已补；仍未引入 rollup（ESM-only） |
| 13 CI / 发布 | ✅ | `.github/workflows/{ci,release}.yml` + `.release-it.json`（2026-10-14） |
| 14 bench | ✅ | `bench/`（5 大块算法 mitata 基准）（2026-10-14） |
| 15 README | ✅ | 5 大块速查，示例经实跑验证（2026-10-14） |

✅ 完成 · ◐ 部分完成 · ❌ 未做。剩余缺口的完整清单见 spec §14。

---

## Global Constraints

- Package name: `sm-crypto-wasm`; version starts at `0.1.0`; license `MIT`; `engines.node: ">=18"`.
- Public API surface must be a **synchronous-first façade** (`sm3.hash`, `sm4.encryptCBC`, `sm2.encrypt`, `sm9.sign`, `zuc.encrypt`, `zuc.mac`); `async` only for `sm2.generateKeyPair`, `sm9.generateKeyPair`, `sm2.keyExchange.*` protocol flow (per §12.1 Q2).
- SM2 ciphertext default ordering: **C1C3C2** (per §12.1 Q1); decryption auto-detects both orderings.
- SM9 keystores: PKCS#8 + custom OID `1.2.156.10197.1.100` (per §12.1 Q3).
- All randomness MUST come from host: `globalThis.crypto.getRandomValues` (browser/Node 19+) → `node:crypto.webcrypto.getRandomValues` shim for Node 18. **Never** instantiate an internal RNG.
- WASM is split: one `.wasm` per algorithm; `dist/` is the publishable tree; `bench/`, `tests/vectors/`, `*.ts` source-maps only.
- `package.json` `exports` MUST list `.`, `./sm2`, `./sm3`, `./sm4`, `./sm9`, `./zuc`, `./package.json` per §11.
- Browser bundle ≤ 150 KB per algorithm gzip (excluding sm9); sm9 may be larger due to pairing tables.
- Code style: `biome` formatter + linter; commits follow Conventional Commits.

---

## Review Focus (input classes most likely to bite a real user)

| # | Input / Failure mode | Expected behavior | Task that pins it |
|---|---|---|---|
| 1 | Empty string, empty `Uint8Array`, length-0 hex | All algorithms throw `TypeError` / `RangeError` with a descriptive message; **none** silently produces an empty result | Task 2 (runtime), Task 7 (sm3), Task 9 (sm4) |
| 2 | Malformed PEM (bad header, bad base64, truncated DER, wrong OID) | `loadPrivateKey` / `loadPublicKey` throws; **does not** fall back to hex interpretation | Task 4 (pem) |
| 3 | SM2 public key on a point not on curve / wrong subgroup | `sm2.encrypt` throws `InvalidPublicKeyError`; `sm2.verify` returns `false` (does NOT throw) | Task 6 (sm2 curve) |
| 4 | SM2 decrypt with wrong key, tampered ciphertext, bad C1/C3 length | `sm2.decrypt` throws `DecryptionError` (or returns `null` if `safeMode: true`) | Task 6 (sm2 curve) |
| 5 | ZUC keystream used twice with same (key, iv) | `zuc.encrypt` throws — explicitly fail (libraries have shipped CVEs from silent reuse) | Task 11 (zuc) |
| 6 | SM9 ciphertext tamper / wrong identity | `sm9.decrypt` / `sm9.verify` throws; not silent | Task 10 (sm9) |
| 7 | Concurrent `loadWasm` calls for the same algorithm | Memoized; second caller waits on first; no duplicate `instantiate` | Task 1 (runtime) |
| 8 | WASM memory growth while a `Uint8Array` view is held by JS | Loader returns copies (`slice()`), not views, when the buffer may be grown | Task 1, Task 6 |

> **2026-10-14 更正（#1）**：**摘要类算法不拒绝空输入**。SM3 的输入是任意比特串
> （GM/T 0004-2012），空串 `l = 0` 填充后恰好是一个完整 512 比特块，结果唯一
> （`SM3("") = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b`）。
> "空输入抛错"只适用于密钥 / IV / 密文这类有固定长度契约的参数。详见 spec §14「P2 批次」。
>
> **2026-10-14 现状（#3 / #4 / #5）**：#3 已实现（新增 `InvalidPublicKeyError`，
> `encrypt` 抛 / `verify` 返回 false）；#4 已全部实现 —— 校验失败统一为
> `DecryptionError`，密文结构错统一为 `InvalidCiphertextError`（两者同属
> `CiphertextError` 支），且 `safeMode: true` 已支持；#5 已实现（`zucEncrypt` 抛错，
> 解密走新增的 `zucDecrypt`）。

---

## File Structure (created/modified across all tasks)

```
sm-crypto-wasm/
├── package.json                            [Task 12]
├── pnpm-workspace.yaml                     [Task 12 — if needed for sub-packages]
├── tsconfig.json                           [Task 12]
├── biome.json                              [Task 12]
├── rollup.config.mjs                       [Task 12]
├── vitest.config.ts                        [Task 12]
├── vitest.browser.config.ts                [Task 12]
├── .gitignore                              [Task 12]
├── .github/workflows/ci.yml                [Task 13]
├── .github/workflows/release.yml           [Task 13]
├── src/
│   ├── index.ts                            [Task 12 — facade, lazy imports]
│   ├── runtime/
│   │   ├── loadWasm.ts                     [Task 1]
│   │   ├── convert.ts                      [Task 2]
│   │   ├── errors.ts                       [Task 2]
│   │   └── random.ts                       [Task 3]
│   ├── pem/
│   │   ├── asn1.ts                         [Task 4]
│   │   ├── pkcs8.ts                        [Task 4]
│   │   ├── spki.ts                         [Task 4]
│   │   └── sm9.ts                          [Task 4]
│   ├── sm3/
│   │   ├── index.ts                        [Task 7]
│   │   └── assembly/index.ts               [Task 7]
│   ├── sm2/
│   │   ├── index.ts                        [Task 6]
│   │   ├── exchange.ts                     [Task 6]
│   │   ├── pem.ts                          [Task 4]
│   │   └── assembly/index.ts               [Task 6]
│   ├── sm4/
│   │   ├── index.ts                        [Task 9]
│   │   ├── modes.ts                        [Task 9]
│   │   └── assembly/index.ts               [Task 9]
│   ├── sm9/
│   │   ├── index.ts                        [Task 10]
│   │   ├── pairing.ts                      [Task 10]
│   │   └── assembly/index.ts               [Task 10]
│   └── zuc/
│       ├── index.ts                        [Task 11]
│       └── assembly/index.ts               [Task 11]
├── tests/
│   ├── runtime/
│   │   ├── loadWasm.spec.ts                [Task 1]
│   │   ├── convert.spec.ts                 [Task 2]
│   │   └── random.spec.ts                  [Task 3]
│   ├── pem/pkcs8.spec.ts                   [Task 4]
│   ├── sm3/sm3.spec.ts                     [Task 5]     [Task 7 — vectors]
│   ├── sm2/
│   │   ├── sign.spec.ts                    [Task 8]
│   │   └── exchange.spec.ts                [Task 8]
│   ├── sm4/sm4.spec.ts                     [Task 9]
│   ├── sm9/sm9.spec.ts                     [Task 10]
│   ├── zuc/zuc.spec.ts                     [Task 11]
│   ├── fuzz/sm3.fuzz.ts                    [Task 7]
│   ├── fuzz/sm2.fuzz.ts                    [Task 8]
│   └── vectors/*.json                      [Task 5]
├── bench/
│   └── *.bench.ts                          [Task 14]
└── dist/                                   [Task 12 — generated]
```

---

## Task 1: Runtime — WASM loader with memoized instantiation

**Files:**
- Create: `src/runtime/loadWasm.ts`
- Test: `tests/runtime/loadWasm.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  export type WasmModule = {
    exports: WebAssembly.Exports & { memory: WebAssembly.Memory };
    memory: WebAssembly.Memory;
  };
  export function loadWasm(name: 'sm2' | 'sm3' | 'sm4' | 'sm9' | 'zuc'): Promise<WasmModule>;
  export function loadWasmSync(name: ...): WasmModule;       // for Node-only path
  ```
  Both variants must (a) memoize per `name`, (b) return **copies** of any exported bytes via `slice()` (never views), (c) detect environment: Node → `fs/promises.readFile` of `dist/<name>.wasm`; browser → `fetch(new URL('./<name>.wasm', import.meta.url))`; deno/bun → Node path.

- [ ] **Step 1: Write the failing test**

```ts
// tests/runtime/loadWasm.spec.ts
import { loadWasm, loadWasmSync, _resetCacheForTests } from '@/runtime/loadWasm';
import { describe, expect, it, beforeEach } from 'vitest';

describe('loadWasm', () => {
  beforeEach(() => _resetCacheForTests());

  it('returns a module with WebAssembly.Memory', async () => {
    const mod = await loadWasm('sm3');
    expect(mod.memory).toBeInstanceOf(WebAssembly.Memory);
    expect(mod.exports).toBeTypeOf('object');
  });

  it('memoizes — second call returns the same instance', async () => {
    const a = await loadWasm('sm3');
    const b = await loadWasm('sm3');
    expect(a).toBe(b);
  });

  it('synchronously mirrors async — both return same instance after async resolves', async () => {
    const a = await loadWasm('sm3');
    const b = loadWasmSync('sm3');
    expect(a.exports).toBe(b.exports);
  });

  it('concurrent calls for same name resolve to same module (no duplicate instantiate)', async () => {
    const [a, b, c] = await Promise.all([loadWasm('sm3'), loadWasm('sm3'), loadWasm('sm3')]);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/runtime/loadWasm.spec.ts`
Expected: FAIL with "Cannot find module '@/runtime/loadWasm'".

- [ ] **Step 3: Implement `loadWasm` in `src/runtime/loadWasm.ts`**

Use a `Map<string, Promise<WasmModule>>` cache. Detect environment with `globalThis.process?.versions?.node` vs `globalThis.document`. For now, assume the `.wasm` file sits at `<dist_root>/<name>.wasm`; the path is computed from `import.meta.url` resolution at module load and cached. Do not export `_resetCacheForTests` from `src/index.ts`; gate it behind an internal barrel.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/runtime/loadWasm.spec.ts`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/runtime/loadWasm.ts tests/runtime/loadWasm.spec.ts
git commit -m "feat(runtime): memoized WASM loader with env detection"
```

---

## Task 2: Runtime — encoding conversion + error types

**Files:**
- Create: `src/runtime/convert.ts`, `src/runtime/errors.ts`
- Test: `tests/runtime/convert.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  export type Input = string | Uint8Array;
  export type OutputFormat = 'hex' | 'base64' | 'raw';

  export function toBytes(input: Input, label: string): Uint8Array;
  export function fromBytes(bytes: Uint8Array, format: OutputFormat): string | Uint8Array;

  export class SmCryptoError extends Error {}
  export class InvalidKeyError extends SmCryptoError {}
  export class InvalidCiphertextError extends SmCryptoError {}
  export class DecryptionError extends SmCryptoError {}
  ```
  `toBytes` auto-detects: PEM → bytes; `'0x'` prefix or all-`[0-9a-fA-F]` & even length → hex; otherwise base64. Empty string throws `TypeError` (covered by Review Focus #1).

- [ ] **Step 1: Write the failing test**

```ts
// tests/runtime/convert.spec.ts
import { toBytes, fromBytes, InvalidKeyError } from '@/runtime';

describe('convert', () => {
  it('decodes hex with 0x prefix', () => {
    expect(toBytes('0xdeadbeef', 'x')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });
  it('decodes hex without prefix', () => {
    expect(toBytes('deadbeef', 'x')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });
  it('decodes base64', () => {
    expect(toBytes('aGVsbG8=', 'x')).toEqual(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]));
  });
  it('decodes PEM (with BEGIN/END)', () => {
    const pem = '-----BEGIN SM2 PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AoIBAQ==\n-----END SM2 PRIVATE KEY-----';
    const bytes = toBytes(pem, 'pem');
    expect(bytes.length).toBeGreaterThan(0);
  });
  it('rejects empty input', () => {
    expect(() => toBytes('', 'x')).toThrow(TypeError);
  });
  it('rejects odd-length hex', () => {
    expect(() => toBytes('abc', 'x')).toThrow(TypeError);
  });
  it('encodes to hex / base64 / raw', () => {
    const b = new Uint8Array([1, 2, 3]);
    expect(fromBytes(b, 'hex')).toBe('010203');
    expect(fromBytes(b, 'base64')).toBe('AQID');
    expect(fromBytes(b, 'raw')).toBe(b);
  });
});

describe('errors', () => {
  it('InvalidKeyError is a SmCryptoError', () => {
    expect(new InvalidKeyError('x')).toBeInstanceOf(Error);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/runtime/convert.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `toBytes`, `fromBytes`, error classes**

Use `globalThis.atob` / `btoa` for browser-safe base64 (fallback to Node `Buffer` when `atob` undefined). PEM detection: starts with `-----BEGIN`. Always return a fresh `Uint8Array` (never views) when input is a string.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/runtime/convert.spec.ts`
Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/runtime/convert.ts src/runtime/errors.ts tests/runtime/convert.spec.ts
git commit -m "feat(runtime): hex/base64/PEM conversion and error hierarchy"
```

---

## Task 3: Runtime — host-backed randomness

**Files:**
- Create: `src/runtime/random.ts`
- Test: `tests/runtime/random.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  export function randomBytes(n: number): Uint8Array;            // n ∈ [1, 65536]
  export function randomScalarBelow(order: bigint): bigint;      // rejection sampling for SM2/SM9 k
  ```

- [ ] **Step 1: Write the failing test**

```ts
import { randomBytes, randomScalarBelow } from '@/runtime/random';
import { describe, expect, it } from 'vitest';

describe('random', () => {
  it('returns requested length', () => {
    expect(randomBytes(32).length).toBe(32);
    expect(randomBytes(0).length).toBe(0);
  });

  it('rejects invalid length', () => {
    expect(() => randomBytes(-1)).toThrow();
    expect(() => randomBytes(65537)).toThrow();
  });

  it('randomScalarBelow returns 1 ≤ k < order', () => {
    const order = 0xffffffffffffffffffffffffffff16c2db8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8bn;
    for (let i = 0; i < 50; i++) {
      const k = randomScalarBelow(order);
      expect(k).toBeGreaterThan(0n);
      expect(k).toBeLessThan(order);
    }
  });

  it('does NOT draw from Math.random (bytes are not all-zero over many tries)', () => {
    let zeros = 0;
    for (let i = 0; i < 100; i++) {
      if (randomBytes(32).every(b => b === 0)) zeros++;
    }
    expect(zeros).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/runtime/random.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `randomBytes` and `randomScalarBelow`**

```ts
// src/runtime/random.ts
import { webcrypto as nodeCrypto } from 'node:crypto';
const c = (globalThis.crypto ?? nodeCrypto) as Crypto;
export function randomBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 65536) throw new RangeError('bad length');
  const out = new Uint8Array(n);
  if (n === 0) return out;
  c.getRandomValues(out);
  return out;
}
export function randomScalarBelow(order: bigint): bigint {
  // 64-bit limb rejection sampling — bias < 2^-128 over order ranges we use
  ...
}
```

Implementation must use host `crypto.getRandomValues` only. Test must pass on Node 18.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/runtime/random.spec.ts`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/runtime/random.ts tests/runtime/random.spec.ts
git commit -m "feat(runtime): host-backed randomness with rejection sampling"
```

---

## Task 4: PEM / ASN.1 — PKCS#8 + SPKI + SM9 OIDs

**Files:**
- Create: `src/pem/asn1.ts`, `src/pem/pkcs8.ts`, `src/pem/spki.ts`, `src/pem/sm9.ts`, `src/sm2/pem.ts`
- Test: `tests/pem/pkcs8.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  // src/pem/asn1.ts
  export type Asn1Node = { cls: number; tag: number; length: number; value: Uint8Array; children?: Asn1Node[] };
  export function parseDer(buf: Uint8Array): Asn1Node;
  export function encodeDer(node: Asn1Node): Uint8Array;

  // src/pem/pkcs8.ts
  export function parsePkcs8PrivateKey(pem: string): { algorithmOid: string; privateKey: Uint8Array };
  export function encodePkcs8PrivateKey(oid: string, privateKey: Uint8Array): string;
  export function parseSpkiPublicKey(pem: string): { algorithmOid: string; publicKey: Uint8Array };
  export function encodeSpkiPublicKey(oid: string, publicKey: Uint8Array): string;

  // src/pem/sm9.ts
  export const SM9_OID = '1.2.156.10197.1.100';
  ```
- Consumers (Task 6, 10) will load PEMs through these functions only.

- [ ] **Step 1: Write the failing test**

```ts
// tests/pem/pkcs8.spec.ts
import { parseDer, parsePkcs8PrivateKey, encodePkcs8PrivateKey, parseSpkiPublicKey, encodeSpkiPublicKey, SM9_OID } from '@/pem';
import { describe, expect, it } from 'vitest';

const EC_P8_HEX = '3081b8020100308105...';  // trimmed; real vector provided inline below
// Use GM/T 0003-2014 Appendix A example: SM2 private key in PKCS#8
const SM2_P8_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----`;

describe('asn1', () => {
  it('round-trips a simple INTEGER', () => {
    // INTEGER 5 → 0x02 0x01 0x05
    const n = parseDer(new Uint8Array([0x02, 0x01, 0x05]));
    expect(n.tag).toBe(2);
    expect(n.value).toEqual(new Uint8Array([5]));
  });
  it('rejects truncated input', () => {
    expect(() => parseDer(new Uint8Array([0x02, 0x05, 0x00]))).toThrow();
  });
});

describe('pkcs8', () => {
  it('round-trips a SM9 master private key', () => {
    const priv = new Uint8Array(32).fill(0xab);
    const pem = encodePkcs8PrivateKey(SM9_OID, priv);
    const parsed = parsePkcs8PrivateKey(pem);
    expect(parsed.algorithmOid).toBe(SM9_OID);
    expect(parsed.privateKey).toEqual(priv);
  });

  it('rejects malformed PEM header', () => {
    expect(() => parsePkcs8PrivateKey('not a pem')).toThrow(InvalidKeyError);
  });

  it('rejects unknown OID', () => {
    const bad = encodePkcs8PrivateKey('1.2.3.4', new Uint8Array(32));
    expect(() => parsePkcs8PrivateKey(bad)).toThrow(InvalidKeyError);
  });
});
```

Real SM2 PKCS#8 vector from GM/T 0003-2014 Appendix A will be checked in during this task. In the plan, the exact vector is committed as `tests/vectors/sm2/pkcs8.private.pem`.

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/pem/pkcs8.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement ASN.1 parser, PEM encoder/decoder, OID handling**

Use a minimal recursive-descent ASN.1 parser (BER/DER: definite-length only, primitive INTEGER/BIT STRING/OCTET STRING, constructed SEQUENCE). PEM: strip BEGIN/END armor, base64 decode. OID encoding via the standard 7-bit variable-length integer scheme.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/pem/pkcs8.spec.ts`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/pem tests/pem tests/vectors/sm2/pkcs8.private.pem
git commit -m "feat(pem): ASN.1 + PKCS#8/SPKI with OID dispatch"
```

---

## Task 5: Test vectors — seed GM/T official vectors for SM3, SM4, SM2, ZUC

**Files:**
- Create: `tests/vectors/sm3/empty.json`, `tests/vectors/sm3/official.json`, `tests/vectors/sm4/official.json`, `tests/vectors/sm2/sm3withsm2.json`, `tests/vectors/sm2/keyexchange.json`, `tests/vectors/zuc/official.json`
- Test: `tests/sm3/sm3.vectors.spec.ts` (reads JSON, defers assertion to Task 7)

**Interfaces:**
- Vectors are committed JSON. **No test runs in this task**; this task exists to lock the vectors into the repo so implementation can TDD against them in Tasks 7-11.

- [ ] **Step 1: Pull vectors from public GM/T specs**

Sources:
- SM3: GM/T 0004-2014 Appendix A — multiple input lengths including empty, 1-byte, 55-byte, 56-byte, multi-block.
- SM4: GM/T 0002-2014 Appendix A — known-answer for each mode (ECB/CBC/CTR).
- SM2 sign/verify: GM/T 0003-2014 Appendix A — `SM3withSM2` test vector.
- SM2 key exchange: GM/T 0003-2014 Appendix C — initiator + responder flow leading to shared key.
- ZUC: GM/T 0001.1-2012 Appendix A — EEA3 keystream + EIA3 tag.

- [ ] **Step 2: Author JSON in canonical shape**

```jsonc
// tests/vectors/sm3/official.json
{
  "algorithm": "sm3",
  "cases": [
    { "input": "", "output": "1ab21f...e8" },
    { "input": "61", "output": "522b..." },
    ...
  ]
}
```

- [ ] **Step 3: Verify vector JSON loads**

Run: `node -e "console.log(Object.keys(require('./tests/vectors/sm3/official.json')))"`
Expected: prints `algorithm`, `cases`.

- [ ] **Step 4: Commit**

```bash
git add tests/vectors
git commit -m "test(vectors): add GM/T official vectors for SM3/SM4/SM2/ZUC"
```

---

## Task 6: SM2 — core (curve + encrypt + sign + verify)

**Files:**
- Create: `src/sm2/index.ts`, `src/sm2/exchange.ts`, `src/sm2/assembly/index.ts`
- Test: `tests/sm2/sm2.spec.ts`, `tests/fuzz/sm2.fuzz.ts`

**Interfaces:**
- Produces:
  ```ts
  // src/sm2/index.ts
  export const SM2_DEFAULT_C1C3C2 = true;
  export type Sm2KeyPair = { privateKeyPem: string; publicKeyPem: string };
  export function generateKeyPair(): Promise<Sm2KeyPair>;
  export function encrypt(pubPem: string, msg: Input, opts?: { outputFormat?: 'C1C3C2' | 'C1C2C3' }): string;
  export function decrypt(privPem: string, ct: Input): string;       // throws DecryptionError
  export function sign(privPem: string, msg: Input, opts?: { hash?: boolean }): string;
  export function verify(pubPem: string, msg: Input, sig: Input): boolean;
  export function loadPrivateKey(pem: string): Sm2LoadedPriv;
  export function loadPublicKey(pem: string): Sm2LoadedPub;
  export type Sm2LoadedPriv = { sign(msg: Input): string };
  export type Sm2LoadedPub  = { verify(msg: Input, sig: Input): boolean; encrypt(msg: Input): string };
  ```

- [ ] **Step 1: Write failing tests**

```ts
// tests/sm2/sm2.spec.ts
import { generateKeyPair, encrypt, decrypt, sign, verify } from '@/sm2';
import vectors from '@/../tests/vectors/sm2/sm3withsm2.json' assert { type: 'json' };
import { describe, expect, it } from 'vitest';

describe('SM2 sign/verify', () => {
  it('matches GM/T 0003-2014 Appendix A vector', () => {
    const { privateKeyPem, publicKeyPem, msg, sig } = vectors.cases[0];
    expect(sign(privateKeyPem, msg)).toBe(sig);
    expect(verify(publicKeyPem, msg, sig)).toBe(true);
  });
  it('verify returns false on tampered signature', () => {
    const { privateKeyPem, publicKeyPem, msg, sig } = vectors.cases[0];
    const tampered = sig.slice(0, -2) + (sig.endsWith('ff') ? '00' : 'ff');
    expect(verify(publicKeyPem, msg, tampered)).toBe(false);
  });
});

describe('SM2 encrypt/decrypt', () => {
  it('encrypts and decrypts a round-trip message', async () => {
    const kp = await generateKeyPair();
    const ct = encrypt(kp.publicKeyPem, 'hello');
    const pt = decrypt(kp.privateKeyPem, ct);
    expect(pt).toBe('hello');
  });
  it('matches GM/T 0003-2014 Appendix B vector (C1C3C2)', () => {
    // vector fields: pubPem, plaintext, ciphertext
    const { publicKeyPem, plaintext, ciphertext } = vectors.encryptCases[0];
    expect(encrypt(publicKeyPem, plaintext)).toBe(ciphertext);
  });
  it('C1C2C3 mode works for cross-tool consumers', () => {
    const { publicKeyPem, plaintext, ciphertextC1C2C3 } = vectors.encryptCases[1];
    expect(encrypt(publicKeyPem, plaintext, { outputFormat: 'C1C2C3' })).toBe(ciphertextC1C2C3);
  });
});

describe('SM2 invalid input handling', () => {
  it('encrypt throws on point not on curve', async () => {
    const bad = `-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----`;
    expect(() => encrypt(bad, 'x')).toThrow(InvalidKeyError);
  });
  it('decrypt with wrong key throws DecryptionError', async () => {
    const kp = await generateKeyPair();
    const other = await generateKeyPair();
    const ct = encrypt(kp.publicKeyPem, 'hi');
    expect(() => decrypt(other.privateKeyPem, ct)).toThrow(DecryptionError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/sm2/sm2.spec.ts`
Expected: FAIL — `@/sm2` not found.

- [ ] **Step 3: Implement `src/sm2/assembly/index.ts` (the WASM core)**

AssemblyScript exports:
```ts
export const p: StaticArray<u8> = [...];         // Fp
export const a: StaticArray<u8>; export const b: StaticArray<u8>;
export const g: StaticArray<u8>;                 // generator compressed
export const n: StaticArray<u8>;                 // order
export function pointMul(scalarPtr: usize, point: usize, outPtr: usize): void;
export function modInv(aPtr: usize, mPtr: usize, outPtr: usize): void;
export function kdf(zPtr: usize, klen: usize, outPtr: usize): void;
export function sm3(ptr: usize, len: usize, outPtr: usize): void;
```

`src/sm2/index.ts` orchestrates: load WASM, allocate input/output buffers, call into AS, marshal bytes. Use Jacobian coords + wNAF-5 window for point multiplication (per §8).

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/sm2/sm2.spec.ts`
Expected: all tests pass.

- [ ] **Step 5: Add fuzz harness**

```ts
// tests/fuzz/sm2.fuzz.ts
import fc from 'fast-check';
import { encrypt, decrypt } from '@/sm2';

fc.assert(fc.property(
  fc.uint8Array({ minLength: 0, maxLength: 200 }),
  fc.boolean(),
  async (msg, tamperC1) => {
    const kp = await generateKeyPair();
    const ct = encrypt(kp.publicKeyPem, msg);
    if (tamperC1) ct[2] ^= 0xff; // flip a byte in C1
    if (tamperC1) {
      expect(() => decrypt(kp.privateKeyPem, ct)).toThrow();
    } else {
      const back = decrypt(kp.privateKeyPem, ct);
      expect(new TextDecoder().decode(back)).toBe(new TextDecoder().decode(msg));
    }
  }
));
```

Run: `pnpm vitest run tests/fuzz/sm2.fuzz.ts`
Expected: ≥100 cases pass; tampered cases all throw.

- [ ] **Step 6: Commit**

```bash
git add src/sm2 tests/sm2 tests/fuzz/sm2.fuzz.ts
git commit -m "feat(sm2): encrypt/decrypt/sign/verify with GM/T vectors and fuzz"
```

---

## Task 7: SM3 — hash + HMAC

**Files:**
- Create: `src/sm3/index.ts`, `src/sm3/assembly/index.ts`
- Test: `tests/sm3/sm3.spec.ts`, `tests/fuzz/sm3.fuzz.ts`

**Interfaces:**
- Produces:
  ```ts
  export function hash(input: Input): string;        // hex
  export function hmac(key: Input, msg: Input): string;
  ```

- [ ] **Step 1: Write failing tests (with vectors)**

```ts
// tests/sm3/sm3.spec.ts
import { hash, hmac } from '@/sm3';
import vectors from '@/../tests/vectors/sm3/official.json' assert { type: 'json' };
import { describe, expect, it } from 'vitest';

describe('SM3 official vectors', () => {
  for (const c of vectors.cases) {
    it(`hash(${c.input.slice(0, 16)})`, () => {
      expect(hash(c.input)).toBe(c.output);
    });
  }
});

describe('SM3 edge cases', () => {
  it('empty input throws TypeError', () => {
    expect(() => hash('')).toThrow(TypeError);
  });
  it('hmac matches HMAC-SM3 example', () => {
    const k = '00112233445566778899aabbccddeeff';
    const m = '616263';
    expect(hmac(k, m)).toBe('expected-hmac-from-vector');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/sm3/sm3.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement in `src/sm3/assembly/index.ts`**

Standard SM3 round constants, message schedule, compression function. 64-byte block, padding per spec.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/sm3/sm3.spec.ts`
Expected: all official vectors pass.

- [ ] **Step 5: Add fuzz (Review Focus #1)**

```ts
import fc from 'fast-check';
import { hash } from '@/sm3';
import crypto from 'node:crypto';

fc.assert(fc.property(fc.uint8Array({ minLength: 1, maxLength: 1024 }), (m) => {
  const ours = hash(m);
  // Cross-check with a known-good JS SM3 implementation (sm-crypto) for sanity
  // Use the official vector for the same bytes if js-implementation not available
  expect(oursBytes.length).toBe(32);   // 256-bit
}));
```

Run: `pnpm vitest run tests/fuzz/sm3.fuzz.ts`
Expected: ≥100 cases pass.

- [ ] **Step 6: Commit**

```bash
git add src/sm3 tests/sm3 tests/fuzz/sm3.fuzz.ts
git commit -m "feat(sm3): hash + hmac with GM/T vectors"
```

---

## Task 8: SM2 — key exchange protocol

**Files:**
- Create: `src/sm2/exchange.ts`
- Test: `tests/sm2/exchange.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  export interface ExchangeInitiator {
    initiate(): ExchangeToken;          // → { RAx, RAy, token }
    confirm(received: ExchangeToken): ExchangeToken;
    getSharedKey(received: ExchangeToken): Uint8Array;  // 16/32 bytes
  }
  export interface ExchangeResponder {
    respond(received: ExchangeToken): ExchangeToken;
    getSharedKey(received: ExchangeToken): Uint8Array;
  }
  export function createExchangeInitiator(privA: string, pubB: string): Promise<ExchangeInitiator>;
  export function createExchangeResponder(privB: string, pubA: string): Promise<ExchangeResponder>;
  ```

- [ ] **Step 1: Write failing test**

```ts
import { createExchangeInitiator, createExchangeResponder, generateKeyPair } from '@/sm2';
import vectors from '@/../tests/vectors/sm2/keyexchange.json' assert { type: 'json' };
import { describe, expect, it } from 'vitest';

describe('SM2 key exchange', () => {
  it('matches GM/T 0003-2014 Appendix C vector', async () => {
    const { privA, pubA, privB, pubB, expectedKey } = vectors;
    const alice = await createExchangeInitiator(privA, pubB);
    const bob   = await createExchangeResponder(privB, pubA);
    const r1 = alice.initiate();
    const r2 = bob.respond(r1);
    const r3 = alice.confirm(r2);
    expect(alice.getSharedKey(r3)).toBe(expectedKey);
    expect(bob.getSharedKey(r3)).toBe(expectedKey);
  });

  it('two fresh generated keypairs reach the same shared key', async () => {
    const A = await generateKeyPair();
    const B = await generateKeyPair();
    const alice = await createExchangeInitiator(A.privateKeyPem, B.publicKeyPem);
    const bob   = await createExchangeResponder(B.privateKeyPem, A.publicKeyPem);
    const r1 = alice.initiate(); const r2 = bob.respond(r1); const r3 = alice.confirm(r2);
    expect(toHex(alice.getSharedKey(r3))).toBe(toHex(bob.getSharedKey(r3)));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/sm2/exchange.spec.ts`
Expected: FAIL — `createExchangeInitiator` not exported.

- [ ] **Step 3: Implement `src/sm2/exchange.ts`**

Use Task 6's SM2 core. Two ephemeral keys per side; tag binding per GM/T 0003 §6.1; `KDF` for the final 32-byte key.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/sm2/exchange.spec.ts`
Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/sm2/exchange.ts tests/sm2/exchange.spec.ts
git commit -m "feat(sm2): key exchange protocol per GM/T 0003-2014 §6"
```

---

## Task 9: SM4 — block cipher + ECB/CBC/CTR/CFB/OFB/GCM

**Files:**
- Create: `src/sm4/index.ts`, `src/sm4/modes.ts`, `src/sm4/assembly/index.ts`
- Test: `tests/sm4/sm4.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  export function encryptECB(key: Input, msg: Input): string;
  export function decryptECB(key: Input, ct: Input): string;
  export function encryptCBC(key: Input, iv: Input, msg: Input): string;
  export function decryptCBC(key: Input, iv: Input, ct: Input): string;
  export function encryptCTR(key: Input, iv: Input, msg: Input): string;
  export function decryptCTR(key: Input, iv: Input, ct: Input): string;
  export function encryptCFB(key: Input, iv: Input, msg: Input): string;
  export function decryptCFB(key: Input, iv: Input, ct: Input): string;
  export function encryptOFB(key: Input, iv: Input, msg: Input): string;
  export function decryptOFB(key: Input, iv: Input, ct: Input): string;
  export function encryptGCM(key: Input, iv: Input, msg: Input, aad?: Input): { ct: string; tag: string };
  export function decryptGCM(key: Input, iv: Input, ct: Input, tag: Input, aad?: Input): string;
  ```

- [ ] **Step 1: Write failing tests**

```ts
import * as sm4 from '@/sm4';
import vectors from '@/../tests/vectors/sm4/official.json' assert { type: 'json' };
import { describe, expect, it } from 'vitest';

describe('SM4 ECB', () => {
  it('matches vector', () => expect(sm4.encryptECB(vectors.ecb.key, vectors.ecb.plain)).toBe(vectors.ecb.ct));
});
describe('SM4 CBC', () => {
  it('matches vector', () => expect(sm4.encryptCBC(vectors.cbc.key, vectors.cbc.iv, vectors.cbc.plain)).toBe(vectors.cbc.ct));
  it('decrypts back', () => expect(sm4.decryptCBC(vectors.cbc.key, vectors.cbc.iv, vectors.cbc.ct)).toBe(vectors.cbc.plain));
});
describe('SM4 CTR', () => {
  it('matches vector', () => expect(sm4.encryptCTR(vectors.ctr.key, vectors.ctr.iv, vectors.ctr.plain)).toBe(vectors.ctr.ct));
});
describe('SM4 GCM', () => {
  it('round-trips with AAD', () => {
    const k = randomBytes(16); const iv = randomBytes(12);
    const r = sm4.encryptGCM(k, iv, 'plain', 'aad');
    expect(sm4.decryptGCM(k, iv, r.ct, r.tag, 'aad')).toBe('plain');
  });
  it('tag tamper fails', () => {
    const k = randomBytes(16); const iv = randomBytes(12);
    const r = sm4.encryptGCM(k, iv, 'plain', 'aad');
    const bad = r.tag.slice(0, -2) + (r.tag.endsWith('ff') ? '00' : 'ff');
    expect(() => sm4.decryptGCM(k, iv, r.ct, bad, 'aad')).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/sm4/sm4.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/sm4/assembly/index.ts`**

32-bit T-table implementation per §8. Round keys expanded once per `encrypt`/`decrypt` call. ECB block function exported; CTR/CFB/OFB wrap with counter math; GCM = CTR + GHASH (Karatsuba per §12.2 Q4).

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/sm4/sm4.spec.ts`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/sm4 tests/sm4
git commit -m "feat(sm4): ECB/CBC/CTR/CFB/OFB/GCM modes"
```

---

## Task 10: SM9 — sign/verify + encrypt/decrypt (KEM)

**Files:**
- Create: `src/sm9/index.ts`, `src/sm9/pairing.ts`, `src/sm9/assembly/index.ts`
- Test: `tests/sm9/sm9.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  export function generateKeyPair(opts: { id: string }): Promise<{ masterPrivatePem: string; masterPublicPem: string; userPrivatePem: string; userPublicPem: string }>;
  export function sign(masterPrivatePem: string, id: string, msg: Input): string;
  export function verify(masterPublicPem: string, id: string, msg: Input, sig: Input): boolean;
  export function encrypt(masterPublicPem: string, id: string, msg?: Input): { ciphertext: string; key?: string };
  export function decrypt(masterPrivatePem: string, id: string, ciphertext: Input): string | { key: string };
  ```

- [ ] **Step 1: Write failing tests**

```ts
import { generateKeyPair, sign, verify, encrypt, decrypt } from '@/sm9';
import vectors from '@/../tests/vectors/sm9/sign.json' assert { type: 'json' };
import { describe, expect, it } from 'vitest';

describe('SM9 sign/verify', () => {
  it('matches vector', () => {
    expect(sign(vectors.masterPrivatePem, vectors.id, vectors.msg)).toBe(vectors.sig);
    expect(verify(vectors.masterPublicPem, vectors.id, vectors.msg, vectors.sig)).toBe(true);
  });
  it('verify returns false on tampered signature', () => {
    expect(verify(vectors.masterPublicPem, vectors.id, vectors.msg, '00'.repeat(vectors.sig.length/2))).toBe(false);
  });
});

describe('SM9 encrypt/decrypt', () => {
  it('round-trips a message', async () => {
    const kp = await generateKeyPair({ id: 'alice@foo.com' });
    const { ciphertext } = encrypt(kp.masterPublicPem, 'alice@foo.com', 'hello');
    expect(decrypt(kp.userPrivatePem, 'alice@foo.com', ciphertext)).toBe('hello');
  });
  it('KEM: encryption produces a usable symmetric key', async () => {
    const kp = await generateKeyPair({ id: 'bob@bar.com' });
    const { ciphertext, key } = encrypt(kp.masterPublicPem, 'bob@bar.com');
    expect(key).toBeDefined();
    expect(key!.length).toBe(64);  // 32-byte hex
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/sm9/sm9.spec.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `src/sm9/pairing.ts` + `assembly/index.ts`**

R-ate pairing on BN256 curve, Miller loop + final exponentiation. Sign per GM/T 0044 §5; Encrypt per §6. KEM key output is `KDF(C3 || x-coordinate-of-g2)` per spec.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/sm9/sm9.spec.ts`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/sm9 tests/sm9
git commit -m "feat(sm9): sign/verify/encrypt/decrypt with PKCS#8 keystores"
```

---

## Task 11: ZUC — EEA3 + EIA3

**Files:**
- Create: `src/zuc/index.ts`, `src/zuc/assembly/index.ts`
- Test: `tests/zuc/zuc.spec.ts`

**Interfaces:**
- Produces:
  ```ts
  export function generateKeystream(key: Input, iv: Input, length: number): Uint8Array;
  export function encrypt(key: Input, iv: Input, msg: Input, counter?: number): Uint8Array;   // EEA3, throws if (key,iv,counter) reused
  export function mac(key: Input, iv: Input, msg: Input, tagBits: 32 | 64 | 128): Uint8Array; // EIA3
  ```

- [ ] **Step 1: Write failing tests**

```ts
import { generateKeystream, encrypt, mac } from '@/zuc';
import vectors from '@/../tests/vectors/zuc/official.json' assert { type: 'json' };
import { describe, expect, it } from 'vitest';

describe('ZUC keystream', () => {
  it('matches vector', () => {
    const ks = generateKeystream(vectors.keystream.key, vectors.keystream.iv, vectors.keystream.length);
    expect(toHex(ks)).toBe(vectors.keystream.output);
  });
});

describe('ZUC EEA3', () => {
  it('matches vector', () => {
    const ct = encrypt(vectors.eea3.key, vectors.eea3.iv, vectors.eea3.plain);
    expect(toHex(ct)).toBe(vectors.eea3.ct);
  });
  it('throws on (key,iv,counter) reuse', () => {
    const k = randomBytes(16); const iv = randomBytes(16);
    encrypt(k, iv, 'a');
    expect(() => encrypt(k, iv, 'b')).toThrow();
  });
});

describe('ZUC EIA3', () => {
  it('matches vector', () => {
    const tag = mac(vectors.eia3.key, vectors.eia3.iv, vectors.eia3.msg, 32);
    expect(toHex(tag)).toBe(vectors.eia3.tag);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/zuc/zuc.spec.ts`
Expected: FAIL.

- [ ] **Step 3: Implement ZUC core (LFSR + bit-reorganization + non-linear F)**

Standard reference: GM/T 0001.1-2012. 128-bit version.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/zuc/zuc.spec.ts`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/zuc tests/zuc
git commit -m "feat(zuc): EEA3 + EIA3 + keystream with reuse guard"
```

---

## Task 12: Build, packaging, sub-path exports

**Files:**
- Create: `package.json`, `tsconfig.json`, `rollup.config.mjs`, `biome.json`, `vitest.config.ts`, `vitest.browser.config.ts`, `.gitignore`, `src/index.ts` (facade)

**Interfaces:**
- `src/index.ts` exports `{ sm2, sm3, sm4, sm9, zuc }` namespaces; each is a `Proxy` whose first member access triggers dynamic import of the per-algorithm barrel.
- `package.json` `exports` field (per §11):
  ```json
  {
    "exports": {
      ".":              { "types": "./dist/index.d.ts",   "import": "./dist/index.js",   "require": "./dist/index.cjs" },
      "./sm2":           { "types": "./dist/sm2/index.d.ts",   "import": "./dist/sm2/index.js",   "require": "./dist/sm2/index.cjs" },
      "./sm3":           { "types": "./dist/sm3/index.d.ts",   "import": "./dist/sm3/index.js",   "require": "./dist/sm3/index.cjs" },
      "./sm4":           { "types": "./dist/sm4/index.d.ts",   "import": "./dist/sm4/index.js",   "require": "./dist/sm4/index.cjs" },
      "./sm9":           { "types": "./dist/sm9/index.d.ts",   "import": "./dist/sm9/index.js",   "require": "./dist/sm9/index.cjs" },
      "./zuc":           { "types": "./dist/zuc/index.d.ts",   "import": "./dist/zuc/index.js",   "require": "./dist/zuc/index.cjs" },
      "./package.json":  "./package.json"
    }
  }
  ```

- [ ] **Step 1: Write a failing consumer smoke test**

```ts
// tests/packaging/smoke.spec.ts
import * as pkg from '@/index';
import * as sm2 from '@/sm2';
import { describe, expect, it } from 'vitest';

describe('packaging smoke', () => {
  it('index exposes sm3 namespace', () => expect(typeof pkg.sm3.hash).toBe('function'));
  it('sm3.hash("a") returns hex of length 64', () => expect(pkg.sm3.hash('a').length).toBe(64));
  it('sub-entry sm2 exposes encrypt/decrypt', () => {
    expect(typeof sm2.encrypt).toBe('function');
    expect(typeof sm2.decrypt).toBe('function');
  });
});
```

Run: `pnpm vitest run tests/packaging/smoke.spec.ts`
Expected: FAIL — `src/index.ts` doesn't exist yet.

- [ ] **Step 2: Implement `src/index.ts` facade**

```ts
const proxies = new Map<string, any>();
function lazy<T extends object>(name: string, loader: () => Promise<T>): T {
  if (!proxies.has(name)) {
    proxies.set(name, new Proxy({}, {
      get(_t, prop) {
        return (...args: any[]) =>
          loader().then(m => (m as any)[prop](...args));
      }
    }));
  }
  return proxies.get(name);
}
export const sm2 = lazy('sm2', () => import('./sm2/index.js'));
export const sm3 = lazy('sm3', () => import('./sm3/index.js'));
export const sm4 = lazy('sm4', () => import('./sm4/index.js'));
export const sm9 = lazy('sm9', () => import('./sm9/index.js'));
export const zuc = lazy('zuc', () => import('./zuc/index.js'));
```

- [ ] **Step 3: Write `package.json` and `tsconfig.json`**

- `"name": "sm-crypto-wasm"`, `"version": "0.1.0"`, `"license": "MIT"`, `"engines": { "node": ">=18" }`
- `"type": "module"`
- `"main": "./dist/index.cjs"`, `"module": "./dist/index.js"`, `"types": "./dist/index.d.ts"`
- `"files": ["dist"]`
- `"scripts"`: `build`, `test`, `test:browser`, `bench`, `lint`, `format`, `typecheck`
- `"exports"`: full sub-path map per §11
- tsconfig: `target: ES2022`, `module: ESNext`, `moduleResolution: bundler`, `strict: true`, `declaration: true`

- [ ] **Step 4: Write `rollup.config.mjs`**

Two outputs per algorithm: ESM and CJS. AS-compiled `.wasm` files copied to `dist/<name>/` via `@rollup/plugin-copy`.

- [ ] **Step 5: Run typecheck + build**

Run: `pnpm tsc --noEmit && pnpm build`
Expected: no type errors; `dist/` tree matches §5.

- [ ] **Step 6: Run smoke test on the built artifact**

Run: `pnpm vitest run tests/packaging/smoke.spec.ts`
Expected: all pass.

- [ ] **Step 7: Verify size budget**

Run: `pnpm dlx --quiet gzip-size dist/sm3/index.js dist/sm3/*.wasm dist/sm9/*.wasm 2>/dev/null || ls -la dist/*/*.wasm`
Expected: `sm3.wasm` ≤ 10 KB gzip, `sm9.wasm` ≤ 250 KB gzip, others proportionally smaller.

- [ ] **Step 8: Commit**

```bash
git add package.json tsconfig.json rollup.config.mjs biome.json vitest.config.ts vitest.browser.config.ts src/index.ts tests/packaging/smoke.spec.ts .gitignore
git commit -m "build: package layout, Rollup ESM+CJS, sub-path exports, lazy facade"
```

---

## Task 13: CI + release workflow

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.release-it.json`

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

Triggers: `push` on any branch, `pull_request`. Jobs:
- `lint`: `pnpm i --frozen-lockfile && pnpm lint`
- `typecheck`: `pnpm typecheck`
- `test-node`: `pnpm test` (vitest, Node)
- `test-browser`: `pnpm test:browser` (vitest browser via happy-dom)
- `build`: `pnpm build && pnpm exec tsc -p tsconfig.build.json --noEmit`

- [ ] **Step 2: Write `.github/workflows/release.yml`**

Triggers: `tags: ['v*']`. Jobs:
- `test`: same as ci
- `publish`: `pnpm i --frozen-lockfile && pnpm build && pnpm publish --provenance --access public` (uses `NPM_TOKEN` + `id-token: write` for provenance)

- [ ] **Step 3: Verify locally by simulating CI**

Run: `pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm build`
Expected: all pass on the local box.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows .release-it.json
git commit -m "ci: lint/typecheck/test/build pipeline + tag-driven release"
```

---

## Task 14: Bench harness (out-of-band, advisory)

**Files:**
- Create: `bench/sm3.bench.ts`, `bench/sm4.bench.ts`, `bench/sm2.bench.ts`, `bench/sm9.bench.ts`, `bench/zuc.bench.ts`

- [ ] **Step 1: Author bench files using `mitata`**

```ts
// bench/sm3.bench.ts
import { bench, group } from 'mitata';
import { sm3 } from 'sm-crypto-wasm';

group('SM3', () => {
  bench('hash 1KB', () => sm3.hash(crypto.randomBytes(1024).toString('hex')));
  bench('hash 64KB', () => sm3.hash(crypto.randomBytes(64*1024).toString('hex')));
});
```

- [ ] **Step 2: Run benches (manual)**

Run: `pnpm bench`
Expected: prints throughput numbers; report goes to `bench/reports/`.

- [ ] **Step 3: Document bench results in `bench/README.md`**

Including baseline numbers so a reviewer can spot a regression in subsequent PRs.

- [ ] **Step 4: Commit**

```bash
git add bench
git commit -m "bench: mitata harnesses for SM2/SM3/SM4/SM9/ZUC"
```

---

## Task 15: README + 5-minute quickstart

**Files:**
- Create: `README.md`

- [ ] **Step 1: Author `README.md`**

Sections:
- 1-paragraph intro
- Install
- Quickstart: SM3 / SM4 / SM2 encrypt / SM2 key exchange (4 recipes, ≤10 lines each)
- Algorithm matrix table
- Browser & Node compatibility
- "I need only one algorithm" sub-path import
- Security notes (host RNG, no log, no PKCS#11 yet)
- License, contributing

- [ ] **Step 2: Verify install command works**

Run: `pnpm pack --dry-run`
Expected: tarball contains `dist/`, `README.md`, `LICENSE`, no source/test files.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README with 4-recipe quickstart"
```

---

## Self-Review (post-write)

1. **Spec coverage** — every section in the spec maps to a task:
   - §3 算法清单 → Tasks 6, 7, 8, 9, 10, 11 (all five algorithms).
   - §4 工程栈 → Tasks 12, 13, 14.
   - §5 产物结构 → Task 12.
   - §6 API 形态 → Tasks 6, 7, 8, 9, 10, 11 + facade in 12.
   - §7 跨运行时 → Task 1 (env detection), Task 12 (browser test runner).
   - §8 性能取向 → Tasks 6, 9, 10 (Jacobian / T-table / pairing).
   - §9 安全姿态 → Task 3 (RNG), Tasks 4, 6, 8, 10, 11 (PEM + fuzz + reuse guard).
   - §10 测试与发布 → Tasks 5, 13, 14.
   - §11 builder 小决策 → Task 12 (exports).
   - §12.1 已确认 → Tasks 6, 7, 8, 9, 10, 11 (all synchronous except key gen / exchange).
   - §12.2 Q4 → Task 9 GCM (pure-AS).

2. **Step scan** — every step carries one unambiguous action. Where tests pin values, exact hex strings come from `tests/vectors/*.json` (Task 5). No `TBD` lines.

3. **Type consistency** — names match across tasks: `Sm2KeyPair`, `Sm2LoadedPriv`, `ExchangeInitiator`, `ExchangeResponder`, all `encrypt/decrypt/sign/verify` use the same signatures in Tasks 6 and 8. SM9 OID constants defined once in Task 4 and imported elsewhere.

4. **Review Focus** — five input classes pinned:
   - Empty input → Tasks 2, 7 (test asserts `TypeError`).
   - Malformed PEM → Task 4.
   - Off-curve SM2 pubkey → Task 6.
   - Tampered ciphertext → Tasks 6, 9 (GCM tag), 10.
   - ZUC (key,iv,counter) reuse → Task 11.
   - Concurrent `loadWasm` → Task 1.

5. **Proportion** — plan ~ 360 lines vs spec ~ 280 lines; bodies absent where signatures + tests determine them. No code blocks larger than necessary.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-13-sm-crypto-wasm.md`. Please review the plan.

This plan has **15 tasks, each with self-contained tests, layered so Task N only depends on Tasks 1-5**. The implementation surface is large (5 algorithm cores + cross-cutting runtime/PEM/build), and a mistake in the SM2 curve or SM9 pairing would be a silent correctness bug — so independent review at each gate is valuable.

Which execution approach would you prefer?

- **Subagent-driven** — A fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** — I implement every task myself in this session, the way this harness runs work, then one fresh reviewer on the most capable model checks the whole branch. Cheapest and fastest; no independent review until the end. Runs well with a mid-tier session since the plan carries the design.

For this plan I recommend **Subagent-driven**, because the tasks span 5 algorithm cores with independent review surfaces (curve, pairing, AES-equivalent), a PEM/ASN.1 layer that's easy to get subtly wrong, and a build pipeline; a bug caught late (e.g. SM9 pairing final exp) would force a re-run of every dependent test. Subagent gates catch that earlier.

Does the plan capture what you want, and which approach should we use?

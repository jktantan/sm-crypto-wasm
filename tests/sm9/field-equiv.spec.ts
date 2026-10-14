/**
 * SM9 扩域 Fp2 / Fp4 / Fp12 的等价性测试。
 *
 * 目的：给「扩域乘法换成 Karatsuba」这类改造上一层保险 —— 用 **BigInt 按域的定义
 * 独立展开**（Fp2 = Fp[u]/(u²+2)、Fp4 = Fp2[v]/(v²−u)、Fp12 = Fp4[w]/(w³−v)），
 * 与 WASM 里 `fp*MulOut` / `fp*SqrOut` 的输出逐字节对比。
 *
 * 刻意不照抄 src 里的公式：参考实现从多项式乘 + 模约简重写，实现若改错会被抓到。
 *
 * 内存布局（与 src/sm9/assembly/index.ts 的 readFp2/readFp4/readFp12 一致）：
 *   Fp2  64B  = a1(32B) || a0(32B)
 *   Fp4 128B  = a1(Fp2) || a0(Fp2)
 *   Fp12 384B = a2(Fp4) || a1(Fp4) || a0(Fp4)
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { loadWasm } from '@/runtime/loadWasm.js';

// ---------- 参考实现（BigInt，按域定义） ----------

const P = BigInt('0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d');

const fp = (x: bigint): bigint => ((x % P) + P) % P;
const fadd = (a: bigint, b: bigint) => fp(a + b);
const fsub = (a: bigint, b: bigint) => fp(a - b);
const fmul = (a: bigint, b: bigint) => fp(a * b);
const fneg = (a: bigint) => fp(-a);
const fdbl = (a: bigint) => fp(2n * a);

/** Fp2 = a0 + a1·u，u² = −2。 */
type F2 = [bigint, bigint];
type F4t = [F2, F2]; // b0 + b1·v
type F12t = [F4t, F4t, F4t]; // c0 + c1·w + c2·w²

const f2add = (a: F2, b: F2): F2 => [fadd(a[0], b[0]), fadd(a[1], b[1])];
const f2dbl = (a: F2): F2 => [fdbl(a[0]), fdbl(a[1])];
/** 乘以 u：(a0 + a1 u)·u = a0 u + a1 u² = −2·a1 + a0·u。 */
const f2mulU = (a: F2): F2 => [fneg(fdbl(a[1])), a[0]];
/** 多项式乘后模 u² = −2。 */
const f2mul = (a: F2, b: F2): F2 => [
  fsub(fmul(a[0], b[0]), fdbl(fmul(a[1], b[1]))),
  fadd(fmul(a[0], b[1]), fmul(a[1], b[0])),
];
const f2sqr = (a: F2): F2 => f2mul(a, a);

const f4add = (a: F4t, b: F4t): F4t => [f2add(a[0], b[0]), f2add(a[1], b[1])];
const f4dbl = (a: F4t): F4t => [f2dbl(a[0]), f2dbl(a[1])];
/** 乘以 v：(b0 + b1 v)·v = b0 v + b1 v² = u·b1 + b0·v。 */
const f4mulV = (a: F4t): F4t => [f2mulU(a[1]), a[0]];
/** 多项式乘后模 v² = u。 */
const f4mul = (a: F4t, b: F4t): F4t => [
  f2add(f2mul(a[0], b[0]), f2mulU(f2mul(a[1], b[1]))),
  f2add(f2mul(a[0], b[1]), f2mul(a[1], b[0])),
];
const f4sqr = (a: F4t): F4t => f4mul(a, a);

/** 多项式乘后模 w³ = v。 */
const f12mul = (a: F12t, b: F12t): F12t => [
  f4add(f4mul(a[0], b[0]), f4add(f4mulV(f4mul(a[1], b[2])), f4mulV(f4mul(a[2], b[1])))),
  f4add(f4add(f4mul(a[0], b[1]), f4mul(a[1], b[0])), f4mulV(f4mul(a[2], b[2]))),
  f4add(f4add(f4mul(a[0], b[2]), f4mul(a[1], b[1])), f4mul(a[2], b[0])),
];
const f12sqr = (a: F12t): F12t => f12mul(a, a);

// ---------- 编解码 ----------

const u256 = (x: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};
const readU256 = (b: Uint8Array, off: number): bigint => {
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[off + i] ?? 0);
  return v;
};

const encF2 = (a: F2): Uint8Array => {
  const out = new Uint8Array(64);
  out.set(u256(a[1]), 0); // a1 在前（GmSSL 约定）
  out.set(u256(a[0]), 32);
  return out;
};
const decF2 = (b: Uint8Array, off: number): F2 => [readU256(b, off + 32), readU256(b, off)];
const encF4 = (a: F4t): Uint8Array => {
  const out = new Uint8Array(128);
  out.set(encF2(a[1]), 0);
  out.set(encF2(a[0]), 64);
  return out;
};
const decF4 = (b: Uint8Array, off: number): F4t => [decF2(b, off + 64), decF2(b, off)];
const encF12 = (a: F12t): Uint8Array => {
  const out = new Uint8Array(384);
  out.set(encF4(a[2]), 0);
  out.set(encF4(a[1]), 128);
  out.set(encF4(a[0]), 256);
  return out;
};
const decF12 = (b: Uint8Array, off: number): F12t => [
  decF4(b, off + 256),
  decF4(b, off + 128),
  decF4(b, off),
];

// ---------- 随机向量 ----------

/** 确定性 PRNG，保证失败可复现。 */
let seed = 0x9e3779b97f4a7c15n;
const nextFp = (): bigint => {
  seed ^= seed << 13n;
  seed &= (1n << 64n) - 1n;
  seed ^= seed >> 7n;
  seed ^= seed << 17n;
  seed &= (1n << 64n) - 1n;
  return seed % P;
};
const randF2 = (): F2 => [nextFp(), nextFp()];
const randF4 = (): F4t => [randF2(), randF2()];
const randF12 = (): F12t => [randF4(), randF4(), randF4()];

// ---------- WASM 绑定 ----------

interface Sm9Diag {
  alloc: (n: number) => number;
  fp2MulOut: (a: number, b: number, o: number) => void;
  fp2SqrOut: (a: number, o: number) => void;
  fp4MulOut: (a: number, b: number, o: number) => void;
  fp4SqrOut: (a: number, o: number) => void;
  fp12MulOut: (a: number, b: number, o: number) => void;
  fp12SqrOut: (a: number, o: number) => void;
}

let ex: Sm9Diag;
let memory: WebAssembly.Memory;
let bufA = 0;
let bufB = 0;
let bufO = 0;

const put = (bytes: Uint8Array, ptr: number): void => {
  new Uint8Array(memory.buffer).set(bytes, ptr);
};
const get = (ptr: number, len: number): Uint8Array =>
  new Uint8Array(memory.buffer, ptr, len).slice();

const CASES = 6;

describe('SM9 扩域等价性（BigInt 参考 vs WASM）', () => {
  beforeAll(async () => {
    const mod = await loadWasm('sm9');
    ex = mod.exports as unknown as Sm9Diag;
    memory = mod.memory;
    // 384 字节够 Fp12；Fp2/Fp4 用同一块的前 64/128 字节。
    bufA = ex.alloc(384);
    bufB = ex.alloc(384);
    bufO = ex.alloc(384);
  }, 30_000);

  it('fp2Mul 与域定义一致', () => {
    for (let i = 0; i < CASES; i++) {
      const a = randF2();
      const b = randF2();
      put(encF2(a), bufA);
      put(encF2(b), bufB);
      ex.fp2MulOut(bufA, bufB, bufO);
      expect(decF2(get(bufO, 64), 0)).toEqual(f2mul(a, b));
    }
  });

  it('fp2Sqr 与域定义一致', () => {
    for (let i = 0; i < CASES; i++) {
      const a = randF2();
      put(encF2(a), bufA);
      ex.fp2SqrOut(bufA, bufO);
      expect(decF2(get(bufO, 64), 0)).toEqual(f2sqr(a));
    }
  });

  it('fp4Mul 与域定义一致', () => {
    for (let i = 0; i < CASES; i++) {
      const a = randF4();
      const b = randF4();
      put(encF4(a), bufA);
      put(encF4(b), bufB);
      ex.fp4MulOut(bufA, bufB, bufO);
      expect(decF4(get(bufO, 128), 0)).toEqual(f4mul(a, b));
    }
  });

  it('fp4Sqr 与域定义一致', () => {
    for (let i = 0; i < CASES; i++) {
      const a = randF4();
      put(encF4(a), bufA);
      ex.fp4SqrOut(bufA, bufO);
      expect(decF4(get(bufO, 128), 0)).toEqual(f4sqr(a));
    }
  });

  it('fp12Mul 与域定义一致', () => {
    for (let i = 0; i < CASES; i++) {
      const a = randF12();
      const b = randF12();
      put(encF12(a), bufA);
      put(encF12(b), bufB);
      ex.fp12MulOut(bufA, bufB, bufO);
      expect(decF12(get(bufO, 384), 0)).toEqual(f12mul(a, b));
    }
  });

  it('fp12Sqr 与域定义一致', () => {
    for (let i = 0; i < CASES; i++) {
      const a = randF12();
      put(encF12(a), bufA);
      ex.fp12SqrOut(bufA, bufO);
      expect(decF12(get(bufO, 384), 0)).toEqual(f12sqr(a));
    }
  });
});

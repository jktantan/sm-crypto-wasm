import { createHash } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import * as sm2 from '@/sm2';
import v from '../vectors/sm2/keyexchange-official.json';

/**
 * SM2 密钥交换**官方向量** KAT：GB/T 32918.3-2016 附录 A.2 示例 1（Fp-256）。
 *
 * 重要：该示例使用一条**示例曲线**（p = 8542D69E…），并非 SM2 推荐曲线，
 * 所以本库（硬编码推荐曲线）无法端到端跑它——ZA/ZB/RA/RB/U 都依赖示例曲线。
 * 但确认值 S_A/S_B 与共享密钥 K 的计算**与曲线无关**（只依赖 xU/yU/ZA/ZB/RA/RB
 * 与 SM3/KDF），因此可以直接用本库的两条参数无关原语验证：
 *   - `kexConfirmOut`：S = SM3(prefix ‖ yU ‖ SM3(xU ‖ ZA ‖ ZB ‖ RA ‖ RB))
 *   - `kdfOut`：K = KDF(xU ‖ yU ‖ ZA ‖ ZB, klen)
 * 第三项则用示例曲线上的独立 BigInt 参考实现，复现标准示例的**全部**中间值，
 * 证明协议理解与标准一致。
 */

interface WasmExports {
  alloc(n: number): number;
  freeAll(): void;
  kexConfirmOut(
    prefix: number,
    uPtr: number,
    zaPtr: number,
    zbPtr: number,
    raPtr: number,
    rbPtr: number,
    outPtr: number,
  ): void;
  kdfOut(zPtr: number, zLen: number, outPtr: number, klen: number): number;
}
interface WasmModule {
  exports: WasmExports;
  memory: WebAssembly.Memory;
}

function wasm(): WasmModule {
  const mod = (globalThis as unknown as { __sm2Wasm?: WasmModule }).__sm2Wasm;
  if (!mod) throw new Error('sm2 未加载');
  return mod;
}

const hx = (s: string): Buffer => Buffer.from(s, 'hex');
const h2b = (arr: Uint8Array): Buffer => Buffer.from(arr);

/** 用库原语算确认值（hex）。 */
function libConfirm(
  prefix: number,
  u65: Buffer,
  za: Buffer,
  zb: Buffer,
  ra: Buffer,
  rb: Buffer,
): string {
  const { exports, memory } = wasm();
  const up = exports.alloc(65);
  const zap = exports.alloc(32);
  const zbp = exports.alloc(32);
  const rap = exports.alloc(64);
  const rbp = exports.alloc(64);
  const op = exports.alloc(32);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(u65, up);
    mem.set(za, zap);
    mem.set(zb, zbp);
    mem.set(ra, rap);
    mem.set(rb, rbp);
    exports.kexConfirmOut(prefix, up, zap, zbp, rap, rbp, op);
    return h2b(new Uint8Array(memory.buffer, op, 32)).toString('hex');
  } finally {
    exports.freeAll();
  }
}

/** 用库原语算 KDF（hex）。 */
function libKdf(z: Buffer, klen: number): string {
  const { exports, memory } = wasm();
  const zp = exports.alloc(z.length);
  const op = exports.alloc(klen);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(z, zp);
    const rc = exports.kdfOut(zp, z.length, op, klen);
    if (rc !== 1) throw new Error('sm2.kdf: 输出全 0');
    return h2b(new Uint8Array(memory.buffer, op, klen)).toString('hex');
  } finally {
    exports.freeAll();
  }
}

describe('SM2 key exchange official KAT (GB/T 32918.3-2016 A.2 示例1)', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('library confirm primitive reproduces official S_A / S_B', () => {
    const U = Buffer.concat([Buffer.from([0x04]), hx(v.U)]);
    const za = hx(v.ZA);
    const zb = hx(v.ZB);
    const ra = hx(v.RA);
    const rb = hx(v.RB);
    expect(libConfirm(0x03, U, za, zb, ra, rb)).toBe(v.SA);
    expect(libConfirm(0x02, U, za, zb, ra, rb)).toBe(v.SB);
  });

  it('library KDF reproduces the official shared key K', () => {
    const u = hx(v.U);
    const z = Buffer.concat([u.subarray(0, 32), u.subarray(32, 64), hx(v.ZA), hx(v.ZB)]);
    expect(libKdf(z, v.klen)).toBe(v.K);
  });

  it('example-curve oracle reproduces the full official transcript', () => {
    const { p, a, b, gx, gy, n } = v.curve;
    const P = BigInt(`0x${p}`);
    const A = BigInt(`0x${a}`);
    const N = BigInt(`0x${n}`);
    const G = { x: BigInt(`0x${gx}`), y: BigInt(`0x${gy}`) };

    const mod = (x: bigint, m: bigint): bigint => {
      const r = x % m;
      return r < 0n ? r + m : r;
    };
    type Pt = { x: bigint; y: bigint } | null;
    const inv = (x: bigint, m: bigint): bigint => {
      let [or, r] = [mod(x, m), m];
      let [os, s] = [1n, 0n];
      while (r !== 0n) {
        const q = or / r;
        [or, r] = [r, or - q * r];
        [os, s] = [s, os - q * s];
      }
      return mod(os, m);
    };
    const dbl = (pt: Pt): Pt => {
      if (!pt || pt.y === 0n) return null;
      const l = mod((3n * pt.x * pt.x + A) * inv(2n * pt.y, P), P);
      const x = mod(l * l - 2n * pt.x, P);
      return { x, y: mod(l * (pt.x - x) - pt.y, P) };
    };
    const add = (pt: Pt, q: Pt): Pt => {
      if (!pt) return q;
      if (!q) return pt;
      if (pt.x === q.x) return mod(pt.y + q.y, P) === 0n ? null : dbl(pt);
      const l = mod((q.y - pt.y) * inv(q.x - pt.x, P), P);
      const x = mod(l * l - pt.x - q.x, P);
      return { x, y: mod(l * (pt.x - x) - pt.y, P) };
    };
    const mul = (k: bigint, pt: Pt): Pt => {
      let r: Pt = null;
      let q = pt;
      let kk = k;
      while (kk > 0n) {
        if (kk & 1n) r = add(r, q);
        q = dbl(q);
        kk >>= 1n;
      }
      return r;
    };
    /**
     * `mul` 的「必须非无穷远」版本。标量非零时结果不可能是无穷远点；真出现就说明
     * 曲线参数或标量写错了 —— 抛一个带上下文的错，而不是用 `!` 把问题留到 null 上
     * 炸出 "Cannot read properties of null"。
     */
    const mulDef = (k: bigint, pt: Pt): NonNullable<Pt> => {
      const r = mul(k, pt);
      if (r === null) {
        throw new Error(`mul(k=0x${k.toString(16)}, pt) 返回无穷远点：标量或曲线参数有误`);
      }
      return r;
    };
    const b32 = (x: bigint): Buffer => {
      const o = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) o[31 - i] = Number((x >> BigInt(i * 8)) & 0xffn);
      return o;
    };
    const sm3 = (...parts: Buffer[]): Buffer =>
      createHash('sm3').update(Buffer.concat(parts)).digest();
    const entla = (id: string): Buffer => {
      const bits = Buffer.byteLength(id, 'latin1') * 8;
      return Buffer.from([(bits >> 8) & 0xff, bits & 0xff]);
    };
    const zOf = (id: string, pub: NonNullable<Pt>): Buffer =>
      sm3(
        entla(id),
        Buffer.from(id, 'latin1'),
        b32(A),
        b32(BigInt(`0x${b}`)),
        b32(G.x),
        b32(G.y),
        b32(pub.x),
        b32(pub.y),
      );

    // PA = [dA]G, PB = [dB]G
    const PA = mulDef(BigInt(`0x${v.dA}`), G);
    const PB = mulDef(BigInt(`0x${v.dB}`), G);
    expect(Buffer.concat([b32(PA.x), b32(PA.y)]).toString('hex')).toBe(v.pubA);
    expect(Buffer.concat([b32(PB.x), b32(PB.y)]).toString('hex')).toBe(v.pubB);

    // ZA / ZB
    expect(zOf(v.idA, PA).toString('hex')).toBe(v.ZA);
    expect(zOf(v.idB, PB).toString('hex')).toBe(v.ZB);

    // RA = [rA]G, RB = [rB]G
    const RA = mulDef(BigInt(`0x${v.rA}`), G);
    const RB = mulDef(BigInt(`0x${v.rB}`), G);
    expect(Buffer.concat([b32(RA.x), b32(RA.y)]).toString('hex')).toBe(v.RA);
    expect(Buffer.concat([b32(RB.x), b32(RB.y)]).toString('hex')).toBe(v.RB);

    // U = [tA](PB + [x̄(RB.x)]RB), tA = (dA + x̄(RA.x)·rA) mod n
    const xbar = (x: bigint): bigint => (1n << 127n) | (x & ((1n << 127n) - 1n));
    const tA = mod(BigInt(`0x${v.dA}`) + mod(xbar(RA.x) * BigInt(`0x${v.rA}`), N), N);
    const U = mulDef(tA, add(PB, mul(xbar(RB.x), RB)));
    expect(Buffer.concat([b32(U.x), b32(U.y)]).toString('hex')).toBe(v.U);

    // S_A / S_B / K
    const inner = sm3(b32(U.x), hx(v.ZA), hx(v.ZB), hx(v.RA), hx(v.RB));
    expect(sm3(Buffer.from([0x03]), b32(U.y), inner).toString('hex')).toBe(v.SA);
    expect(sm3(Buffer.from([0x02]), b32(U.y), inner).toString('hex')).toBe(v.SB);

    const kdfZ = Buffer.concat([b32(U.x), b32(U.y), hx(v.ZA), hx(v.ZB)]);
    const kdf = (z: Buffer, klen: number): Buffer => {
      const out = Buffer.alloc(klen);
      let written = 0;
      let ct = 1;
      while (written < klen) {
        const hh = sm3(
          z,
          Buffer.from([(ct >>> 24) & 0xff, (ct >>> 16) & 0xff, (ct >>> 8) & 0xff, ct & 0xff]),
        );
        const take = Math.min(32, klen - written);
        hh.copy(out, written, 0, take);
        written += take;
        ct++;
      }
      return out;
    };
    expect(kdf(kdfZ, v.klen).toString('hex')).toBe(v.K);
  });
});

import { createHash } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import * as sm2 from '@/sm2';

/**
 * SM2 密钥交换（GM/T 0003.3-2014 §6.4）。
 *
 * 验证策略：
 * 1. **独立 oracle 对拍** —— 本文件内用纯 BigInt 椭圆曲线 + Node `crypto` 的
 *    SM3 重写一遍协议（逐行复刻 GmSSL `src/sm2_exch.c`），与本库 wasm 实现
 *    逐字节比较 U / ZA / ZB / S_A / S_B / 共享密钥。
 * 2. **端到端自洽** —— 双方独立跑协议，确认共享密钥一致、确认值互相校验通过。
 * 3. **负例** —— 篡改确认值、ID 不匹配、调用顺序错乱都应被拒绝。
 */

// ---------- 曲线参数（GM/T 0003.5） ----------
const P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn;
const A = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffcn;
const B = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n;
const N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n;
const GX = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n;
const GY = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n;

// 模拟 SM2 用户标识（同 GmSSL sm2_exchtest.c：'Alice' / 'Bob'）。
const IDA = 'Alice';
const IDB = 'Bob';

// 固定密钥（确定性地对拍 oracle）。
const D_A = 0x00000000000000000000000000000000000000000000000000004012309bb0629bf53edeca2da3ean;
const D_B = 0x000000000000000000000000000000000000000000000000000087a6df4183bfb57e22afa5f9ef01n;
const R_A = 0x000000000000000000000000000000000000000000000000000038886cd26199d99300d703fb8abfn;
const R_B = 0x0000000000000000000000000000000000000000000000000000fbd4c66f6c6fe159c0cfd3805f2en;

// ---------- BigInt 椭圆曲线 ----------
type Pt = { x: bigint; y: bigint } | null;

const mod = (x: bigint, m: bigint): bigint => {
  const r = x % m;
  return r < 0n ? r + m : r;
};

function ecDouble(p: Pt): Pt {
  if (p === null || p.y === 0n) return null;
  const lambda = mod((3n * p.x * p.x + A) * invMod(2n * p.y, P), P);
  const x = mod(lambda * lambda - 2n * p.x, P);
  const y = mod(lambda * (p.x - x) - p.y, P);
  return { x, y };
}

function ecAdd(p: Pt, q: Pt): Pt {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x) {
    if (mod(p.y + q.y, P) === 0n) return null;
    return ecDouble(p);
  }
  const lambda = mod((q.y - p.y) * invMod(q.x - p.x, P), P);
  const x = mod(lambda * lambda - p.x - q.x, P);
  const y = mod(lambda * (p.x - x) - p.y, P);
  return { x, y };
}

function ecMul(k: bigint, p: Pt): Pt {
  let r: Pt = null;
  let q = p;
  let kk = k;
  while (kk > 0n) {
    if (kk & 1n) r = ecAdd(r, q);
    q = ecDouble(q);
    kk >>= 1n;
  }
  return r;
}

function invMod(a: bigint, m: bigint): bigint {
  // 扩展欧几里得（m 为素数时等价 a^{m-2}，但通用实现更稳）。
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

/** x̄ = 2^127 + (x mod 2^127)。 */
function xHat(x: bigint): bigint {
  return (1n << 127n) | (x & ((1n << 127n) - 1n));
}

// ---------- 字节工具 ----------
const be = (v: bigint, n = 32): Buffer => {
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) out[n - 1 - i] = Number((v >> BigInt(i * 8)) & 0xffn);
  return out;
};
const xy = (p: NonNullable<Pt>): Buffer => Buffer.concat([be(p.x), be(p.y)]);
const hex = (b: Buffer): string => b.toString('hex');
const G: NonNullable<Pt> = { x: GX, y: GY };

// ---------- SM3（Node crypto，独立于本库） ----------
const sm3 = (...parts: Buffer[]): Buffer => createHash('sm3').update(Buffer.concat(parts)).digest();

// ---------- 协议参考实现（对齐 GmSSL sm2_exch.c） ----------

/** Z = SM3(ENTLA || ID || a || b || Gx || Gy || Px || Py)。 */
function zOracle(id: string, pub: Buffer): Buffer {
  const idBytes = Buffer.from(id, 'utf8');
  const entla = idBytes.length * 8;
  return sm3(
    Buffer.from([(entla >> 8) & 0xff, entla & 0xff]),
    idBytes,
    be(A),
    be(B),
    be(GX),
    be(GY),
    pub.subarray(0, 32),
    pub.subarray(32, 64),
  );
}

/** U = (x̄(R_self)·r_self + d)·(P_peer + x̄(R_peer)·R_peer)。 */
function uOracle(
  d: bigint,
  r: bigint,
  rSelf: NonNullable<Pt>,
  pPeer: NonNullable<Pt>,
  rPeer: NonNullable<Pt>,
): NonNullable<Pt> {
  const t = mod(xHat(rSelf.x) * r + d, N);
  const inner = ecAdd(pPeer, ecMul(xHat(rPeer.x), rPeer));
  const u = ecMul(t, inner);
  if (u === null) throw new Error('oracle: U is infinity');
  return u;
}

/** S = SM3(prefix || Uy || SM3(Ux || ZA || ZB || RA || RB))。 */
function sOracle(
  prefix: number,
  u: Buffer,
  za: Buffer,
  zb: Buffer,
  ra: Buffer,
  rb: Buffer,
): Buffer {
  const inner = sm3(u.subarray(0, 32), za, zb, ra, rb);
  return sm3(Buffer.from([prefix]), u.subarray(32, 64), inner);
}

/** KDF(Z, klen)（GM/T 0003.4 §5.4.3）。 */
function kdfOracle(z: Buffer, klen: number): Buffer {
  const out = Buffer.alloc(klen);
  let written = 0;
  let ct = 1;
  while (written < klen) {
    const h = sm3(
      z,
      Buffer.from([(ct >>> 24) & 0xff, (ct >>> 16) & 0xff, (ct >>> 8) & 0xff, ct & 0xff]),
    );
    const take = Math.min(32, klen - written);
    h.subarray(0, take).copy(out, written);
    written += take;
    ct++;
  }
  return out;
}

/** 固定输入下，oracle 给出的全套中间量。 */
function oracleVector() {
  const PA = ecMul(D_A, G);
  const PB = ecMul(D_B, G);
  const RA = ecMul(R_A, G);
  const RB = ecMul(R_B, G);
  if (!PA || !PB || !RA || !RB) throw new Error('oracle: key derivation failed');

  const paBytes = xy(PA);
  const pbBytes = xy(PB);
  const raBytes = xy(RA);
  const rbBytes = xy(RB);

  const ZA = zOracle(IDA, paBytes);
  const ZB = zOracle(IDB, pbBytes);

  const Ua = uOracle(D_A, R_A, RA, PB, RB);
  const Ub = uOracle(D_B, R_B, RB, PA, RA);
  const uBytes = xy(Ua);
  if (hex(uBytes) !== hex(xy(Ub))) throw new Error('oracle: U_A != U_B');

  const SA = sOracle(0x03, uBytes, ZA, ZB, raBytes, rbBytes);
  const SB = sOracle(0x02, uBytes, ZA, ZB, raBytes, rbBytes);
  const key = kdfOracle(Buffer.concat([uBytes, ZA, ZB]), 32);

  return { paBytes, pbBytes, raBytes, rbBytes, ZA, ZB, uBytes, SA, SB, key };
}

const dAHex = be(D_A).toString('hex');
const dBHex = be(D_B).toString('hex');
const rAHex = be(R_A).toString('hex');
const rBHex = be(R_B).toString('hex');

describe('SM2 key exchange vs independent BigInt oracle', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('matches the oracle bit-for-bit for a fixed transcript', async () => {
    const v = oracleVector();

    const alice = await sm2.createExchangeInitiator(dAHex, hex(v.pbBytes), {
      idSelf: IDA,
      idPeer: IDB,
      ephemeralPrivateKey: rAHex,
    });
    const bob = await sm2.createExchangeResponder(dBHex, hex(v.paBytes), {
      idSelf: IDB,
      idPeer: IDA,
      ephemeralPrivateKey: rBHex,
    });

    const r1 = alice.initiate();
    const r2 = bob.respond(r1);
    const r3 = alice.confirm(r2);

    // 临时公钥
    expect(r1.ephemeralPub).toBe('04' + hex(v.raBytes));
    expect(r2.ephemeralPub).toBe('04' + hex(v.rbBytes));
    // 确认值（S_B 由响应方算出、S_A 由发起方算出）
    expect(r2.confirm).toBe(hex(v.SB));
    expect(r3.confirm).toBe(hex(v.SA));
    // 共享密钥（双方一致，且等于 oracle 的 KDF 结果）
    expect(alice.getSharedKey(r3)).toBe(hex(v.key));
    expect(bob.getSharedKey(r3)).toBe(hex(v.key));
  });

  it('derives the same public key as the oracle', async () => {
    const v = oracleVector();
    expect(sm2.getPublicKey(dAHex)).toBe(hex(v.paBytes));
    expect(sm2.getPublicKey(dBHex)).toBe(hex(v.pbBytes));
  });
});

describe('SM2 key exchange end-to-end', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  /** 跑一遍完整协议，返回两端与三条消息。 */
  async function run(options?: { kLen?: number }) {
    const v = oracleVector();
    const alice = await sm2.createExchangeInitiator(dAHex, hex(v.pbBytes), {
      idSelf: IDA,
      idPeer: IDB,
    });
    const bob = await sm2.createExchangeResponder(dBHex, hex(v.paBytes), {
      idSelf: IDB,
      idPeer: IDA,
    });
    const r1 = alice.initiate();
    const r2 = bob.respond(r1);
    const r3 = alice.confirm(r2);
    return {
      alice,
      bob,
      r1,
      r2,
      r3,
      keyA: alice.getSharedKey(r3, options?.kLen),
      keyB: bob.getSharedKey(r3, options?.kLen),
    };
  }

  it('both sides reach the same shared key with fresh randomness', async () => {
    const { keyA, keyB } = await run();
    expect(keyA).toBe(keyB);
    expect(keyA).toHaveLength(64); // 32 字节 hex
  });

  it('supports a custom key length', async () => {
    const { keyA, keyB } = await run({ kLen: 16 });
    expect(keyA).toBe(keyB);
    expect(keyA).toHaveLength(32); // 16 字节 hex
  });

  it('rejects a tampered responder confirm (S_B)', async () => {
    const v = oracleVector();
    const alice = await sm2.createExchangeInitiator(dAHex, hex(v.pbBytes), {
      idSelf: IDA,
      idPeer: IDB,
    });
    const bob = await sm2.createExchangeResponder(dBHex, hex(v.paBytes), {
      idSelf: IDB,
      idPeer: IDA,
    });
    const r1 = alice.initiate();
    const r2 = bob.respond(r1);
    const tampered = { ...r2, confirm: flipHex(r2.confirm) };
    expect(() => alice.confirm(tampered)).toThrow(/S_B/);
  });

  it('rejects a tampered initiator confirm (S_A)', async () => {
    const v = oracleVector();
    const alice = await sm2.createExchangeInitiator(dAHex, hex(v.pbBytes), {
      idSelf: IDA,
      idPeer: IDB,
    });
    const bob = await sm2.createExchangeResponder(dBHex, hex(v.paBytes), {
      idSelf: IDB,
      idPeer: IDA,
    });
    const r1 = alice.initiate();
    const r2 = bob.respond(r1);
    const r3 = alice.confirm(r2);
    expect(() => bob.getSharedKey({ ...r3, confirm: flipHex(r3.confirm) })).toThrow(/S_A/);
  });

  it('fails when the two sides disagree on identities', async () => {
    const v = oracleVector();
    // Bob 用了错误的发起方 ID（'Mallory'），故 ZA 不同 → S_A/S_B 不匹配。
    const alice = await sm2.createExchangeInitiator(dAHex, hex(v.pbBytes), {
      idSelf: IDA,
      idPeer: IDB,
    });
    const bob = await sm2.createExchangeResponder(dBHex, hex(v.paBytes), {
      idSelf: IDB,
      idPeer: 'Mallory',
    });
    const r1 = alice.initiate();
    const r2 = bob.respond(r1);
    expect(() => alice.confirm(r2)).toThrow(/S_B/);
  });

  it('enforces call order', async () => {
    const v = oracleVector();
    const alice = await sm2.createExchangeInitiator(dAHex, hex(v.pbBytes), {
      idSelf: IDA,
      idPeer: IDB,
    });
    expect(() =>
      alice.confirm({ ephemeralPub: '04' + hex(v.rbBytes), confirm: '00'.repeat(32) }),
    ).toThrow(/initiate/);
    expect(() => alice.initiate()).not.toThrow();
    expect(() => alice.initiate()).toThrow(/只能调用一次/);
  });
});

/** 翻转 hex 串最后一个字节。 */
function flipHex(h: string): string {
  const last = h.slice(-2);
  return h.slice(0, -2) + (last === 'ff' ? '00' : 'ff');
}

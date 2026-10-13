// SM2 椭圆曲线点运算（AssemblyScript）。
//
// 曲线：y² = x³ + a·x + b (mod p)，a = p - 3。
// 参数（GM/T 0003-2012）：
//   b  = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
//   Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
//   Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
//   n  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
//
// 坐标：Jacobian (X, Y, Z) 表示仿射 (X/Z², Y/Z³)。无穷远点 Z = 0。
//
// oracle 验证：plan Task 6；对点加/倍点/标量乘用 gmkitx 或 Node bigint 校验。

import {
  U256,
  pArr,
  fpAdd,
  fpSub,
  fpMul,
  fpSqr,
  fpInv,
  u256fromBytes,
  u256toBytes,
  u256cmp,
  u256isZero,
  u256zero,
} from './field';

/** Jacobian 点。 */
export class JPoint {
  x: U256;
  y: U256;
  z: U256;
  constructor() {
    this.x = new StaticArray<u32>(8);
    this.y = new StaticArray<u32>(8);
    this.z = new StaticArray<u32>(8);
  }
}

/** 曲线参数 b。 */
export function curveB(): U256 {
  const b = new Uint8Array(32);
  const hex = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93';
  hexToBytesInto(hex, b);
  return u256fromBytes(b, 0);
}

/** 基点 G（仿射）。 */
export function basePoint(): JPoint {
  const p = new JPoint();
  const gx = new Uint8Array(32);
  const gy = new Uint8Array(32);
  hexToBytesInto('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', gx);
  hexToBytesInto('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', gy);
  p.x = u256fromBytes(gx, 0);
  p.y = u256fromBytes(gy, 0);
  const z = u256zero();
  z[0] = 1;
  p.z = z;
  return p;
}

function hexToBytesInto(hex: string, out: Uint8Array): void {
  for (let i = 0; i < out.length; i++) {
    const hi = hexChar(hex.charCodeAt(i * 2));
    const lo = hexChar(hex.charCodeAt(i * 2 + 1));
    out[i] = <u8>((hi << 4) | lo);
  }
}

function hexChar(code: i32): i32 {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return 0;
}

/** 无穷远点判定：Z == 0。 */
export function isInfinity(p: JPoint): bool {
  return u256isZero(p.z);
}

/** P = -P（Y = p - Y）。 */
export function negate(p: JPoint): JPoint {
  const r = new JPoint();
  r.x = p.x;
  const pv = pArr();
  r.y = fpSub(pv, p.y);
  r.z = p.z;
  return r;
}

/**
 * Jacobian 倍点：R = 2·P。
 * 公式（dbl-2007-bl，a = -3 优化版）：
 *   delta = Z1²
 *   gamma = Y1²
 *   beta  = X1·gamma
 *   alpha = 3·(X1 - delta)·(X1 + delta)   （因 a = -3）
 *   X3 = alpha² - 8·beta
 *   Y3 = alpha·(4·beta - X3) - 8·gamma²
 *   Z3 = 2·Y1·Z1
 */
export function doublePoint(p: JPoint): JPoint {
  if (isInfinity(p) || u256isZero(p.y)) {
    return infinity();
  }
  const delta = fpSqr(p.z);
  const gamma = fpSqr(p.y);
  const beta = fpMul(p.x, gamma);
  // alpha = 3*(X1 - delta)*(X1 + delta)
  const xmd = fpSub(p.x, delta);
  const xpd = fpAdd(p.x, delta);
  let alpha = fpMul(xmd, xpd);
  alpha = fpAdd(fpAdd(alpha, alpha), alpha);

  const x3 = fpSub(fpSqr(alpha), mulSmall(beta, 8));
  // Y3 = alpha*(4*beta - X3) - 8*gamma²
  const fourBeta = mulSmall(beta, 4);
  const y3 = fpSub(fpMul(alpha, fpSub(fourBeta, x3)), mulSmall(fpSqr(gamma), 8));
  // Z3 = 2*Y1*Z1
  const z3 = mulSmall(fpMul(p.y, p.z), 2);

  const r = new JPoint();
  r.x = x3;
  r.y = y3;
  r.z = z3;
  return r;
}

/**
 * Jacobian 点加：R = P + Q（P、Q 均非无穷远）。
 * 公式（add-2007-bl）。
 */
export function addPoints(p: JPoint, q: JPoint): JPoint {
  if (isInfinity(p)) return clonePoint(q);
  if (isInfinity(q)) return clonePoint(p);

  const z1z1 = fpSqr(p.z);
  const z2z2 = fpSqr(q.z);
  const u1 = fpMul(p.x, z2z2);
  const u2 = fpMul(q.x, z1z1);
  const s1 = fpMul(p.y, fpMul(q.z, z2z2));
  const s2 = fpMul(q.y, fpMul(p.z, z1z1));

  const h = fpSub(u2, u1);
  const r = fpSub(s2, s1);

  if (u256isZero(h)) {
    if (u256isZero(r)) {
      return doublePoint(p);
    }
    return infinity();
  }

  const hh = fpSqr(h);
  const hhh = fpMul(h, hh);
  const v = fpMul(u1, hh);

  const x3 = fpSub(fpSub(fpSqr(r), hhh), mulSmall(v, 2));
  const y3 = fpSub(fpMul(r, fpSub(v, x3)), fpMul(s1, hhh));
  const z3 = fpMul(p.z, fpMul(q.z, h));

  const out = new JPoint();
  out.x = x3;
  out.y = y3;
  out.z = z3;
  return out;
}

/** 无穷远点。 */
export function infinity(): JPoint {
  return new JPoint(); // Z = 0 by default
}

export function clonePoint(p: JPoint): JPoint {
  const r = new JPoint();
  for (let i = 0; i < 8; i++) {
    r.x[i] = p.x[i];
    r.y[i] = p.y[i];
    r.z[i] = p.z[i];
  }
  return r;
}

/** 小整数乘（1..8）：k * a mod p，k 为 u32 小值。 */
function mulSmall(a: U256, k: u32): U256 {
  const kv = u256zero();
  kv[0] = k;
  return fpMul(a, kv);
}

// ---------- 标量模运算（mod n） ----------

/** n 的小端 limb。 */
const N_BYTES = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';

function nArr(): U256 {
  const b = new Uint8Array(32);
  hexToBytesInto(N_BYTES, b);
  return u256fromBytes(b, 0);
}

/** 把标量（256-bit）折到 [0, n)。假定输入 < 2^256，n 接近 2^256，最多减一次。 */
function reduceModN(a: U256): U256 {
  const n = nArr();
  if (u256cmp(a, n) >= 0) {
    return fpSubRaw(a, n);
  }
  return a;
}

/** 原始 256-bit 减法（不 mod p），借位忽略（假定 a >= b）。 */
function fpSubRaw(a: U256, b: U256): U256 {
  const r = new StaticArray<u32>(8);
  let borrow: i64 = 0;
  for (let i = 0; i < 8; i++) {
    const d: i64 = i64(a[i]) - i64(b[i]) - borrow;
    if (d < 0) {
      r[i] = <u32>(d + 0x100000000);
      borrow = 1;
    } else {
      r[i] = <u32>d;
      borrow = 0;
    }
  }
  return r;
}

/**
 * 标量乘：R = k · P（k 为 256-bit 标量，P 为 Jacobian 点）。
 * 双倍-点加，MSB-first，左到右。
 */
export function scalarMul(k: U256, p: JPoint): JPoint {
  let r = infinity();
  let started = false;
  for (let i = 255; i >= 0; i--) {
    if (started) {
      r = doublePoint(r);
    }
    const bit = (k[i >> 5] >>> (i & 31)) & 1;
    if (bit === 1) {
      if (!started) {
        r = clonePoint(p);
        started = true;
      } else {
        r = addPoints(r, p);
      }
    }
  }
  return r;
}

/**
 * 标量乘 G：R = k · G。与 scalarMul 相同，但固定基点可优化（此处未做窗口）。
 */
export function scalarMulG(k: U256): JPoint {
  return scalarMul(k, basePoint());
}

/** Jacobian → 仿射：返回 (x, y)。Z == 0 时返回全 0。 */
export function toAffine(p: JPoint): JPoint {
  const out = new JPoint();
  if (isInfinity(p)) {
    return out; // (0,0,0)
  }
  const zinv = fpInv(p.z);
  const zinv2 = fpSqr(zinv);
  const zinv3 = fpMul(zinv2, zinv);
  out.x = fpMul(p.x, zinv2);
  out.y = fpMul(p.y, zinv3);
  const z = u256zero();
  z[0] = 1;
  out.z = z;
  return out;
}
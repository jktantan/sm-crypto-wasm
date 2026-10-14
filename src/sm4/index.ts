/**
 * SM4 业务 API（TS 胶水层，调 WASM）。
 *
 * 支持模式：ECB / CBC / CTR / CFB / OFB / GCM。
 * 所有对称模式在 TS 层用块级 `sm4Block` 调用拼装，核心轮函数在 WASM。
 *
 * spec/plan 对应：plan Task 9；spec §6 API。
 */
import { loadWasm } from '../runtime/loadWasm.js';
import { fromBytes, toBytes } from '../runtime/convert.js';

interface Sm4Exports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly sm4EncryptECB: (keyPtr: number, inPtr: number, inLen: number, outPtr: number) => void;
  readonly sm4DecryptECB: (keyPtr: number, inPtr: number, inLen: number, outPtr: number) => void;
  readonly sm4Block: (keyPtr: number, inPtr: number, outPtr: number, decrypt: number) => void;
  readonly sm4GcmEncrypt: (
    keyPtr: number,
    ivPtr: number,
    ivLen: number,
    aadPtr: number,
    aadLen: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
    tagPtr: number,
  ) => void;
  readonly sm4GcmDecrypt: (
    keyPtr: number,
    ivPtr: number,
    ivLen: number,
    aadPtr: number,
    aadLen: number,
    inPtr: number,
    inLen: number,
    outPtr: number,
    tagPtr: number,
  ) => number;
  readonly memory: WebAssembly.Memory;
}

interface Sm4Module {
  exports: Sm4Exports;
  memory: WebAssembly.Memory;
}

/** 预热 WASM 模块。 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('sm4');
  (globalThis as { __sm4Wasm?: Sm4Module }).__sm4Wasm = {
    exports: mod.exports as unknown as Sm4Exports,
    memory: mod.memory,
  };
}

function getModule(): Sm4Module {
  const mod = (globalThis as { __sm4Wasm?: Sm4Module }).__sm4Wasm;
  if (!mod) {
    throw new Error('sm4: 未初始化，请先 `await ensureLoaded()`。');
  }
  return mod;
}

/** 在 wasm 内存里临时铺三个缓冲，用完自动 freeAll。 */
function withBuffers<T>(
  key: Uint8Array,
  data: Uint8Array,
  outLen: number,
  fn: (keyPtr: number, inPtr: number, outPtr: number, mem: Uint8Array) => T,
): T {
  const { exports, memory } = getModule();
  const keyPtr = exports.alloc(16);
  const inPtr = exports.alloc(data.length === 0 ? 1 : data.length);
  const outPtr = exports.alloc(outLen);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(key, keyPtr);
    mem.set(data, inPtr);
    return fn(keyPtr, inPtr, outPtr, new Uint8Array(memory.buffer));
  } finally {
    exports.freeAll();
  }
}

/** ECB 加密（多块）。 */
export function encryptECB(key: string | Uint8Array, msg: string | Uint8Array): string {
  const k = toBytes(key, 'key');
  const m = toBytes(msg, 'msg');
  if (k.length !== 16) throw new RangeError('sm4: key must be 16 bytes');
  if (m.length % 16 !== 0 || m.length === 0) {
    throw new RangeError('sm4 ECB: 明文长度必须是 16 的非零倍数');
  }
  const out = withBuffers(k, m, m.length, (kp, ip, op) => {
    const { exports } = getModule();
    exports.sm4EncryptECB(kp, ip, m.length, op);
    return new Uint8Array(getModule().memory.buffer, op, m.length).slice();
  });
  return fromBytes(out, 'hex');
}

/** ECB 解密（多块）。 */
export function decryptECB(key: string | Uint8Array, ct: string | Uint8Array): string {
  const k = toBytes(key, 'key');
  const c = toBytes(ct, 'ct');
  if (k.length !== 16) throw new RangeError('sm4: key must be 16 bytes');
  if (c.length % 16 !== 0 || c.length === 0) {
    throw new RangeError('sm4 ECB: 密文长度必须是 16 的非零倍数');
  }
  const out = withBuffers(k, c, c.length, (kp, ip, op) => {
    const { exports } = getModule();
    exports.sm4DecryptECB(kp, ip, c.length, op);
    return new Uint8Array(getModule().memory.buffer, op, c.length).slice();
  });
  return fromBytes(out, 'hex');
}

/** 单块加密（供模式拼装）：返回 16 字节密文块。 */
function encryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  const out = withBuffers(key, block, 16, (_kp, _ip, op) => {
    // withBuffers 已把 key/block 铺好；这里调用块函数。
    const { exports, memory } = getModule();
    const keyPtr = _kp;
    const inPtr = _ip;
    exports.sm4Block(keyPtr, inPtr, op, 0);
    return new Uint8Array(memory.buffer, op, 16).slice();
  });
  return out;
}

/** 单块解密。 */
function decryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  return withBuffers(key, block, 16, (kp, ip, op) => {
    const { exports, memory } = getModule();
    exports.sm4Block(kp, ip, op, 1);
    return new Uint8Array(memory.buffer, op, 16).slice();
  });
}

function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  return out;
}

/** CBC 加密（PKCS#7 填充）。 */
export function encryptCBC(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const m = toBytes(msg, 'msg');
  if (k.length !== 16 || v.length !== 16) throw new RangeError('sm4 CBC: key/iv must be 16 bytes');
  const padded = pkcs7Pad(m);
  const out = new Uint8Array(padded.length);
  let prev = v;
  for (let off = 0; off < padded.length; off += 16) {
    const block = xor16(padded.subarray(off, off + 16), prev);
    const enc = encryptBlock(k, block);
    out.set(enc, off);
    prev = enc;
  }
  return fromBytes(out, 'hex');
}

/** CBC 解密。 */
export function decryptCBC(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const c = toBytes(ct, 'ct');
  if (k.length !== 16 || v.length !== 16) throw new RangeError('sm4 CBC: key/iv must be 16 bytes');
  if (c.length % 16 !== 0) throw new RangeError('sm4 CBC: 密文长度必须是 16 的倍数');
  const out = new Uint8Array(c.length);
  let prev = v;
  for (let off = 0; off < c.length; off += 16) {
    const block = c.subarray(off, off + 16);
    const dec = decryptBlock(k, block);
    out.set(xor16(dec, prev), off);
    prev = block;
  }
  const unpadded = pkcs7Unpad(out);
  return fromBytes(unpadded, 'hex');
}

/** CTR 加密/解密（流式，无需填充）。 */
export function cryptCTR(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const d = toBytes(data, 'data');
  if (k.length !== 16 || v.length !== 16) throw new RangeError('sm4 CTR: key/iv must be 16 bytes');
  const out = new Uint8Array(d.length);
  const counter: Uint8Array = new Uint8Array(v);
  for (let off = 0; off < d.length; off += 16) {
    const ks = encryptBlock(k, counter);
    const take = Math.min(16, d.length - off);
    for (let i = 0; i < take; i++) out[off + i] = (d[off + i] ?? 0) ^ (ks[i] ?? 0);
    // 计数器自增（big-endian）。到 0 回绕。
    for (let i = 15; i >= 0; i--) {
      counter[i] = ((counter[i] ?? 0) + 1) & 0xff;
      if (counter[i] !== 0) break;
    }
  }
  return fromBytes(out, 'hex');
}

/** CFB 加密。 */
export function encryptCFB(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
): string {
  return cfb(key, iv, msg, true);
}

/** CFB 解密。 */
export function decryptCFB(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
): string {
  return cfb(key, iv, ct, false);
}

function cfb(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  encrypt: boolean,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const d = toBytes(data, 'data');
  if (k.length !== 16 || v.length !== 16) throw new RangeError('sm4 CFB: key/iv must be 16 bytes');
  const out = new Uint8Array(d.length);
  let feedback: Uint8Array = new Uint8Array(v);
  for (let off = 0; off < d.length; off += 16) {
    const ks = encryptBlock(k, feedback);
    const take = Math.min(16, d.length - off);
    const cur = new Uint8Array(16);
    for (let i = 0; i < take; i++) {
      const p = d[off + i] ?? 0;
      const c = p ^ (ks[i] ?? 0);
      out[off + i] = c;
      cur[i] = encrypt ? c : p;
    }
    // CFB128：反馈整个密文块；不足 16 字节时用当前块补齐。
    feedback = cur;
  }
  return fromBytes(out, 'hex');
}

/** OFB 加密/解密（对称）。 */
export function cryptOFB(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
): string {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const d = toBytes(data, 'data');
  if (k.length !== 16 || v.length !== 16) throw new RangeError('sm4 OFB: key/iv must be 16 bytes');
  const out = new Uint8Array(d.length);
  let state: Uint8Array = new Uint8Array(v);
  for (let off = 0; off < d.length; off += 16) {
    state = encryptBlock(k, state);
    const take = Math.min(16, d.length - off);
    for (let i = 0; i < take; i++) out[off + i] = (d[off + i] ?? 0) ^ (state[i] ?? 0);
  }
  return fromBytes(out, 'hex');
}

// ---------- 命名别名 ----------
// 现名 `cryptCTR` / `cryptOFB` 来自实现历史，保留为主名；下面给出 spec §6 与
// plan Task 9 写的方法名，两者指向同一实现（CTR/OFB 加解密同构）。
export {
  cryptCTR as encryptCTR,
  cryptCTR as decryptCTR,
  cryptOFB as encryptOFB,
  cryptOFB as decryptOFB,
};

// ---------- PKCS#7 ----------

function pkcs7Pad(m: Uint8Array): Uint8Array {
  const padLen = 16 - (m.length % 16);
  const out = new Uint8Array(m.length + padLen);
  out.set(m);
  out.fill(padLen, m.length);
  return out;
}

function pkcs7Unpad(m: Uint8Array): Uint8Array {
  if (m.length === 0) throw new RangeError('sm4 CBC: 空输出');
  const padLen = m[m.length - 1] ?? 0;
  if (padLen < 1 || padLen > 16) throw new RangeError('sm4 CBC: 非法 PKCS#7 填充');
  return m.subarray(0, m.length - padLen);
}

// ---------- GCM ----------

/**
 * GCM 允许空明文 / 空 AAD，而 `toBytes` 对空输入抛错；这里做一层归一化。
 */
function optionalBytes(
  v: string | Uint8Array | undefined,
  label: string,
): Uint8Array {
  if (v === undefined) return new Uint8Array(0);
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (v.length === 0) return new Uint8Array(0);
  return toBytes(v, label);
}

/** GCM 输入校验与归一化。 */
function gcmInputs(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  aad: string | Uint8Array | undefined,
) {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  const a = optionalBytes(aad, 'aad');
  if (k.length !== 16) throw new RangeError('sm4 GCM: key must be 16 bytes');
  if (v.length === 0) throw new RangeError('sm4 GCM: iv 不能为空');
  return { k, v, a };
}

/** 在 WASM 内存里铺 GCM 的 6 个缓冲，用完自动 freeAll。 */
function withGcmBuffers<T>(
  k: Uint8Array,
  v: Uint8Array,
  a: Uint8Array,
  data: Uint8Array,
  fn: (
    ptrs: {
      keyPtr: number;
      ivPtr: number;
      aadPtr: number;
      inPtr: number;
      outPtr: number;
      tagPtr: number;
    },
    mem: Uint8Array,
  ) => T,
): T {
  const { exports, memory } = getModule();
  const keyPtr = exports.alloc(16);
  const ivPtr = exports.alloc(v.length === 0 ? 1 : v.length);
  const aadPtr = exports.alloc(a.length === 0 ? 1 : a.length);
  const inPtr = exports.alloc(data.length === 0 ? 1 : data.length);
  const outPtr = exports.alloc(data.length === 0 ? 1 : data.length);
  const tagPtr = exports.alloc(16);
  try {
    let mem = new Uint8Array(memory.buffer);
    mem.set(k, keyPtr);
    mem.set(v, ivPtr);
    if (a.length !== 0) mem.set(a, aadPtr);
    if (data.length !== 0) mem.set(data, inPtr);
    return fn({ keyPtr, ivPtr, aadPtr, inPtr, outPtr, tagPtr }, mem);
  } finally {
    exports.freeAll();
  }
}

/**
 * SM4-GCM 加密（AEAD）。
 *
 * @param key 16 字节密钥。
 * @param iv 初始向量，常用 12（96 bit）；其它长度按 GCM 规范走 GHASH 派生。
 * @param msg 明文，可为空。
 * @param aad 附加认证数据，可为空 / 省略。
 * @returns `{ ct, tag }`，均为 hex；`tag` 16 字节。
 */
export function encryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
  aad?: string | Uint8Array,
): { ct: string; tag: string } {
  const { k, v, a } = gcmInputs(key, iv, aad);
  const m = optionalBytes(msg, 'msg');
  return withGcmBuffers(k, v, a, m, (p) => {
    const { exports, memory } = getModule();
    exports.sm4GcmEncrypt(
      p.keyPtr,
      p.ivPtr,
      v.length,
      p.aadPtr,
      a.length,
      p.inPtr,
      m.length,
      p.outPtr,
      p.tagPtr,
    );
    // 调用可能触发 WASM 内存增长，必须重新取 buffer 视图。
    const mem = new Uint8Array(memory.buffer);
    const ct = new Uint8Array(mem.buffer, p.outPtr, m.length).slice();
    const tag = new Uint8Array(mem.buffer, p.tagPtr, 16).slice();
    return { ct: fromBytes(ct, 'hex'), tag: fromBytes(tag, 'hex') };
  });
}

/**
 * SM4-GCM 解密 + 认证。
 *
 * @param key 16 字节密钥。
 * @param iv 初始向量（与加密一致）。
 * @param ct 密文，可为空（空明文时）。
 * @param tag 16 字节认证标签（hex / base64 / Uint8Array）。
 * @param aad 附加认证数据，可为空 / 省略。
 * @returns 明文 hex。
 * @throws Error 标签校验失败（密文/标签/AAD 任一被篡改）。
 */
export function decryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
  tag: string | Uint8Array,
  aad?: string | Uint8Array,
): string {
  const { k, v, a } = gcmInputs(key, iv, aad);
  const c = optionalBytes(ct, 'ct');
  const t = toBytes(tag, 'tag');
  if (t.length !== 16) throw new RangeError('sm4 GCM: tag must be 16 bytes');
  return withGcmBuffers(k, v, a, c, (p) => {
    const { exports, memory } = getModule();
    const mem = new Uint8Array(memory.buffer);
    mem.set(t, p.tagPtr);
    const ok = exports.sm4GcmDecrypt(
      p.keyPtr,
      p.ivPtr,
      v.length,
      p.aadPtr,
      a.length,
      p.inPtr,
      c.length,
      p.outPtr,
      p.tagPtr,
    );
    if (ok !== 0) throw new Error('sm4 GCM: 认证标签校验失败');
    const out = new Uint8Array(memory.buffer);
    const pt = new Uint8Array(out.buffer, p.outPtr, c.length).slice();
    return fromBytes(pt, 'hex');
  });
}
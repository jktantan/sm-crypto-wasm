/**
 * ZUC 业务 API（TS 胶水层，调 WASM）。
 *
 * 支持：
 * - `zucKeystream(key, iv, nBytes)`：生成 nBytes 字节密钥流
 * - `zucEncrypt(key, iv, data)`：EEA3 加密/解密（异或，自反）
 *
 * spec/plan 对应：plan Task 11；spec §3 算法清单、§6 API。
 */
import { loadWasm } from '../runtime/loadWasm.js';
import { toBytes } from '../runtime/convert.js';

interface ZucExports extends WebAssembly.Exports {
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly zucKeystream: (keyPtr: number, ivPtr: number, outPtr: number, nbytes: number) => void;
  readonly memory: WebAssembly.Memory;
}

interface ZucModule {
  exports: ZucExports;
  memory: WebAssembly.Memory;
}

/** 预热 WASM 模块。 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('zuc');
  (globalThis as { __zucWasm?: ZucModule }).__zucWasm = {
    exports: mod.exports as unknown as ZucExports,
    memory: mod.memory,
  };
}

function getModule(): ZucModule {
  const mod = (globalThis as { __zucWasm?: ZucModule }).__zucWasm;
  if (!mod) throw new Error('zuc: 未初始化，请先 `await ensureLoaded()`。');
  return mod;
}

/**
 * 生成 ZUC-128 密钥流。
 *
 * @param key 16 字节密钥。
 * @param iv 16 字节 IV。
 * @param nBytes 输出字节数。
 * @returns 密钥流字节数组。
 */
export function zucKeystream(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  nBytes: number,
): Uint8Array {
  const k = toBytes(key, 'key');
  const v = toBytes(iv, 'iv');
  if (k.length !== 16) throw new RangeError('zuc: key must be 16 bytes');
  if (v.length !== 16) throw new RangeError('zuc: iv must be 16 bytes');
  if (!Number.isInteger(nBytes) || nBytes < 0) throw new RangeError('zuc: bad nBytes');
  if (nBytes === 0) return new Uint8Array(0);
  const { exports, memory } = getModule();
  const keyPtr = exports.alloc(16);
  const ivPtr = exports.alloc(16);
  const outPtr = exports.alloc(nBytes);
  try {
    const mem = new Uint8Array(memory.buffer);
    mem.set(k, keyPtr);
    mem.set(v, ivPtr);
    exports.zucKeystream(keyPtr, ivPtr, outPtr, nBytes);
    return new Uint8Array(memory.buffer, outPtr, nBytes).slice();
  } finally {
    exports.freeAll();
  }
}

/**
 * ZUC-128 EEA3 加密/解密（异或密钥流，自反）。
 *
 * @param key 16 字节密钥。
 * @param iv 16 字节 IV。
 * @param data 明文或密文。
 * @returns 密文或明文。
 */
export function zucEncrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
): Uint8Array {
  const bytes = toBytes(data, 'data');
  const ks = zucKeystream(key, iv, bytes.length);
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = (bytes[i] ?? 0) ^ (ks[i] ?? 0);
  return out;
}
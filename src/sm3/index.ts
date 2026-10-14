/**
 * SM3 业务 API（TS 胶水层，调 WASM）。
 *
 * 流程：
 * 1. `ensureLoaded()` → `loadWasm('sm3')` 拿 instance 与 memory。
 * 2. 用 WASM 侧 `alloc(n)` 分配 input/output 缓冲区（**不能**用固定地址 0）。
 * 3. 拷入输入、调 `instance.exports.sm3(inputPtr, inputLen, outPtr)`。
 * 4. 从 outPtr 拷出 32 字节。
 *
 * spec/plan 对应：plan Task 7；spec §6 API、§9 安全姿态。
 */
import { loadWasm } from '../runtime/loadWasm.js';
import { fromBytes, toBytes } from '../runtime/convert.js';

/** WASM 暴露的导出类型。 */
interface Sm3Exports extends WebAssembly.Exports {
  readonly sm3: (inputPtr: number, inputLen: number, outPtr: number) => void;
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly memory: WebAssembly.Memory;
}

interface Sm3Module {
  exports: Sm3Exports;
  memory: WebAssembly.Memory;
}

/**
 * 预热 WASM 模块；把 instance 挂在 globalThis 上以供同步 `hash()` 使用。
 * 浏览器场景必须在首次调用 `hash()` 前 `await ensureLoaded()`。
 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('sm3');
  (globalThis as { __sm3Wasm?: Sm3Module }).__sm3Wasm = {
    exports: mod.exports as unknown as Sm3Exports,
    memory: mod.memory,
  };
}

function getModule(): Sm3Module {
  const mod = (globalThis as { __sm3Wasm?: Sm3Module }).__sm3Wasm;
  if (!mod) {
    throw new Error(
      'sm3: 未初始化，请先 `await ensureLoaded()`（或 await loadWasm("sm3")）。',
    );
  }
  return mod;
}

/**
 * 消息/密钥归一化。与通用 `toBytes` 不同，这里**放行空输入**：
 * SM3 的输入是任意比特串（GM/T 0004-2012），空串（l = 0）填充后是一个完整的
 * 512 比特块、结果唯一；HMAC 对空 key / 空消息同样有定义（RFC 2104）。
 * `toBytes('')` 的抛错是给"漏填参数"设计的，对摘要类输入不适用。
 */
function digestInput(input: string | Uint8Array, label: string): Uint8Array {
  if (input instanceof Uint8Array && input.length === 0) return new Uint8Array(0);
  if (input === '') return new Uint8Array(0);
  return toBytes(input, label);
}

/**
 * SM3 摘要（同步）。
 *
 * @param input 任意输入（hex / base64 / Uint8Array / 字符串）；空输入按零长度消息处理。
 * @returns 32 字节摘要的 hex 字符串（64 字符）。
 */
export function hash(input: string | Uint8Array): string {
  const bytes = digestInput(input, 'msg');
  const { exports, memory } = getModule();
  const inputLen = bytes.length;
  // 从 WASM 堆分配缓冲区；**不可**用固定地址，否则覆盖 AS runtime 数据。
  const inputPtr = exports.alloc(inputLen === 0 ? 1 : inputLen);
  const outPtr = exports.alloc(32);
  try {
    new Uint8Array(memory.buffer, inputPtr, inputLen).set(bytes);
    exports.sm3(inputPtr, inputLen, outPtr);
    const out = new Uint8Array(memory.buffer, outPtr, 32).slice();
    return fromBytes(out, 'hex');
  } finally {
    exports.freeAll();
  }
}

/**
 * HMAC-SM3（同步）。
 *
 * @param key 任意长度密钥。
 * @param msg 任意长度消息。
 * @returns 32 字节摘要的 hex 字符串。
 */
export function hmac(key: string | Uint8Array, msg: string | Uint8Array): string {
  const k = digestInput(key, 'key');
  const m = digestInput(msg, 'msg');
  const blockKey = k.length > 64 ? toBytes(hash(k), 'key64') : k;
  const padded = new Uint8Array(64);
  padded.set(blockKey);
  const innerKey = new Uint8Array(64);
  for (let i = 0; i < 64; i++) innerKey[i] = (padded[i] ?? 0) ^ 0x36;
  const outerKey = new Uint8Array(64);
  for (let i = 0; i < 64; i++) outerKey[i] = (padded[i] ?? 0) ^ 0x5c;
  const innerMsg = new Uint8Array(64 + m.length);
  innerMsg.set(innerKey, 0);
  innerMsg.set(m, 64);
  const inner = toBytes(hash(innerMsg), 'inner');
  const outerMsg = new Uint8Array(64 + 32);
  outerMsg.set(outerKey, 0);
  outerMsg.set(inner, 64);
  return hash(outerMsg);
}
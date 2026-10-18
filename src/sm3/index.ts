/**
 * SM3 业务 API（TS 胶水层，调 WASM）。
 *
 * 流程：
 * 1. `ensureLoaded()` → `loadWasm('sm3')` 拿 instance 与 memory。
 * 2. 用 WASM 侧 `alloc(n)` 分配 input/output 缓冲区（**不能**用固定地址 0）。
 * 3. 拷入输入、调 `instance.exports.sm3(inputPtr, inputLen, outPtr)`。
 * 4. 从 outPtr 拷出 32 字节。
 *
 * HMAC 的 ipad/opad 拼接与两次摘要调用都在 WASM 内完成（`exports.sm3Hmac`），
 * 这一层只做参数归一化与缓冲区搬运。
 *
 * spec/plan 对应：plan Task 7；spec §6 API、§9 安全姿态。
 *
 * SM3 business API (TypeScript glue layer calling WASM).
 *
 * Flow:
 * 1. `ensureLoaded()` → `loadWasm('sm3')` obtains the instance and its memory.
 * 2. Allocate the input/output buffers with the WASM-side `alloc(n)`
 *    (a fixed address such as 0 must **not** be used).
 * 3. Copy the input in, then call `instance.exports.sm3(inputPtr, inputLen, outPtr)`.
 * 4. Copy the 32-byte digest back out of `outPtr`.
 *
 * HMAC ipad/opad padding and both digest calls run inside WASM
 * (`exports.sm3Hmac`); this layer only normalises arguments and moves buffers.
 *
 * Spec/plan: plan Task 7; spec §6 API, §9 security posture.
 */

import { fromBytes, toBytes } from '../runtime/convert.js';
import { loadWasm } from '../runtime/loadWasm.js';

/**
 * WASM 暴露的导出类型。
 *
 * Export types exposed by the WASM module.
 */
interface Sm3Exports extends WebAssembly.Exports {
  readonly sm3: (inputPtr: number, inputLen: number, outPtr: number) => void;
  readonly sm3Hmac: (
    keyPtr: number,
    keyLen: number,
    msgPtr: number,
    msgLen: number,
    outPtr: number,
  ) => void;
  readonly alloc: (n: number) => number;
  readonly freeAll: () => void;
  readonly memory: WebAssembly.Memory;
}

/**
 * 预热后的模块句柄：导出表 + 线性内存。
 *
 * Preloaded module handle: export table plus linear memory.
 */
interface Sm3Module {
  exports: Sm3Exports;
  memory: WebAssembly.Memory;
}

/**
 * 预热 WASM 模块；把 instance 挂在 globalThis 上以供同步 `hash()` 使用。
 * 浏览器场景必须在首次调用 `hash()` 前 `await ensureLoaded()`。
 *
 * Preload the WASM module and hang the instance on globalThis so the
 * synchronous `hash()` can use it. In browsers, `await ensureLoaded()` must
 * run before the first `hash()` call.
 */
export async function ensureLoaded(): Promise<void> {
  const mod = await loadWasm('sm3');
  (globalThis as { __sm3Wasm?: Sm3Module }).__sm3Wasm = {
    exports: mod.exports as unknown as Sm3Exports,
    memory: mod.memory,
  };
}

/**
 * 取已预热的模块句柄；未预热时抛错，避免在空句柄上继续执行。
 *
 * Fetch the preloaded module handle; throws when nothing was preloaded so the
 * caller never proceeds on an empty handle.
 */
function getModule(): Sm3Module {
  const mod = (globalThis as { __sm3Wasm?: Sm3Module }).__sm3Wasm;
  if (!mod) {
    throw new Error('sm3: 未初始化，请先 `await ensureLoaded()`（或 await loadWasm("sm3")）。');
  }
  return mod;
}

/**
 * 消息/密钥归一化。与通用 `toBytes` 不同，这里**放行空输入**：
 * SM3 的输入是任意比特串（GM/T 0004-2012），空串（l = 0）填充后是一个完整的
 * 512 比特块、结果唯一；HMAC 对空 key / 空消息同样有定义（RFC 2104）。
 * `toBytes('')` 的抛错是给"漏填参数"设计的，对摘要类输入不适用。
 *
 * Message/key normalisation. Unlike the generic `toBytes`, empty input is
 * **allowed** here: SM3 takes an arbitrary bit string (GM/T 0004-2012), and the
 * empty string (l = 0) pads into exactly one 512-bit block with a unique
 * result; HMAC is likewise defined for an empty key or message (RFC 2104).
 * The throw from `toBytes('')` exists for "forgot an argument" cases and does
 * not apply to digest inputs.
 */
function digestInput(input: string | Uint8Array, label: string): Uint8Array {
  if (input instanceof Uint8Array && input.length === 0) return new Uint8Array(0);
  if (input === '') return new Uint8Array(0);
  return toBytes(input, label);
}

/**
 * `Uint8Array` 直接使用：紧接着就会 `set` 进 WASM 私有缓冲，再复制一份是纯浪费。
 *
 * Use a `Uint8Array` as is: it is copied into a WASM-private buffer right
 * after, so an extra copy would be pure waste.
 */
function inputBytes(input: string | Uint8Array, label: string): Uint8Array {
  return input instanceof Uint8Array ? input : digestInput(input, label);
}

/**
 * SM3 摘要（同步）。
 *
 * @param input 任意输入（hex / base64 / Uint8Array / 字符串）；空输入按零长度消息处理。
 * @returns 32 字节摘要的 hex 字符串（64 字符）。
 *
 * SM3 digest (synchronous).
 *
 * @param input Any input (hex / base64 / Uint8Array / string); an empty input is
 *   treated as a zero-length message.
 * @returns The 32-byte digest as a hex string (64 characters).
 */
export function hash(input: string | Uint8Array): string {
  const bytes = inputBytes(input, 'msg');
  const { exports, memory } = getModule();
  const inputLen = bytes.length;
  // 从 WASM 堆分配缓冲区；**不可**用固定地址，否则覆盖 AS runtime 数据。
  //
  // Allocate from the WASM heap; a fixed address must **not** be used, or it
  // would overwrite AS runtime data.
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
 * HMAC-SM3（同步，RFC 2104）。
 *
 * @param key 任意长度密钥。
 * @param msg 任意长度消息。
 * @returns 32 字节摘要的 hex 字符串。
 *
 * HMAC-SM3 (synchronous, RFC 2104).
 *
 * @param key Key of any length.
 * @param msg Message of any length.
 * @returns The 32-byte digest as a hex string.
 */
export function hmac(key: string | Uint8Array, msg: string | Uint8Array): string {
  const k = inputBytes(key, 'key');
  const m = inputBytes(msg, 'msg');
  const { exports, memory } = getModule();
  // 空 key / 空 msg 也要占 1 字节：`alloc(0)` 返回的地址不保证可写。
  //
  // An empty key / message still takes 1 byte: the address returned by
  // `alloc(0)` is not guaranteed to be writable.
  const keyPtr = exports.alloc(k.length === 0 ? 1 : k.length);
  const msgPtr = exports.alloc(m.length === 0 ? 1 : m.length);
  const outPtr = exports.alloc(32);
  try {
    if (k.length > 0) new Uint8Array(memory.buffer, keyPtr, k.length).set(k);
    if (m.length > 0) new Uint8Array(memory.buffer, msgPtr, m.length).set(m);
    exports.sm3Hmac(keyPtr, k.length, msgPtr, m.length, outPtr);
    const out = new Uint8Array(memory.buffer, outPtr, 32).slice();
    return fromBytes(out, 'hex');
  } finally {
    exports.freeAll();
  }
}

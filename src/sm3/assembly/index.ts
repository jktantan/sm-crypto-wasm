// AssemblyScript SM3 入口（编译为 dist/sm3/sm3.wasm）。
//
// 纯算法实现在同目录 `sm3-core.ts`；本文件只做：
// - 内存分配导出（alloc / freeAll）
// - 对外 wasm 入口 `sm3(inputPtr, inputLen, outPtr)`
//
// 内存约定：
// - inputPtr..inputPtr+inputLen：输入字节。
// - outPtr..outPtr+32：输出摘要（32 字节，big-endian）。
//
// 公开算法参考：GB/T 32905-2016 / GM/T 0004-2014。
//
// AssemblyScript SM3 entry point (compiled to dist/sm3/sm3.wasm).
//
// The pure algorithm lives in `sm3-core.ts` in this directory; this file only:
// - exports the allocator (alloc / freeAll);
// - exposes the wasm entry point `sm3(inputPtr, inputLen, outPtr)`.
//
// Memory contract:
// - inputPtr..inputPtr+inputLen: input bytes.
// - outPtr..outPtr+32: output digest (32 bytes, big-endian).
//
// Public algorithm references: GB/T 32905-2016 / GM/T 0004-2014.

import { sm3HashInto, sm3HmacInto } from './sm3-core';

/**
 * 持住已分配缓冲，防止被 AS GC 回收。
 *
 * Holds every allocated buffer so the AS GC cannot reclaim it.
 */
const pinned: Array<StaticArray<u8>> = [];

/**
 * 从 AS 堆分配 n 字节，返回首地址。
 *
 * 暴露给 TS 胶水层用于分配 input / output 缓冲区 —— **绝不能**用固定的
 * 小地址（如 0），因为 wasm 线性内存的 0 段被 AS runtime 占用。
 *
 * Allocate n bytes from the AS heap and return the base address.
 *
 * Exposed to the TypeScript glue layer to allocate the input / output buffers.
 * A small fixed address (such as 0) must **never** be used, because segment 0 of
 * the wasm linear memory belongs to the AS runtime.
 */
export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

/**
 * 释放全部 `alloc` 分配的缓冲。
 *
 * Release every buffer allocated through `alloc`.
 */
export function freeAll(): void {
  pinned.length = 0;
}

/**
 * SM3 单块调用入口：输入任意字节长度，输出 32 字节摘要。
 *
 * @param inputPtr 输入字节起始地址。
 * @param inputLen 输入字节长度。
 * @param outPtr 输出 32 字节起始地址。
 *
 * SM3 single-call entry point: any input byte length in, a 32-byte digest out.
 *
 * @param inputPtr Start address of the input bytes.
 * @param inputLen Input byte length.
 * @param outPtr Start address of the 32-byte output.
 */
export function sm3(inputPtr: usize, inputLen: usize, outPtr: usize): void {
  sm3HashInto(inputPtr, inputLen, outPtr);
}

/**
 * SM3-HMAC 单块调用入口（RFC 2104）：整段计算在 WASM 内完成。
 *
 * @param keyPtr 密钥字节起始地址。
 * @param keyLen 密钥字节长度。
 * @param msgPtr 消息字节起始地址。
 * @param msgLen 消息字节长度。
 * @param outPtr 输出 32 字节起始地址。
 *
 * SM3-HMAC single-call entry point (RFC 2104): the whole computation runs inside WASM.
 *
 * @param keyPtr Start address of the key bytes.
 * @param keyLen Key byte length.
 * @param msgPtr Start address of the message bytes.
 * @param msgLen Message byte length.
 * @param outPtr Start address of the 32-byte output.
 */
export function sm3Hmac(
  keyPtr: usize,
  keyLen: usize,
  msgPtr: usize,
  msgLen: usize,
  outPtr: usize,
): void {
  sm3HmacInto(keyPtr, keyLen, msgPtr, msgLen, outPtr);
}

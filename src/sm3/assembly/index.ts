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

import { sm3HashInto } from './sm3-core';

/** 持住已分配缓冲，防止被 AS GC 回收。 */
const pinned: Array<StaticArray<u8>> = [];

/**
 * 从 AS 堆分配 n 字节，返回首地址。
 *
 * 暴露给 TS 胶水层用于分配 input / output 缓冲区 —— **绝不能**用固定的
 * 小地址（如 0），因为 wasm 线性内存的 0 段被 AS runtime 占用。
 */
export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

/** 释放全部 `alloc` 分配的缓冲。 */
export function freeAll(): void {
  pinned.length = 0;
}

/**
 * SM3 单块调用入口：输入任意字节长度，输出 32 字节摘要。
 *
 * @param inputPtr 输入字节起始地址。
 * @param inputLen 输入字节长度。
 * @param outPtr 输出 32 字节起始地址。
 */
export function sm3(inputPtr: usize, inputLen: usize, outPtr: usize): void {
  sm3HashInto(inputPtr, inputLen, outPtr);
}
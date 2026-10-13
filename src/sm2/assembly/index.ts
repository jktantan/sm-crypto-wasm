// SM2 AssemblyScript 入口。
//
// 当前阶段：仅暴露素数域 Fp 基础运算，用于逐层验证（oracle = Node BigInt）。
// 后续叠加：曲线点运算、标量乘、签名/验签、加密/解密。
//
// 导出：
//   alloc(n) / freeAll()
//   fpAddOut(aPtr, bPtr, outPtr)
//   fpSubOut(aPtr, bPtr, outPtr)
//   fpMulOut(aPtr, bPtr, outPtr)
//   fpInvOut(aPtr, outPtr)
//
// 所有 256-bit 操作数按 32 字节大端读写。

import {
  U256,
  u256fromBytes,
  u256toBytes,
  fpAdd,
  fpSub,
  fpMul,
  fpInv,
  mul512Debug,
  reduce512Debug,
} from './field';

const pinned: Array<StaticArray<u8>> = [];

export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

export function freeAll(): void {
  pinned.length = 0;
}

function read(ptr: usize): U256 {
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = load<u8>(ptr + i);
  return u256fromBytes(b, 0);
}

export function fpAddOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = fpAdd(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

export function fpSubOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = fpSub(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

export function fpMulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = fpMul(read(aPtr), read(bPtr));
  u256toBytes(r, outPtr);
}

export function fpInvOut(aPtr: usize, outPtr: usize): void {
  const r = fpInv(read(aPtr));
  u256toBytes(r, outPtr);
}

/** 调试用：暴露 mul512 的低 512 位（16 limb → 64 字节大端）。 */
export function mul512Out(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const r = mul512Debug(read(aPtr), read(bPtr));
  for (let i = 0; i < 16; i++) {
    const v = r[15 - i];
    store<u8>(outPtr + i * 4, <u8>(v >>> 24));
    store<u8>(outPtr + i * 4 + 1, <u8>(v >>> 16));
    store<u8>(outPtr + i * 4 + 2, <u8>(v >>> 8));
    store<u8>(outPtr + i * 4 + 3, <u8>v);
  }
}

/** 调试用：仅 reduce512 的包装。 */
export function reduce512Out(aPtr: usize, bPtr: usize, outPtr: usize): void {
  const prod = mul512Debug(read(aPtr), read(bPtr));
  const r = reduce512Debug(prod);
  u256toBytes(r, outPtr);
}
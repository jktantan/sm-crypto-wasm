// SM9 AssemblyScript 入口。
//
// 分阶段实现（对齐 GmSSL 官方 view/SM9.js）：
//   Fp（fp.ts）→ Fp2（fp2.ts）→ Fp4（fp4.ts）→ Fp12（fp12.ts）
//   → G1/G2 点 → pairing → final exponent → sign/encrypt
//
// 当前阶段：暴露 Fp2 的加/乘/平方/逆诊断入口，用 GmSSL oracle 逐层对拍。
//
// 导出（诊断阶段）：
//   alloc(n) / freeAll()
//   fp2MulOut(aPtr, bPtr, outPtr)   —— 输入/输出为 a0||a1 各 32 字节大端
//   fp2SqrOut(aPtr, outPtr)
//   fp2InvOut(aPtr, outPtr)

import { Fp2, fp2fromBytes, fp2Mul, fp2Sqr, fp2Inv } from './fp2';
import { u256toBytes } from '../../common/assembly/field256';

const pinned: Array<StaticArray<u8>> = [];

export function alloc(n: i32): usize {
  const a = new StaticArray<u8>(n);
  pinned.push(a);
  return changetype<usize>(a);
}

export function freeAll(): void {
  pinned.length = 0;
}

function readFp2(ptr: usize): Fp2 {
  const b = new Uint8Array(64);
  for (let i = 0; i < 64; i++) b[i] = load<u8>(ptr + i);
  return fp2fromBytes(b, 0);
}

function writeFp2(a: Fp2, ptr: usize): void {
  u256toBytes(a[0], ptr);
  u256toBytes(a[1], ptr + 32);
}

/** 诊断：Fp2 乘。 */
export function fp2MulOut(aPtr: usize, bPtr: usize, outPtr: usize): void {
  writeFp2(fp2Mul(readFp2(aPtr), readFp2(bPtr)), outPtr);
}

/** 诊断：Fp2 平方。 */
export function fp2SqrOut(aPtr: usize, outPtr: usize): void {
  writeFp2(fp2Sqr(readFp2(aPtr)), outPtr);
}

/** 诊断：Fp2 逆。 */
export function fp2InvOut(aPtr: usize, outPtr: usize): void {
  writeFp2(fp2Inv(readFp2(aPtr)), outPtr);
}
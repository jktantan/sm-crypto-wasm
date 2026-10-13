// SM9 oracle：把 GmSSL 官方 JS 实现（view/SM9.js，Apache-2.0）包成可调用模块。
//
// view/SM9.js 是单文件脚本、末尾自带 pairing_test() 自检。这里：
// - 读入源码并去掉自动执行的那一行；
// - 用 Function 构造一个作用域，把所需的顶层函数 return 出来；
// - 供测试逐层对拍（fp/fp2/fp4/fp12/point/twist/pairing）。
//
// 用途：仅测试期对拍，不进生产代码路径。
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../view/SM9.js', import.meta.url), 'utf8')
  .replace(/pairing_test\(\);\s*$/, '');

const factory = new Function(
  src +
    `
return {
  SM9_P, SM9_N, SM9_P1, SM9_P2, SM9_Ppubs,
  fp_add, fp_sub, fp_mul, fp_sqr, fp_inv, fp_neg, fp_from_hex, fp_is_zero, fp_equ,
  fp2_add, fp2_sub, fp2_mul, fp2_sqr, fp2_inv, fp2_from_hex, fp2_equ,
  fp4_add, fp4_sub, fp4_mul, fp4_sqr, fp4_inv, fp4_from_hex, fp4_equ,
  fp12_add, fp12_sub, fp12_mul, fp12_sqr, fp12_inv, fp12_pow, fp12_from_hex, fp12_equ, fp12_new,
  fp4_new, fp2_new,
  fp12_frobenius, fp12_frobenius2, fp12_frobenius3, fp12_frobenius6,
  point_mul, point_mul_G, point_from_hex, point_get_affine, point_equ,
  twist_point_mul, twist_point_mul_G, twist_point_from_hex, twist_point_get_affine,
  final_exponent, sm9_pairing,
};
`,
);

export type Sm9Oracle = {
  SM9_P: bigint;
  SM9_N: bigint;
  SM9_P1: { X: bigint; Y: bigint; Z: bigint };
  SM9_P2: { X: bigint[]; Y: bigint[]; Z: bigint[] };
  SM9_Ppubs: { X: bigint[]; Y: bigint[]; Z: bigint[] };
  [k: string]: unknown;
};

// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
export const oracle = factory() as Sm9Oracle;
/**
 * ASN.1 内部层 barrel。
 *
 * **不进入主入口导出**（spec Anti-Goal：不公开底层 DER/大数接口）。
 * `src/pem/asn1.ts` 仍按旧符号名 re-export 本层，供 PEM/PKCS#8 代码与测试使用。
 *
 * Internal ASN.1 layer barrel.
 *
 * **Not exported from the main entry** (spec anti-goal: the low-level DER/big-number
 * interfaces stay private). `src/pem/asn1.ts` still re-exports this layer under the
 * legacy symbol names for the PEM/PKCS#8 code and the tests.
 */

export * from './decode.js';
export * from './encode.js';
export * from './oid.js';
export * from './time.js';
export * from './types.js';

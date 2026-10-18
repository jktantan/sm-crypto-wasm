/**
 * 运行时公共 barrel。供 `src/index.ts` facade 与各算法模块共用。
 *
 * 注释约定：中文为主、英文为辅（spec §11）。
 *
 * Public runtime barrel, shared by the `src/index.ts` facade and the algorithm
 * modules.
 *
 * Comment convention: Chinese first, English second (spec §11).
 */
export * from './convert.js';
export * from './errors.js';
export * from './loadWasm.js';
export * from './random.js';

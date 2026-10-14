/**
 * Bench 入口。
 *
 * 用法：`node --import tsx bench/run.ts`
 * 或 `pnpm bench`（package.json scripts 指向这里）。
 *
 * 一次性预热所有 wasm 模块（避免每个 bench 的首次 allocate 被算进开销），
 * 然后让每个 group 自己注册用例。
 */
import { run } from 'mitata';
import { benchSm2 } from './sm2.bench.js';
import { benchSm3 } from './sm3.bench.js';
import { benchSm4 } from './sm4.bench.js';
import { benchSm9 } from './sm9.bench.js';
import { benchZuc } from './zuc.bench.js';

await benchSm2();
await benchSm3();
await benchSm4();
await benchZuc();
await benchSm9();

run();

/**
 * SM3 基准。
 *
 * 输入尺寸覆盖 SM3 的"短/中/长"三档，命中：
 *   - < 64 B：单次压缩函数（padding 完成一个块）
 *   - ~1 KB：约 16 块
 *   - ~64 KB：约 1024 块
 *
 * 预热一轮让 wasm 副作用落定后再正式计时。
 */
import { bench, group } from 'mitata';
import { hash, hmac, ensureLoaded } from '../src/sm3/index.js';

const SIZES: Array<[string, Uint8Array]> = [
  ['32B', new Uint8Array(32).fill(0xab)],
  ['1KB', new Uint8Array(1024).fill(0xcd)],
  ['64KB', new Uint8Array(64 * 1024).fill(0xef)],
];
const KEY = new Uint8Array(32).fill(0x77);

export async function benchSm3(): Promise<void> {
  await ensureLoaded();
  for (const [, msg] of SIZES) hash(msg);
  group('SM3', () => {
    for (const [label, msg] of SIZES) {
      bench(`hash ${label}`, () => {
        hash(msg);
      });
    }
    bench('hmac 1KB', () => {
      hmac(KEY, SIZES[1][1]);
    });
  });
}

/**
 * ZUC 基准。
 *
 * 覆盖：EEA3 密钥流（吞吐最敏感的路径）、EIA3 MAC（不同比特长度）、IV 构造。
 *
 * 用 `resetReuseGuard()` 让每个 bench 调用都从"无记录"开始，避免上一轮的
 * counter 复用而让 zucEncrypt 抛错（基准不该抛）。
 */
import { bench, group } from 'mitata';
import {
  ensureLoaded,
  resetReuseGuard,
  zucEia3Iv,
  zucEncrypt,
  zucKeystream,
  zucMac,
} from '../src/zuc/index.js';

const KEY = new Uint8Array(16).fill(0x33);
const IV = new Uint8Array(16).fill(0x44);

function counterFor(i: number): number {
  return i;
}

export async function benchZuc(): Promise<void> {
  await ensureLoaded();
  zucKeystream(KEY, IV, 16);
  const iv = zucEia3Iv(0x66035492, 0x0f, 0);
  zucMac(KEY, iv, new Uint8Array(1024).fill(0x55));
  group('ZUC', () => {
    bench('EEA3 keystream 1KB', () => {
      resetReuseGuard();
      zucKeystream(KEY, IV, 1024);
    });
    bench('EIA3 MAC 1KB / 32-bit', () => {
      zucMac(KEY, iv, new Uint8Array(1024).fill(0x55));
    });
    bench('zucEia3Iv construct', () => {
      zucEia3Iv(counterFor(0x66035492), 0x0f, 0);
    });
    bench('EEA3 encrypt 1KB (reuseGuard on)', () => {
      resetReuseGuard();
      zucEncrypt(KEY, IV, new Uint8Array(1024).fill(0x55), counterFor(1));
      counterFor(1);
    });
  });
}

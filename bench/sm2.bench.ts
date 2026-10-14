/**
 * SM2 基准。
 *
 * 签/验/加/解：均为单次调用（带 32 字节短消息 + 32 字节私钥），命中 wasm 入口
 * 的恒定成本（无大循环压力）。密钥生成放进来方便对比"一次性 vs 持续调用"。
 */
import { bench, group } from 'mitata';
import { sign, verify, encrypt, decrypt, getPublicKey, ensureLoaded } from '../src/sm2/index.js';

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const MSG = new Uint8Array(64).fill(0x5a);

export async function benchSm2(): Promise<void> {
  await ensureLoaded();
  getPublicKey(D);
  const sig = sign(D, MSG);
  verify(getPublicKey(D), MSG, sig);
  const pub = getPublicKey(D);
  const ct = encrypt(pub, MSG);
  decrypt(D, ct);
  group('SM2', () => {
    bench('publicKey derive (point mul)', () => {
      getPublicKey(D);
    });
    bench('sign 64B', () => {
      sign(D, MSG);
    });
    bench('verify 64B (success)', () => {
      verify(pub, MSG, sig);
    });
    bench('encrypt 64B (C1C3C2)', () => {
      encrypt(pub, MSG);
    });
    bench('decrypt 64B (auto)', () => {
      decrypt(D, ct);
    });
  });
}

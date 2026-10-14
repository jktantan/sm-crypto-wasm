/**
 * SM9 基准。
 *
 * 注意：SM9 sign / encrypt 在 WASM 里的核心循环是 pairing（每次几百毫秒），
 * 主要意义是给后续 PR 留"基线"以便发现回归。密钥生成只跑一次。
 *
 * SM9 的签名主私钥与加密主私钥形态不同：签名主公钥是 G2 点（128B），
 * 加密主公钥是 G1 点（64B）—— `generateKeyPair` 用 `purpose` 区分两者。
 * 若混用，`encrypt(kp.masterPublicPem, ...)` 会在 `keyArg` 里抛
 * `InvalidKeyError: publicKey 应为 64 字节，实际 128`。
 */
import { bench, group } from 'mitata';
import { sign, verify, encrypt, decrypt, generateKeyPair, ensureLoaded } from '../src/sm9/index.js';

export async function benchSm9(): Promise<void> {
  await ensureLoaded();

  const id = 'bench@x.io';
  const kpSign = await generateKeyPair({ id });
  const kpEnc = await generateKeyPair({ id, purpose: 'enc' });
  const msg = new Uint8Array(32).fill(0x42);

  // 预热：让 sign / verify / encrypt / decrypt 的 wasm 入口走过一次，避开首次
  // allocate 与 cache miss。
  const sig = sign(kpSign.masterPrivatePem, id, msg);
  verify(kpSign.masterPrivatePem, id, msg, sig);
  const ct = encrypt(kpEnc.masterPublicPem, id, msg);
  decrypt(kpEnc.masterPrivatePem, id, ct);

  group('SM9', () => {
    bench('sign 32B', () => {
      sign(kpSign.masterPrivatePem, id, msg);
    });
    bench('verify 32B (success)', () => {
      verify(kpSign.masterPrivatePem, id, msg, sig);
    });
    bench('encrypt 32B', () => {
      encrypt(kpEnc.masterPublicPem, id, msg);
    });
    bench('decrypt 32B (success)', () => {
      decrypt(kpEnc.masterPrivatePem, id, ct);
    });
  });
}

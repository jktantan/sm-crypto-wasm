/**
 * WebCrypto 适配层在 happy-dom 下的冒烟测试。
 *
 * 验证 DOMException、fetch 加载 wasm、SM3 摘要与 SM2 签名在浏览器环境可用。
 */
import { describe, expect, it } from 'vitest';
import type { SmCryptoKeyPair } from '@/webcrypto';
import { subtle } from '@/webcrypto';

describe('webcrypto (happy-dom)', () => {
  it('digests and signs with the same APIs as Node', async () => {
    const data = new TextEncoder().encode('hello 国密 browser');
    const digest = new Uint8Array(await subtle.digest('SM3', data));
    expect(digest.length).toBe(32);

    const pair = (await subtle.generateKey({ name: 'SM2' }, false, [
      'sign',
      'verify',
    ])) as SmCryptoKeyPair;
    const signature = new Uint8Array(await subtle.sign({ name: 'SM2' }, pair.privateKey, data));
    expect(signature.length).toBe(64);
    expect(await subtle.verify({ name: 'SM2' }, pair.publicKey, signature, data)).toBe(true);

    // 错误映射在浏览器环境也返回 DOMException。
    await expect(subtle.digest('SHA-256', data)).rejects.toMatchObject({
      name: 'NotSupportedError',
    });
  });
});

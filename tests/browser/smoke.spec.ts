import { describe, expect, it } from 'vitest';
import * as sm2 from '@/sm2';
import * as sm3 from '@/sm3';
import * as sm4 from '@/sm4';
import * as sm9 from '@/sm9';
import * as zuc from '@/zuc';

/**
 * 浏览器 runner 的烟雾测试（happy-dom 环境）。
 *
 * 与 Node runner 的差异：这里只验证"所有 wasm 都能在 DOM 上下文里被加载 + 调用"，
 * 不重复跑完整的 KAT 向量（`tests/` 下的覆盖已经钉死正确性）。
 *
 * 若 happy-dom 下 `loadWasm` 的 `isNode` 判别翻车（true → false），本测试会因
 * `fetch` 失败而抛——那是个**真实**的浏览器行为问题。
 *
 * 已知差异：`loadWasm` 的 `isNode` 在 happy-dom 下仍为 `true`（happy-dom 不抹掉
 * `process.versions.node`），所以走的是 Node 分支。这并不削弱本测试的目的——它的
 * 目标只是"wasm 在 DOM 上下文里能 instantiate + 能调用"。真浏览器的路径覆盖
 * 留给未来的 Playwright/Chromium 配置。
 */
describe('浏览器 runner 烟雾', () => {
  it('happy-dom 环境里能识别浏览器 / Node 的差别', () => {
    // 仅 sanity check：当前 vitest config 把 environment 切成 happy-dom。
    expect(typeof window).toBe('object');
    // Node 全局仍在（happy-dom 不抹掉 process）。
    expect(typeof process).toBe('object');
  });

  it('SM3 ensureLoaded + hash', async () => {
    await sm3.ensureLoaded();
    expect(sm3.hash(new Uint8Array([0x61, 0x62, 0x63]))).toBe(
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
    );
  });

  it('SM2 ensureLoaded + 加密 round-trip', async () => {
    await sm2.ensureLoaded();
    const kp = await sm2.generateKeyPair();
    const ct = sm2.encrypt(kp.publicKeyPem, new Uint8Array([1, 2, 3]));
    expect(Buffer.from(sm2.decrypt(kp.privateKeyPem, ct), 'hex')).toEqual(Buffer.from([1, 2, 3]));
  });

  it('SM4 ensureLoaded + GCM 加密', async () => {
    await sm4.ensureLoaded();
    const key = new Uint8Array(16).fill(1);
    const iv = new Uint8Array(12).fill(2);
    const r = sm4.encryptGCM(key, iv, new Uint8Array([1, 2, 3]));
    expect(sm4.decryptGCM(key, iv, r.ct, r.tag)).toBe('010203');
  });

  it('ZUC ensureLoaded + EEA3 keystream', async () => {
    await zuc.ensureLoaded();
    expect(
      Buffer.from(zuc.zucKeystream(new Uint8Array(16), new Uint8Array(16), 16)).toString('hex'),
    ).toBe('27bede74018082da87d4e5b69f18bf66');
  });

  it('SM9 ensureLoaded + 加密 round-trip（purpose: enc）', async () => {
    await sm9.ensureLoaded();
    const kp = await sm9.generateKeyPair({ id: 'browser@x.io', purpose: 'enc' });
    const msg = new Uint8Array([9, 9]);
    const ct = sm9.encrypt(kp.masterPublicPem, 'browser@x.io', msg);
    expect(sm9.decrypt(kp.masterPrivatePem, 'browser@x.io', ct)).toBe('0909');
  });
});

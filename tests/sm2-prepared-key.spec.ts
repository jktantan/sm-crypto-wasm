/**
 * SM2 多槽公钥预计算表（comb + LRU）：行为与边界。
 *
 * 表本身不可观测，所以这里测的是**语义**：
 * - prepare 后加解密仍正确（comb 与 wNAF 两条路径必须给出可互解的密文）；
 * - 多槽共存、容量缩减、LRU 淘汰后旧公钥自动回退且仍然正确；
 * - clear 后回到默认路径；
 * - 坏公钥 / 非法容量在入口就被拒绝。
 *
 * 性能收益的证据在 `bench/sm2.bench.ts` 与 VitePress 性能页，不在单测里。
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { InvalidPublicKeyError } from '@/runtime';
import * as sm2 from '@/sm2';

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
/** 另外两个合法私钥（0 < d < n）。 */
const D2 = '6fcba2e4c3ab5a4d0b5c1e8f7a9d3b2c4e5f60718293a4b5c6d7e8f90a1b2c3d';
const D3 = '1111111111111111111111111111111111111111111111111111111111111111';
const MSG = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);

function roundtrip(privateKey: string, publicKey: string | Uint8Array): void {
  const ct = sm2.encrypt(publicKey, MSG);
  const pt = sm2.decrypt(privateKey, ct);
  expect(Buffer.from(pt, 'hex').equals(Buffer.from(MSG))).toBe(true);
}

describe('SM2 多槽公钥预计算表', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  afterEach(() => {
    sm2.configurePreparedKeyCache({ capacity: 8 });
    sm2.clearPreparedPublicKeys();
  });

  it('默认 8 槽：两把公钥可以共存', async () => {
    const pubA = sm2.getPublicKey(D);
    const pubB = sm2.getPublicKey(D2);
    await sm2.preparePublicKey(pubA);
    await sm2.preparePublicKey(pubB);

    expect(sm2.getPreparedPublicKeys()).toEqual(expect.arrayContaining([pubA, pubB]));
    roundtrip(D, pubA);
    roundtrip(D2, pubB);
  });

  it('重复 prepare 同一公钥不会占两个槽', async () => {
    const pub = sm2.getPublicKey(D);
    await sm2.preparePublicKey(pub);
    await sm2.preparePublicKey(pub);
    const keys = sm2.getPreparedPublicKeys();
    expect(keys.filter((k) => k === pub)).toHaveLength(1);
    roundtrip(D, pub);
  });

  it('capacity=1 时新公钥覆盖旧槽，旧公钥自动回退', async () => {
    sm2.configurePreparedKeyCache({ capacity: 1 });
    const pubA = sm2.getPublicKey(D);
    const pubB = sm2.getPublicKey(D2);
    await sm2.preparePublicKey(pubA);
    await sm2.preparePublicKey(pubB);

    expect(sm2.getPreparedPublicKeys()).toEqual([pubB]);
    roundtrip(D, pubA);
    roundtrip(D2, pubB);
  });

  it('capacity=2 且 LRU：访问过的 A 保留，最久未用的 B 被淘汰', async () => {
    sm2.configurePreparedKeyCache({ capacity: 2 });
    const pubA = sm2.getPublicKey(D);
    const pubB = sm2.getPublicKey(D2);
    const pubC = sm2.getPublicKey(D3);
    await sm2.preparePublicKey(pubA);
    await sm2.preparePublicKey(pubB);
    roundtrip(D, pubA); // 命中并刷新 A 的时间戳

    await sm2.preparePublicKey(pubC);
    const keys = sm2.getPreparedPublicKeys();
    expect(keys).toContain(pubA);
    expect(keys).toContain(pubC);
    expect(keys).not.toContain(pubB);

    roundtrip(D, pubA);
    roundtrip(D2, pubB); // 回退 wNAF
    roundtrip(D3, pubC);
  });

  it('未加载 wasm 时查询返回空数组、clear 也安全', () => {
    expect(sm2.getPreparedPublicKeys()).toEqual([]);
    expect(() => sm2.clearPreparedPublicKeys()).not.toThrow();
    expect(sm2.getPreparedPublicKey()).toBe(null);
  });

  it('clear 后所有槽清空，加解密仍正确', async () => {
    const pubA = sm2.getPublicKey(D);
    const pubB = sm2.getPublicKey(D2);
    await sm2.preparePublicKey(pubA);
    await sm2.preparePublicKey(pubB);
    sm2.clearPreparedPublicKeys();

    expect(sm2.getPreparedPublicKeys()).toEqual([]);
    roundtrip(D, pubA);
    roundtrip(D2, pubB);
  });

  it('单数查询接口保留兼容', async () => {
    const pub = sm2.getPublicKey(D);
    await sm2.preparePublicKey(pub);
    expect(sm2.getPreparedPublicKey()).toBe(pub);
    sm2.clearPreparedPublicKey();
    expect(sm2.getPreparedPublicKey()).toBe(null);
    expect(sm2.getPreparedPublicKeys()).toEqual([]);
  });

  it('capacity 只接受 1..8 的整数', () => {
    expect(() => sm2.configurePreparedKeyCache({ capacity: 0 })).toThrow(RangeError);
    expect(() => sm2.configurePreparedKeyCache({ capacity: 9 })).toThrow(RangeError);
    expect(() => sm2.configurePreparedKeyCache({ capacity: 1.5 })).toThrow(RangeError);
    expect(() => sm2.configurePreparedKeyCache({ capacity: 1 })).not.toThrow();
    expect(() => sm2.configurePreparedKeyCache({ capacity: 8 })).not.toThrow();
  });

  it('接受 65 字节带 04 前缀的公钥', async () => {
    const pub = sm2.getPublicKey(D);
    await sm2.preparePublicKey(`04${pub}`);
    expect(sm2.getPreparedPublicKeys()).toContain(pub);
    roundtrip(D, pub);
  });

  it('prepare 后 C1C3C2 / C1C2C3 都能解', async () => {
    const pub = sm2.getPublicKey(D);
    await sm2.preparePublicKey(pub);
    roundtrip(D, pub);
    const ct = sm2.encrypt(pub, MSG, { outputFormat: 'C1C2C3' });
    expect(Buffer.from(sm2.decrypt(D, ct), 'hex').equals(Buffer.from(MSG))).toBe(true);
  });

  it('prepare 前加密的密文，prepare 后仍能解', async () => {
    const pub = sm2.getPublicKey(D);
    const ct = sm2.encrypt(pub, MSG);
    await sm2.preparePublicKey(pub);
    expect(Buffer.from(sm2.decrypt(D, ct), 'hex').equals(Buffer.from(MSG))).toBe(true);
  });

  it('拒绝不在曲线上的公钥', async () => {
    await expect(sm2.preparePublicKey('00'.repeat(64))).rejects.toBeInstanceOf(
      InvalidPublicKeyError,
    );
    expect(sm2.getPreparedPublicKeys()).toEqual([]);
  });

  it('接受 SPKI PEM 公钥', async () => {
    const kp = await sm2.generateKeyPair();
    await sm2.preparePublicKey(kp.publicKeyPem);
    const ct = sm2.encrypt(kp.publicKeyPem, MSG);
    expect(Buffer.from(sm2.decrypt(kp.privateKeyPem, ct), 'hex').equals(Buffer.from(MSG))).toBe(
      true,
    );
  });
});

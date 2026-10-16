/**
 * SM9 集成测试（src/sm9 门面层）。精简版 5 个 it, 总耗时 ≤ 95s, 在 2m0s 主机 cap 内可一次跑完。
 *
 * 覆盖:
 *  1. 主公钥派生 (getSignPublicKey 对拍 GmSSL C; getEncPublicKey 输出格式; 拒绝坏输入)
 *  2. sign 定 r 跨平台 (产生期望 sig) + verify 接受
 *  3. encrypt 定 r 跨平台 (产生期望 ct) + decrypt 还原
 *  4. sign 缺 r 走 CSPRNG + verify 接受 + verify 接受 Uint8Array msg
 *  5. 长消息 (10KB) 反复加解密 + 签名验签（密文缓冲越界回归）
 *
 * 超时放宽说明：新增 sm9-kem / sm9-exch / sm9-kem-exch-kat 测试后，多个 SM9
 * 文件并行会争用 CPU，单个 pairing 相关用例耗时上升，故护栏从 20~60s 放宽到 60~120s。
 *
 * 详细 6+ 用例版（含篡改/wrong id 拒坏、随机 r round-trip 等）见 sm9-full.spec.ts。
 * 后者在内含 3-4 次 verify 时单测 ≥ 60s, 需要 CI testTimeout ≥ 150s。
 *
 * spec/plan 对应：plan Task 10；spec §6 API、§12.1 Q2（同步优先）、Q3（PKCS#8 + SM9 OID）。
 */
import { beforeAll, describe, expect, it } from 'vitest';
import * as sm9 from '@/sm9';
import params from '../vectors/sm9/params.json' with { type: 'json' };

const P = (params as typeof params & { _meta: unknown }).params;
const SIGN = (params as typeof params & { _meta: unknown }).sign;
const ENC = (params as typeof params & { _meta: unknown }).encrypt;

describe('SM9 facade', () => {
  beforeAll(async () => {
    await sm9.ensureLoaded();
  }, 30_000);

  it('主公钥派生: getSignPublicKey 对拍 GmSSL C; getEncPublicKey 输出 128 字符; 拒绝坏输入', () => {
    expect(sm9.getSignPublicKey(SIGN.ks_hex).toLowerCase()).toBe(P.hex_ppubs.toLowerCase());
    // GmSSL C sm9test.c 中 hex_Ppube 是 Montgomery 域表示, 不可与朴素 Fp 仿射直接对拍
    expect(sm9.getEncPublicKey(ENC.ke_hex)).toMatch(/^[0-9a-f]{128}$/);
    expect(() => sm9.getSignPublicKey('not-hex')).toThrow();
    expect(() => sm9.getSignPublicKey('aa'.repeat(31))).toThrow();
    expect(() => sm9.getSignPublicKey('aa'.repeat(33))).toThrow();
    expect(() => sm9.getEncPublicKey('not-hex')).toThrow();
    expect(() => sm9.getEncPublicKey('aa'.repeat(33))).toThrow();
  });

  it('sign 定 r 跨平台 + verify 接受', () => {
    const sig = sm9.sign(SIGN.ks_hex, SIGN.ida, SIGN.msg_hex, SIGN.r_hex);
    expect(sig.toLowerCase()).toBe(SIGN.expected_sig_hex.toLowerCase());
    expect(sm9.verify(SIGN.ks_hex, SIGN.ida, SIGN.msg_hex, sig)).toBe(true);
  }, 120_000);

  it('encrypt 定 r 跨平台 + decrypt 还原', () => {
    const ct = sm9.encrypt(ENC.ke_hex, ENC.idb, ENC.msg_hex, ENC.r_hex);
    expect(ct.length).toBe(ENC.expected_ct_len * 2);
    expect(ct.toLowerCase()).toBe(ENC.expected_ct_hex.toLowerCase());
    expect(sm9.decrypt(ENC.ke_hex, ENC.idb, ct).toLowerCase()).toBe(ENC.msg_hex.toLowerCase());
  }, 60_000);

  it('sign 缺 r 走 CSPRNG + verify 接受 hex / Uint8Array 两种 msg', () => {
    const sig = sm9.sign(SIGN.ks_hex, SIGN.ida, SIGN.msg_hex);
    expect(sig).toMatch(/^[0-9a-f]{192}$/);
    expect(sm9.verify(SIGN.ks_hex, SIGN.ida, SIGN.msg_hex, sig)).toBe(true);
    const u8 = new Uint8Array(Buffer.from(SIGN.msg_hex, 'hex'));
    expect(sm9.verify(SIGN.ks_hex, SIGN.ida, u8, sig)).toBe(true);
  }, 120_000);

  it('长消息 (10KB) 反复加解密 + 签名验签：不再内存越界', () => {
    // 回归：encrypt 的密文缓冲曾硬编码 alloc(4096)，密文 = 97 + |msg| 字节，
    // 明文超过 3999 字节就写越界、破坏 WASM 堆，几轮后抛
    // RuntimeError: memory access out of bounds。这里循环多轮以覆盖累积效应。
    const msg = new Uint8Array(10240);
    for (let i = 0; i < msg.length; i++) msg[i] = (i * 7) & 0xff;
    const msgHex = Buffer.from(msg).toString('hex');

    for (let i = 0; i < 8; i++) {
      const ct = sm9.encrypt(ENC.ke_hex, ENC.idb, msg);
      expect(ct.length).toBe((97 + msg.length) * 2);
      expect(sm9.decrypt(ENC.ke_hex, ENC.idb, ct).toLowerCase()).toBe(msgHex);
    }

    const sig = sm9.sign(SIGN.ks_hex, SIGN.ida, msg);
    expect(sm9.verify(SIGN.ks_hex, SIGN.ida, msg, sig)).toBe(true);
  }, 120_000);
});

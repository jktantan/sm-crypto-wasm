/**
 * 与纯 JS 国密库 `gmkitx` 的对比基准（同机、同参数、同消息）。
 *
 * 用途：README「性能」小节的对比列来源。用 `pnpm bench` 或
 * `node --import tsx bench/run.ts` 复现。
 *
 * 覆盖：SM2（公钥派生 / 签名 / 验签 / 加密 / 解密 / 密钥交换）、SM3（hash / hmac）、
 * SM4（ECB / CBC / CTR / CFB / OFB / GCM）、ZUC（EEA3）—— 即 gmkitx 有对应实现的
 * 部分。**gmkitx 没有 SM9 实现**（纯 JS 生态普遍如此，pairing 在纯 JS 里成本过高），
 * 所以 SM9 只在 sm9.bench.ts 里给本库的绝对耗时。
 *
 * 参数对齐：密钥 / IV / 消息完全相同，公钥各自从同一私钥派生。分组模式上，本库的
 * ECB 是"无填充裸块"、CBC 带 PKCS#7，因此 gmkitx 侧分别用 `padding: NONE` 与
 * `PKCS7`，保证两侧处理的数据量一致。
 *
 * 断言（而非静默）：两侧都实际算出结果，避免"空跑"污染数字。
 */

import {
  CipherMode as GkMode,
  PaddingMode as GkPadding,
  sm2GetPublicKeyFromPrivateKey as gkGetPub,
  sm2Decrypt as gkSm2Decrypt,
  sm2Encrypt as gkSm2Encrypt,
  sm2KeyExchange as gkSm2Kex,
  sm2Sign as gkSm2Sign,
  sm2Verify as gkSm2Verify,
  sm3Digest as gkSm3,
  sm3Hmac as gkSm3Hmac,
  sm4Encrypt as gkSm4,
  zucEncrypt as gkZuc,
} from 'gmkitx';
import { bench, group } from 'mitata';
import {
  createExchangeInitiator,
  createExchangeResponder,
  decrypt,
  encrypt,
  getPublicKey,
  sign,
  ensureLoaded as sm2Load,
  verify,
} from '../src/sm2/index.js';
import { hash, hmac, ensureLoaded as sm3Load } from '../src/sm3/index.js';
import {
  cryptCTR,
  cryptOFB,
  encryptCBC,
  encryptCFB,
  encryptECB,
  encryptGCM,
  ensureLoaded as sm4Load,
} from '../src/sm4/index.js';
import { resetReuseGuard, zucEncrypt, ensureLoaded as zucLoad } from '../src/zuc/index.js';

/** 与本库 sm2.bench.ts 相同的私钥 / 对端私钥 / 临时私钥，便于交叉参照。 */
const SK = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const SK2 = '6fcba2e4c3ab5a4d0b5c1e8f7a9d3b2c4e5f60718293a4b5c6d7e8f90a1b2c3d';
const R_A = '1111111111111111111111111111111111111111111111111111111111111111';
const R_B = '2222222222222222222222222222222222222222222222222222222222222222';
const MSG_SM2 = new Uint8Array(64).fill(0x5a);
const MSG_1K = new Uint8Array(1024).fill(0x5a);
const SM4_KEY = '0123456789abcdeffedcba9876543210';
const SM4_IV = 'fedcba98765432100123456789abcdef';
const SM4_GCM_IV = '000102030405060708090a0b';
const ZUC_KEY = '00112233445566778899aabbccddeeff';
const ZUC_IV = 'ffeeddccbbaa99887766554433221100';

export async function benchCompare(): Promise<void> {
  await Promise.all([sm2Load(), sm3Load(), sm4Load(), zucLoad()]);

  // ---- 预热 + 自检：两侧都必须真的算出结果 ----
  const wasmPub = getPublicKey(SK);
  const wasmPub2 = getPublicKey(SK2);
  const wasmSig = sign(SK, MSG_SM2);
  if (!verify(wasmPub, MSG_SM2, wasmSig)) throw new Error('compare bench: 本库 verify 预热失败');
  const wasmCt = encrypt(wasmPub, MSG_SM2);
  decrypt(SK, wasmCt);
  hash(MSG_1K);
  hmac(SM4_KEY, MSG_1K);
  encryptECB(SM4_KEY, MSG_1K);
  encryptCBC(SM4_KEY, SM4_IV, MSG_1K);
  cryptCTR(SM4_KEY, SM4_IV, MSG_1K);
  encryptCFB(SM4_KEY, SM4_IV, MSG_1K);
  cryptOFB(SM4_KEY, SM4_IV, MSG_1K);
  encryptGCM(SM4_KEY, SM4_GCM_IV, MSG_1K);
  resetReuseGuard();
  zucEncrypt(ZUC_KEY, ZUC_IV, MSG_1K);

  const gkPub = gkGetPub(SK);
  const gkPub2 = gkGetPub(SK2);
  const gkSig = gkSm2Sign(SK, MSG_SM2);
  if (!gkSm2Verify(gkPub, MSG_SM2, gkSig)) throw new Error('compare bench: gmkitx verify 预热失败');
  const gkCt = gkSm2Encrypt(gkPub, MSG_SM2);
  gkSm2Decrypt(SK, gkCt);
  gkSm3(MSG_1K);
  gkSm3Hmac(SM4_KEY, MSG_1K);
  gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.ECB, padding: GkPadding.NONE });
  gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CBC, padding: GkPadding.PKCS7, iv: SM4_IV });
  gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CTR, padding: GkPadding.NONE, iv: SM4_IV });
  gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CFB, padding: GkPadding.NONE, iv: SM4_IV });
  gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.OFB, padding: GkPadding.NONE, iv: SM4_IV });
  gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.GCM, iv: SM4_GCM_IV });
  gkZuc(ZUC_KEY, ZUC_IV, MSG_1K);

  // 密钥交换：两侧都按"完成一次 A↔B 协商"计 —— 本库是三方消息流的完整流程，
  // gmkitx 是双方各调一次单步 API。
  const kexWasm = async (): Promise<void> => {
    const a = await createExchangeInitiator(SK, wasmPub2, { ephemeralPrivateKey: R_A });
    const m1 = a.initiate();
    const b = await createExchangeResponder(SK2, wasmPub, { ephemeralPrivateKey: R_B });
    const m2 = b.respond(m1);
    const conf = a.confirm(m2); // A 自己的确认值 S_A
    b.getSharedKey(conf);
    a.getSharedKey(conf);
  };
  const gkKex = (): void => {
    gkSm2Kex({
      privateKey: SK,
      publicKey: gkPub,
      peerPublicKey: gkPub2,
      peerTempPublicKey: gkGetPub(R_B),
      tempPrivateKey: R_A,
      isInitiator: true,
      keyLength: 16,
    });
    gkSm2Kex({
      privateKey: SK2,
      publicKey: gkPub2,
      peerPublicKey: gkPub,
      peerTempPublicKey: gkGetPub(R_A),
      tempPrivateKey: R_B,
      isInitiator: false,
      keyLength: 16,
    });
  };
  await kexWasm();
  gkKex();

  group('SM2 — sm-crypto-wasm vs gmkitx', () => {
    bench('publicKey derive / wasm', () => {
      getPublicKey(SK);
    });
    bench('publicKey derive / gmkitx', () => {
      gkGetPub(SK);
    });
    bench('sign 64B / wasm', () => {
      sign(SK, MSG_SM2);
    });
    bench('sign 64B / gmkitx', () => {
      gkSm2Sign(SK, MSG_SM2);
    });
    bench('verify 64B / wasm', () => {
      verify(wasmPub, MSG_SM2, wasmSig);
    });
    bench('verify 64B / gmkitx', () => {
      gkSm2Verify(gkPub, MSG_SM2, gkSig);
    });
    bench('encrypt 64B / wasm', () => {
      encrypt(wasmPub, MSG_SM2);
    });
    bench('encrypt 64B / gmkitx', () => {
      gkSm2Encrypt(gkPub, MSG_SM2);
    });
    bench('decrypt 64B / wasm', () => {
      decrypt(SK, wasmCt);
    });
    bench('decrypt 64B / gmkitx', () => {
      gkSm2Decrypt(SK, gkCt);
    });
    bench('key exchange (A↔B) / wasm', async () => {
      await kexWasm();
    });
    bench('key exchange (A↔B) / gmkitx', () => {
      gkKex();
    });
  });

  group('SM3 — sm-crypto-wasm vs gmkitx', () => {
    bench('hash 1KB / wasm', () => {
      hash(MSG_1K);
    });
    bench('hash 1KB / gmkitx', () => {
      gkSm3(MSG_1K);
    });
    bench('hmac 1KB / wasm', () => {
      hmac(SM4_KEY, MSG_1K);
    });
    bench('hmac 1KB / gmkitx', () => {
      gkSm3Hmac(SM4_KEY, MSG_1K);
    });
  });

  group('SM4 — sm-crypto-wasm vs gmkitx (1KB)', () => {
    bench('ECB / wasm', () => {
      encryptECB(SM4_KEY, MSG_1K);
    });
    bench('ECB / gmkitx', () => {
      gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.ECB, padding: GkPadding.NONE });
    });
    bench('CBC / wasm', () => {
      encryptCBC(SM4_KEY, SM4_IV, MSG_1K);
    });
    bench('CBC / gmkitx', () => {
      gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CBC, padding: GkPadding.PKCS7, iv: SM4_IV });
    });
    bench('CTR / wasm', () => {
      cryptCTR(SM4_KEY, SM4_IV, MSG_1K);
    });
    bench('CTR / gmkitx', () => {
      gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CTR, padding: GkPadding.NONE, iv: SM4_IV });
    });
    bench('CFB / wasm', () => {
      encryptCFB(SM4_KEY, SM4_IV, MSG_1K);
    });
    bench('CFB / gmkitx', () => {
      gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CFB, padding: GkPadding.NONE, iv: SM4_IV });
    });
    bench('OFB / wasm', () => {
      cryptOFB(SM4_KEY, SM4_IV, MSG_1K);
    });
    bench('OFB / gmkitx', () => {
      gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.OFB, padding: GkPadding.NONE, iv: SM4_IV });
    });
    bench('GCM / wasm', () => {
      encryptGCM(SM4_KEY, SM4_GCM_IV, MSG_1K);
    });
    bench('GCM / gmkitx', () => {
      gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.GCM, iv: SM4_GCM_IV });
    });
  });

  group('ZUC — sm-crypto-wasm vs gmkitx (EEA3)', () => {
    bench('EEA3 encrypt 1KB / wasm', () => {
      resetReuseGuard(); // 本库的密钥流复用保护：每次从"无记录"开始
      zucEncrypt(ZUC_KEY, ZUC_IV, MSG_1K);
    });
    bench('EEA3 encrypt 1KB / gmkitx', () => {
      gkZuc(ZUC_KEY, ZUC_IV, MSG_1K);
    });
  });
}

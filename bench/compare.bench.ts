/**
 * 与纯 JS 国密库 `gmkitx` 的对比基准（同机、同参数、同消息）。
 *
 * 用途：README「性能」小节的数字来源。用 `pnpm bench` 或
 * `node --import tsx bench/run.ts` 复现。
 *
 * 覆盖 SM2 / SM3 / SM4 / ZUC —— GMKit **没有 SM9 实现**（纯 JS 生态普遍如此，
 * pairing 在纯 JS 里成本过高），故 SM9 只给本库绝对耗时，见 sm9.bench.ts。
 *
 * 参数对齐：密钥 / IV / 消息完全相同，公钥各自从同一私钥派生；两侧都是同步
 * 调用（本库首次使用前需要 ensureLoaded，已在预热中完成）。
 * 断言（而非静默）：两侧都实际算出结果，避免"空跑"污染数字。
 */

import {
  CipherMode as GkMode,
  PaddingMode as GkPadding,
  sm2GetPublicKeyFromPrivateKey as gkGetPub,
  sm2Sign as gkSm2Sign,
  sm2Verify as gkSm2Verify,
  sm3Digest as gkSm3,
  sm4Encrypt as gkSm4,
  zucEncrypt as gkZuc,
} from 'gmkitx';
import { bench, group } from 'mitata';
import { getPublicKey, sign, ensureLoaded as sm2Load, verify } from '../src/sm2/index.js';
import { hash, ensureLoaded as sm3Load } from '../src/sm3/index.js';
import { encryptCBC, ensureLoaded as sm4Load } from '../src/sm4/index.js';
import { resetReuseGuard, zucEncrypt, ensureLoaded as zucLoad } from '../src/zuc/index.js';

/** 与本库 sm2.bench.ts 相同的私钥，便于交叉参照。 */
const SK = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const MSG_SM2 = new Uint8Array(64).fill(0x5a);
const MSG_1K = new Uint8Array(1024).fill(0x5a);
const SM4_KEY = '0123456789abcdeffedcba9876543210';
const SM4_IV = 'fedcba98765432100123456789abcdef';
const ZUC_KEY = '00112233445566778899aabbccddeeff';
const ZUC_IV = 'ffeeddccbbaa99887766554433221100';

export async function benchCompare(): Promise<void> {
  await Promise.all([sm2Load(), sm3Load(), sm4Load(), zucLoad()]);

  // 预热 + 自检：两侧都必须真的算出结果
  const wasmPub = getPublicKey(SK);
  const wasmSig = sign(SK, MSG_SM2);
  if (!verify(wasmPub, MSG_SM2, wasmSig)) throw new Error('compare bench: 本库 verify 预热失败');
  hash(MSG_1K);
  encryptCBC(SM4_KEY, SM4_IV, MSG_1K);
  resetReuseGuard();
  zucEncrypt(ZUC_KEY, ZUC_IV, MSG_1K);

  const gkPub = gkGetPub(SK);
  const gkSig = gkSm2Sign(SK, MSG_SM2);
  if (!gkSm2Verify(gkPub, MSG_SM2, gkSig)) throw new Error('compare bench: gmkitx verify 预热失败');
  gkSm3(MSG_1K);
  gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CBC, padding: GkPadding.PKCS7, iv: SM4_IV });
  gkZuc(ZUC_KEY, ZUC_IV, MSG_1K);

  group('SM2 — sm-crypto-wasm vs gmkitx', () => {
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
  });

  group('SM3 — sm-crypto-wasm vs gmkitx', () => {
    bench('hash 1KB / wasm', () => {
      hash(MSG_1K);
    });
    bench('hash 1KB / gmkitx', () => {
      gkSm3(MSG_1K);
    });
  });

  group('SM4 — sm-crypto-wasm vs gmkitx (CBC/PKCS7)', () => {
    bench('CBC encrypt 1KB / wasm', () => {
      encryptCBC(SM4_KEY, SM4_IV, MSG_1K);
    });
    bench('CBC encrypt 1KB / gmkitx', () => {
      gkSm4(SM4_KEY, MSG_1K, { mode: GkMode.CBC, padding: GkPadding.PKCS7, iv: SM4_IV });
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

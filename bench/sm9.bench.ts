/**
 * SM9 基准。
 *
 * 覆盖本库 SM9 的全部公开操作：主密钥对生成、主公钥派生（签名 / 加密）、用户公钥
 * 复算、签名/验签、加密/解密、KEM 封装/解封装，以及一次完整的密钥交换（A↔B）。
 *
 * 注意：SM9 的每个操作都由 pairing 主导（单次几毫秒到几十毫秒），所以这里的数字
 * 主要用途是留基线、看回归。纯 JS 生态没有可比实现（pairing 在纯 JS 里成本过高）。
 *
 * 签名主私钥与加密主私钥形态不同：签名主公钥是 G2 点（128B），加密主公钥是
 * G1 点（64B）—— `generateKeyPair` 用 `purpose` 区分两者。
 */
import { bench, group } from 'mitata';
import {
  createExchangeInitiator,
  createExchangeResponder,
  decrypt,
  encrypt,
  ensureLoaded,
  generateKeyPair,
  getEncPublicKey,
  getSignPublicKey,
  getUserPublicKey,
  kemDecrypt,
  kemEncrypt,
  sign,
  verify,
} from '../src/sm9/index.js';

/** 固定的主私钥（合法标量：< n），用于密钥派生类基线，避免把 CSPRNG 算进数字。 */
const KS = 'd0e0f'.padStart(64, '0');
const KE = 'a0b0c0d'.padStart(64, '0');
/** 密钥交换的固定临时私钥（两侧各一个）。 */
const R_A = '0101010101010101010101010101010101010101010101010101010101010101';
const R_B = '0202020202020202020202020202020202020202020202020202020202020202';

export async function benchSm9(): Promise<void> {
  await ensureLoaded();

  const id = 'bench@x.io';
  const id2 = 'bench2@x.io';
  const kpSign = await generateKeyPair({ id });
  const kpEnc = await generateKeyPair({ id, purpose: 'enc' });
  const msg = new Uint8Array(32).fill(0x42);

  // 预热：让各 wasm 入口走过一次，避开首次 allocate 与 cache miss。
  const sig = sign(kpSign.masterPrivatePem, id, msg);
  verify(kpSign.masterPrivatePem, id, msg, sig);
  const ct = encrypt(kpEnc.masterPublicPem, id, msg);
  decrypt(kpEnc.masterPrivatePem, id, ct);
  const kem = kemEncrypt(KE, id);
  kemDecrypt(KE, id, kem.encapsulation);
  getSignPublicKey(KS);
  getEncPublicKey(KE);
  getUserPublicKey(getSignPublicKey(KS), id);

  const kex = async (): Promise<void> => {
    const a = await createExchangeInitiator(KE, id, id2, { ephemeral: R_A });
    const m1 = a.initiate();
    const b = await createExchangeResponder(KE, id2, id, { ephemeral: R_B });
    const m2 = b.respond(m1);
    const conf = a.confirm(m2);
    b.getSharedKey(conf);
    a.getSharedKey(m2);
  };
  await kex();

  group('SM9', () => {
    bench('generateKeyPair (sign)', async () => {
      await generateKeyPair({ id });
    });
    bench('generateKeyPair (enc)', async () => {
      await generateKeyPair({ id, purpose: 'enc' });
    });
    bench('sign master public key', () => {
      getSignPublicKey(KS);
    });
    bench('enc master public key', () => {
      getEncPublicKey(KE);
    });
    bench('user public key (derive)', () => {
      getUserPublicKey(getSignPublicKey(KS), id);
    });
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
    bench('KEM encapsulate', () => {
      kemEncrypt(KE, id);
    });
    bench('KEM decapsulate', () => {
      kemDecrypt(KE, id, kem.encapsulation);
    });
    bench('key exchange (full A↔B)', async () => {
      await kex();
    });
  });
}

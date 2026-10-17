/**
 * SM2 基准。
 *
 * 覆盖本库 SM2 的全部公开操作：公钥派生、密钥对生成、签名/验签、加密/解密
 * （C1C3C2）与一次完整的密钥交换（A↔B 三方消息流，含两端取共享密钥）。
 *
 * 签/验/加/解均为单次调用（32 字节私钥 + 64 字节消息），命中 wasm 入口的恒定
 * 成本；密钥生成与密钥交换是异步（含宿主 CSPRNG）。
 */
import { bench, group } from 'mitata';
import {
  clearPreparedPublicKeys,
  createExchangeInitiator,
  createExchangeResponder,
  decrypt,
  encrypt,
  ensureLoaded,
  generateKeyPair,
  getPublicKey,
  hybridDecrypt,
  hybridEncrypt,
  kemDecrypt,
  kemEncrypt,
  preparePublicKey,
  sign,
  verify,
} from '../src/sm2/index.js';
import { ensureLoaded as ensureSm4Loaded } from '../src/sm4/index.js';

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
/** 对端私钥（仅用于基准的密钥交换，合法标量：< n）。 */
const D2 = '6fcba2e4c3ab5a4d0b5c1e8f7a9d3b2c4e5f60718293a4b5c6d7e8f90a1b2c3d';
/** 固定的临时私钥，避免把 CSPRNG 开销算进密钥交换（两侧必须用同一对）。 */
const RA = '1111111111111111111111111111111111111111111111111111111111111111';
const RB = '2222222222222222222222222222222222222222222222222222222222222222';
const MSG = new Uint8Array(64).fill(0x5a);

export async function benchSm2(): Promise<void> {
  await ensureLoaded();
  await ensureSm4Loaded();
  const pub = getPublicKey(D);
  const pub2 = getPublicKey(D2);
  // 多槽轮换用例：8 把互不相同的合法私钥（第 0 把复用 D2）。
  const rotatingD = Array.from({ length: 8 }, (_, i) =>
    i === 0 ? D2 : (BigInt('0x1234567890abcdef') * BigInt(i)).toString(16).padStart(64, '0'),
  );
  const rotatingPubs = rotatingD.map((d) => getPublicKey(d));
  const preparedPub = rotatingPubs[0];
  if (preparedPub === undefined) throw new Error('bench: empty rotating key list');
  const sig = sign(D, MSG);
  verify(pub, MSG, sig);
  const ct = encrypt(pub, MSG);
  decrypt(D, ct);
  const kem = kemEncrypt(pub, 16);
  kemDecrypt(D, kem.encapsulation, 16);
  const big = new Uint8Array(1024 * 1024).fill(0x5a);
  const hybridSealed = hybridEncrypt(pub, big);
  hybridDecrypt(D, hybridSealed);

  const kex = async (): Promise<void> => {
    const a = await createExchangeInitiator(D, pub2, { ephemeralPrivateKey: RA });
    const m1 = a.initiate();
    const b = await createExchangeResponder(D2, pub, { ephemeralPrivateKey: RB });
    const m2 = b.respond(m1);
    const conf = a.confirm(m2); // 返回的是 A 自己的确认值 S_A
    b.getSharedKey(conf); // B 用 S_A 校验并派生
    a.getSharedKey(conf); // A 用同一个 S_A 派生（SM2 的发起方签名收 InitiatorConfirm）
  };
  await kex(); // 预热 + 自检
  await generateKeyPair();

  // 固定公钥预计算：填满 8 个槽（不包含 pub，普通 encrypt 仍走 wNAF 基线）。
  for (const p of rotatingPubs) await preparePublicKey(p);

  group('SM2', () => {
    bench('publicKey derive (point mul)', () => {
      getPublicKey(D);
    });
    bench('generateKeyPair', async () => {
      await generateKeyPair();
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
    bench('encrypt 64B (prepared pk)', () => {
      encrypt(preparedPub, MSG);
    });
    let rot = 0;
    bench('encrypt 64B (8 prepared keys, rotating)', () => {
      const p = rotatingPubs[rot++ & 7];
      if (p !== undefined) encrypt(p, MSG);
    });
    bench('preparePublicKey (build comb table)', async () => {
      clearPreparedPublicKeys();
      await preparePublicKey(preparedPub);
    });
    bench('decrypt 64B (auto)', () => {
      decrypt(D, ct);
    });
    bench('KEM encapsulate (16B key)', () => {
      kemEncrypt(pub, 16);
    });
    bench('KEM decapsulate (16B key)', () => {
      kemDecrypt(D, kem.encapsulation, 16);
    });
    bench('hybrid encrypt 1MB', () => {
      hybridEncrypt(pub, big);
    });
    bench('hybrid decrypt 1MB', () => {
      hybridDecrypt(D, hybridSealed);
    });
    bench('key exchange (full A↔B)', async () => {
      await kex();
    });
  });
}

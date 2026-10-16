/**
 * 三方国密库横向基准：本库 vs `Cubelrti/sm-crypto-wasm`(Rust→WASM) vs `sm-crypto-v2`(TS/纯 JS)。
 *
 * 运行：
 *   node --import tsx bench/compare-cubelrti.bench.ts
 *   # 或 pnpm bench:cubelrti
 *
 * Cubelrti 侧产物（放在 bench/.vendor/cubelrti/，已 gitignore），二选一：
 *   1. `pkg/` —— 容器内 Rust + wasm-pack 构建（首选：严格对应其源码 release）：
 *        bash bench/build-cubelrti-wasm.sh
 *   2. `tt/`  —— 复制其仓库内已提交的 release 预构建产物（已验证无 DWARF 调试符号）：
 *        mkdir -p bench/.vendor/cubelrti && cp -r <Cubelrti/sm-crypto-wasm>/templates/tt/sm-crypto bench/.vendor/cubelrti/tt
 *
 * `sm-crypto-v2` 直接走 npm 发布的 dist（仓库 devDependency）。本库走 `src/`
 * （与其余 bench 文件一致，wasm 为 `pnpm build:wasm:*` 的 release 产物）。
 *
 * 参数对齐（由 `selfCheck()` 逐字节裁决，不一致即抛错，避免出假数字）：
 *   - SM3 / SM3-HMAC：1KB 0x5a 消息，16B 0x11 密钥
 *   - SM4：ECB 无填充 / CBC PKCS#7 / CTR 无填充 / GCM（12B IV、空 AAD）
 *   - SM2：SM3withSM2 + 默认用户标识 `1234567812345678`，签名输出裸 r‖s（非 DER）
 *
 * 易混淆的格式差异（不影响各自计时，仅影响互操作）：
 *   - 公钥：本库 64B（无前缀）／ `sm-crypto-v2` 需要 65B（`04` 前缀）
 *   - 密文 C1：本库 65B（`04` 前缀）／ Cubelrti 64B（无前缀）／ v2 64B（无前缀）
 *   - SM4 CTR：`sm-crypto-v2` 未实现，故该项仅两方
 *   - SM2 密钥对：本库返回 PKCS#8/SPKI PEM 且为 async，另两方返回 hex
 *
 * ⚠️ Cubelrti WASM 的每个导出函数内部都执行 `console::log_1("invoked ...")`。
 * 为不让 stdout I/O 污染计时，bench 期间 `console.log` 被替换成 no-op，mitata 的结果
 * 改由其 `print` 回调输出。Cubelrti 侧因此仍保留"每次调用多一次被丢弃的 JS 调用"
 * 的开销 —— 这是该库自身的实现瑕疵，本文件不做替它擦除的额外优化。
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bench, group, run } from 'mitata';
import { sm2 as v2sm2, sm3 as v2sm3, sm4 as v2sm4 } from 'sm-crypto-v2';
import {
  generateKeyPair,
  getPublicKey,
  decrypt as sm2Decrypt,
  encrypt as sm2Encrypt,
  ensureLoaded as sm2Load,
  sign as sm2Sign,
  verify as sm2Verify,
} from '../src/sm2/index.js';
import { hash as sm3Hash, hmac as sm3Hmac, ensureLoaded as sm3Load } from '../src/sm3/index.js';
import {
  cryptCTR,
  decryptCBC,
  encryptCBC,
  encryptECB,
  encryptGCM,
  ensureLoaded as sm4Load,
} from '../src/sm4/index.js';

const require = createRequire(import.meta.url);

// ---------------------------------------------------------------- 固定参数

const SK = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const MSG_64B = new Uint8Array(64).fill(0x5a);
const MSG_1KB = new Uint8Array(1024).fill(0x5a);
const MSG_32B = new Uint8Array(32).fill(0x5a);
const MSG_16B = new Uint8Array(16).fill(0x5a);
const SM3_HMAC_KEY = new Uint8Array(16).fill(0x11);
const SM4_KEY = new Uint8Array(Buffer.from('0123456789abcdeffedcba9876543210', 'hex'));
const SM4_IV = new Uint8Array(Buffer.from('fedcba98765432100123456789abcdef', 'hex'));
const SM4_GCM_IV = new Uint8Array(Buffer.from('000102030405060708090a0b', 'hex'));

type Sm4Opts = {
  mode: 'ecb' | 'cbc' | 'ctr' | 'gcm';
  padding?: 'none' | 'pkcs7' | 'pkcs#7';
  iv?: Uint8Array;
  aad?: Uint8Array;
};

// ---------------------------------------------------- Cubelrti 产物接入层

/**
 * 把 Cubelrti 的两种交付形态统一成同一组调用：
 *   - `pkg/`：wasm-pack `--target nodejs` 的裸导出（`sm2_sign`、`sm3`…）
 *   - `tt/` ：其仓库提交的小程序 glue（`default.sm2.doSignature`…）
 */
interface CubelrtiLib {
  kind: 'pkg' | 'tt';
  sm2Sign(msg: Uint8Array, sk: string): string;
  sm2Verify(msg: Uint8Array, pk: string, sig: string): boolean;
  sm2Encrypt(msg: Uint8Array, pk: string): Uint8Array;
  sm2Decrypt(ct: Uint8Array, sk: string): Uint8Array;
  sm2GenerateKeyPair(): { privateKey: string; publicKey: string };
  sm3(msg: Uint8Array): Uint8Array;
  sm3Hmac(key: Uint8Array, msg: Uint8Array): Uint8Array;
  sm4(data: Uint8Array, key: Uint8Array, o: Sm4Opts, decrypt: boolean): Uint8Array;
}

const VENDOR = fileURLToPath(new URL('./.vendor/cubelrti/', import.meta.url));
const RNG_SEED = new Uint8Array(32).fill(0x42);

async function loadCubelrti(): Promise<CubelrtiLib> {
  const pkgJs = join(VENDOR, 'pkg', 'sm_crypto_wasm.js');
  if (existsSync(pkgJs)) {
    const pkg = require(pkgJs);
    pkg.init_rng_pool(RNG_SEED);
    const sm2Opts = { hash: true, der: false };
    return {
      kind: 'pkg',
      sm2Sign: (m, sk) => pkg.sm2_sign(sk, m, sm2Opts),
      sm2Verify: (m, pk, sig) => pkg.sm2_verify(pk, m, sig, sm2Opts),
      sm2Encrypt: (m, pk) => pkg.sm2_encrypt(pk, m, { asn1: false, c1c2c3: false }),
      sm2Decrypt: (ct, sk) => pkg.sm2_decrypt(sk, ct, { asn1: false, c1c2c3: false }),
      sm2GenerateKeyPair: () => pkg.sm2_generate_keypair(),
      sm3: (m) => pkg.sm3(m),
      sm3Hmac: (k, m) => pkg.sm3_hmac(k, m),
      sm4: (d, k, o, dec) =>
        (dec ? pkg.sm4_decrypt : pkg.sm4_encrypt)(d, k, {
          mode: o.mode,
          padding: o.padding === 'none' ? 'none' : 'pkcs7',
          iv: o.iv,
          aad: o.aad,
        }),
    };
  }

  const ttDir = join(VENDOR, 'tt');
  const ttJs = join(ttDir, 'index.js');
  if (existsSync(ttJs)) {
    // 仓库根 package.json 是 `"type": "module"`，而该 glue 是 CommonJS；补一个局部声明，
    // Node 才会按 CJS 加载它（vendor 目录是 gitignored 的本地产物目录）。
    const cjsMarker = join(ttDir, 'package.json');
    if (!existsSync(cjsMarker)) writeFileSync(cjsMarker, '{"type":"commonjs"}\n');

    // glue 里用的是字节小程序的全局 `TTWebAssembly`，Node 下 shim 成标准 WebAssembly；
    // 其加载路径固定为 `/sm-crypto/crypto.wasm`，由下面的 instantiate 重定向到 vendor 目录。
    (globalThis as Record<string, unknown>).TTWebAssembly = {
      Instance: WebAssembly.Instance,
      Module: WebAssembly.Module,
      instantiate: async (p: string, imports: WebAssembly.Imports) => {
        const bytes = readFileSync(join(ttDir, String(p).split('/').pop() ?? ''));
        return (await WebAssembly.instantiate(bytes, imports)).instance;
      },
    };
    const glue = require(ttJs);
    await glue.initSMCrypto();
    glue.sm2.initRNGPool(RNG_SEED);
    const sm2Opts = { hash: true, der: false };
    return {
      kind: 'tt',
      sm2Sign: (m, sk) => glue.sm2.doSignature(m, sk, sm2Opts),
      sm2Verify: (m, pk, sig) => glue.sm2.doVerifySignature(m, pk, sig, sm2Opts),
      sm2Encrypt: (m, pk) =>
        glue.sm2.encrypt(m, pk, { cipherMode: 1, asn1: false, output: 'array' }),
      sm2Decrypt: (ct, sk) =>
        glue.sm2.decrypt(ct, sk, { cipherMode: 1, asn1: false, output: 'array' }),
      sm2GenerateKeyPair: () => glue.sm2.generateKeyPairHex(),
      sm3: (m) => glue.sm3(m),
      sm3Hmac: (k, m) => glue.sm3(m, { key: k }),
      sm4: (d, k, o, dec) =>
        (dec ? glue.sm4.decrypt : glue.sm4.encrypt)(d, k, {
          mode: o.mode,
          // 只放已定义的键：该 glue 用 `Object.assign({padding:'pkcs7',…}, opts)` 填默认值，
          // 显式传 `padding: undefined` 会覆盖掉默认，令 Rust 侧 `padding: String`
          // 反序列化失败并 panic（wasm `unreachable`）。
          padding: o.padding === 'none' ? 'none' : 'pkcs7',
          ...(o.iv !== undefined ? { iv: o.iv } : {}),
          ...(o.aad !== undefined ? { aad: o.aad } : {}),
          output: 'array',
        }),
    };
  }

  throw new Error(
    `未找到 Cubelrti 产物：${VENDOR}\n` +
      '  · 容器构建：bash bench/build-cubelrti-wasm.sh\n' +
      '  · 或用其仓库预构建产物：cp -r <Cubelrti/sm-crypto-wasm>/templates/tt/sm-crypto bench/.vendor/cubelrti/tt',
  );
}

// ------------------------------------------------------------------ 自检

const hex = (u8: Uint8Array): string => Buffer.from(u8).toString('hex');

/** 三库跑同一输入并逐字节比对；不一致直接抛错，避免基准跑在错误参数上。 */
function selfCheck(cw: CubelrtiLib, minePub: string, pub65: string): void {
  const eq = (name: string, a: string, b: string, c?: string): void => {
    const bad =
      a.toLowerCase() !== b.toLowerCase() ||
      (c !== undefined && b.toLowerCase() !== c.toLowerCase());
    if (bad)
      throw new Error(`selfCheck 失败：${name}\n  mine=${a}\n  cw=${b}\n  v2=${c ?? '<n/a>'}`);
  };

  eq(
    'SM3("abc")',
    sm3Hash(hex(new Uint8Array([0x61, 0x62, 0x63]))),
    hex(cw.sm3(new Uint8Array([0x61, 0x62, 0x63]))),
    v2sm3('abc'),
  );
  eq('SM3 1KB', sm3Hash(MSG_1KB), hex(cw.sm3(MSG_1KB)), v2sm3(MSG_1KB));
  eq(
    'SM3 hmac 1KB',
    sm3Hmac(SM3_HMAC_KEY, MSG_1KB),
    hex(cw.sm3Hmac(SM3_HMAC_KEY, MSG_1KB)),
    v2sm3(MSG_1KB, { key: SM3_HMAC_KEY }),
  );

  eq(
    'SM4-ECB 16B',
    encryptECB(SM4_KEY, MSG_16B),
    hex(cw.sm4(MSG_16B, SM4_KEY, { mode: 'ecb', padding: 'none' }, false)),
    hex(
      v2sm4.encrypt(MSG_16B, SM4_KEY, {
        mode: 'ecb',
        padding: 'none',
        output: 'array',
      }) as Uint8Array,
    ),
  );
  eq(
    'SM4-CBC 32B',
    encryptCBC(SM4_KEY, SM4_IV, MSG_32B),
    hex(cw.sm4(MSG_32B, SM4_KEY, { mode: 'cbc', padding: 'pkcs7', iv: SM4_IV }, false)),
    hex(
      v2sm4.encrypt(MSG_32B, SM4_KEY, {
        mode: 'cbc',
        padding: 'pkcs#7',
        iv: SM4_IV,
        output: 'array',
      }) as Uint8Array,
    ),
  );
  eq(
    'SM4-CTR 1KB',
    cryptCTR(SM4_KEY, SM4_IV, MSG_1KB),
    hex(cw.sm4(MSG_1KB, SM4_KEY, { mode: 'ctr', padding: 'none', iv: SM4_IV }, false)),
  );

  const g = encryptGCM(SM4_KEY, SM4_GCM_IV, MSG_1KB);
  const gcw = cw.sm4(
    MSG_1KB,
    SM4_KEY,
    { mode: 'gcm', iv: SM4_GCM_IV, aad: new Uint8Array(0) },
    false,
  );
  const gv2 = v2sm4.encrypt(MSG_1KB, SM4_KEY, {
    mode: 'gcm',
    iv: SM4_GCM_IV,
    output: 'array',
    outputTag: true,
  }) as { output: Uint8Array; tag: Uint8Array };
  eq('SM4-GCM ct', g.ct, hex(gcw.subarray(0, -16)), hex(gv2.output));
  eq('SM4-GCM tag', g.tag, hex(gcw.subarray(-16)), hex(gv2.tag));

  // SM2 签名含随机 k，无法按字节比；改用「本库签名 → 三方交叉验签」+「各自加密 → 自解」。
  const sig = sm2Sign(SK, MSG_64B);
  const verdicts = [
    sm2Verify(minePub, MSG_64B, sig),
    cw.sm2Verify(MSG_64B, minePub, sig),
    v2sm2.doVerifySignature(MSG_64B, sig, pub65, { hash: true, der: false }),
  ];
  if (verdicts.some((v) => v !== true)) {
    throw new Error(`selfCheck 失败：SM2 交叉验签 ${JSON.stringify(verdicts)}`);
  }

  const back = [
    sm2Decrypt(SK, sm2Encrypt(minePub, MSG_64B)),
    hex(cw.sm2Decrypt(cw.sm2Encrypt(MSG_64B, minePub), SK)),
    hex(
      v2sm2.doDecrypt(v2sm2.doEncrypt(MSG_64B, pub65, 1), SK, 1, { output: 'array' }) as Uint8Array,
    ),
  ];
  const expect = hex(MSG_64B);
  if (back.some((b) => b.toLowerCase() !== expect)) {
    throw new Error(`selfCheck 失败：SM2 明文还原 ${JSON.stringify(back)}`);
  }
}

// ------------------------------------------------------------------ 主流程

async function main(): Promise<void> {
  await Promise.all([sm2Load(), sm3Load(), sm4Load()]);
  const cw = await loadCubelrti();

  // 公钥：本库 64B 无前缀；sm-crypto-v2（noble-curves）要求 65B 带 04 前缀。
  const minePub = getPublicKey(SK);
  const pub65 = `04${minePub}`;
  await v2sm2.initRNGPool();

  selfCheck(cw, minePub, pub65);

  // 预先算好各方的输入/输出，bench 回调里只做被测的那一次操作。
  const mineSig = sm2Sign(SK, MSG_64B);
  const cwSig = cw.sm2Sign(MSG_64B, SK);
  const v2Sig = v2sm2.doSignature(MSG_64B, SK, { hash: true, der: false, publicKey: pub65 });
  const mineCt = sm2Encrypt(minePub, MSG_64B);
  const cwCt = cw.sm2Encrypt(MSG_64B, minePub);
  const v2Ct = v2sm2.doEncrypt(MSG_64B, pub65, 1);
  const mineSm4Cbc = encryptCBC(SM4_KEY, SM4_IV, MSG_1KB);
  const cwSm4Cbc = cw.sm4(MSG_1KB, SM4_KEY, { mode: 'cbc', padding: 'pkcs7', iv: SM4_IV }, false);
  const v2Sm4Cbc = v2sm4.encrypt(MSG_1KB, SM4_KEY, {
    mode: 'cbc',
    padding: 'pkcs#7',
    iv: SM4_IV,
    output: 'array',
  }) as Uint8Array;

  group('SM2 64B — 本库 vs Cubelrti/WASM(Rust) vs sm-crypto-v2', () => {
    bench('sign / 本库', () => void sm2Sign(SK, MSG_64B));
    bench('sign / Cubelrti', () => void cw.sm2Sign(MSG_64B, SK));
    bench(
      'sign / sm-crypto-v2',
      () => void v2sm2.doSignature(MSG_64B, SK, { hash: true, der: false, publicKey: pub65 }),
    );

    bench('verify / 本库', () => void sm2Verify(minePub, MSG_64B, mineSig));
    bench('verify / Cubelrti', () => void cw.sm2Verify(MSG_64B, minePub, cwSig));
    bench(
      'verify / sm-crypto-v2',
      () => void v2sm2.doVerifySignature(MSG_64B, v2Sig, pub65, { hash: true, der: false }),
    );

    bench('encrypt / 本库', () => void sm2Encrypt(minePub, MSG_64B));
    bench('encrypt / Cubelrti', () => void cw.sm2Encrypt(MSG_64B, minePub));
    bench('encrypt / sm-crypto-v2', () => void v2sm2.doEncrypt(MSG_64B, pub65, 1));

    bench('decrypt / 本库', () => void sm2Decrypt(SK, mineCt));
    bench('decrypt / Cubelrti', () => void cw.sm2Decrypt(cwCt, SK));
    bench('decrypt / sm-crypto-v2', () => void v2sm2.doDecrypt(v2Ct, SK, 1, { output: 'array' }));

    bench('keypair / 本库', async () => void (await generateKeyPair()));
    bench('keypair / Cubelrti', () => void cw.sm2GenerateKeyPair());
    bench('keypair / sm-crypto-v2', () => void v2sm2.generateKeyPairHex());
  });

  group('SM3 1KB — 三方', () => {
    bench('hash / 本库', () => void sm3Hash(MSG_1KB));
    bench('hash / Cubelrti', () => void cw.sm3(MSG_1KB));
    bench('hash / sm-crypto-v2', () => void v2sm3(MSG_1KB));

    bench('hmac / 本库', () => void sm3Hmac(SM3_HMAC_KEY, MSG_1KB));
    bench('hmac / Cubelrti', () => void cw.sm3Hmac(SM3_HMAC_KEY, MSG_1KB));
    bench('hmac / sm-crypto-v2', () => void v2sm3(MSG_1KB, { key: SM3_HMAC_KEY }));
  });

  group('SM4 1KB — 三方（CTR 仅两方：sm-crypto-v2 未实现）', () => {
    bench('ECB encrypt / 本库', () => void encryptECB(SM4_KEY, MSG_1KB));
    bench(
      'ECB encrypt / Cubelrti',
      () => void cw.sm4(MSG_1KB, SM4_KEY, { mode: 'ecb', padding: 'none' }, false),
    );
    bench(
      'ECB encrypt / sm-crypto-v2',
      () => void v2sm4.encrypt(MSG_1KB, SM4_KEY, { mode: 'ecb', padding: 'none', output: 'array' }),
    );

    bench('CBC encrypt / 本库', () => void encryptCBC(SM4_KEY, SM4_IV, MSG_1KB));
    bench(
      'CBC encrypt / Cubelrti',
      () => void cw.sm4(MSG_1KB, SM4_KEY, { mode: 'cbc', padding: 'pkcs7', iv: SM4_IV }, false),
    );
    bench(
      'CBC encrypt / sm-crypto-v2',
      () =>
        void v2sm4.encrypt(MSG_1KB, SM4_KEY, {
          mode: 'cbc',
          padding: 'pkcs#7',
          iv: SM4_IV,
          output: 'array',
        }),
    );

    bench('CBC decrypt / 本库', () => void decryptCBC(SM4_KEY, SM4_IV, mineSm4Cbc));
    bench(
      'CBC decrypt / Cubelrti',
      () => void cw.sm4(cwSm4Cbc, SM4_KEY, { mode: 'cbc', padding: 'pkcs7', iv: SM4_IV }, true),
    );
    bench(
      'CBC decrypt / sm-crypto-v2',
      () =>
        void v2sm4.decrypt(v2Sm4Cbc, SM4_KEY, {
          mode: 'cbc',
          padding: 'pkcs#7',
          iv: SM4_IV,
          output: 'array',
        }),
    );

    bench('CTR encrypt / 本库', () => void cryptCTR(SM4_KEY, SM4_IV, MSG_1KB));
    bench(
      'CTR encrypt / Cubelrti',
      () => void cw.sm4(MSG_1KB, SM4_KEY, { mode: 'ctr', padding: 'none', iv: SM4_IV }, false),
    );

    bench('GCM encrypt / 本库', () => void encryptGCM(SM4_KEY, SM4_GCM_IV, MSG_1KB));
    bench(
      'GCM encrypt / Cubelrti',
      () =>
        void cw.sm4(
          MSG_1KB,
          SM4_KEY,
          { mode: 'gcm', iv: SM4_GCM_IV, aad: new Uint8Array(0) },
          false,
        ),
    );
    bench(
      'GCM encrypt / sm-crypto-v2',
      () =>
        void v2sm4.encrypt(MSG_1KB, SM4_KEY, {
          mode: 'gcm',
          iv: SM4_GCM_IV,
          output: 'array',
          outputTag: true,
        }),
    );
  });

  const realLog = console.log.bind(console);
  console.log = () => {};
  try {
    await run({ print: (s: string) => realLog(s) });
  } finally {
    console.log = realLog;
  }
}

await main();

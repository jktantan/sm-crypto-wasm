import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  encodeSm2PrivateKeyPem,
  encodeSm2PublicKeyPem,
  parseSm2PrivateKeyPem,
  parseSm2PublicKeyPem,
} from '@/pem';
import { InvalidKeyError } from '@/runtime';
import * as sm2 from '@/sm2';

/**
 * SM2 密钥交换的 PEM 输入路径。
 *
 * - 前半段（总是运行）：编码/解析 round-trip、用自产 PEM 跑完整交换、
 *   以及"PEM 输入与裸 hex 输入得到同一共享密钥"的等价性。
 * - 后半段（有 OpenSSL+SM2 时运行）：以 OpenSSL 生成的 PEM 为权威 oracle，
 *   校验 d/公钥解析一致，并用真实 PEM 跑协议。
 */

// 固定密钥（< n，非 0），保证 PEM 与 hex 两条路径可比。
const D_A = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const D_B = '7a3d1c2b9e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f';

/** 固定临时私钥，让两条路径的共享密钥可比。 */
const R_A = '0000000000000000000000000000000000000000000000000000000000000003';
const R_B = '0000000000000000000000000000000000000000000000000000000000000005';

/** 用给定私钥/公钥输入跑一遍完整协议，返回两端的共享密钥。 */
async function runExchange(
  privA: string | Uint8Array,
  pubB: string | Uint8Array,
  privB: string | Uint8Array,
  pubA: string | Uint8Array,
): Promise<{ kA: string; kB: string }> {
  const alice = await sm2.createExchangeInitiator(privA, pubB, {
    idSelf: 'Alice',
    idPeer: 'Bob',
    ephemeralPrivateKey: R_A,
  });
  const bob = await sm2.createExchangeResponder(privB, pubA, {
    idSelf: 'Bob',
    idPeer: 'Alice',
    ephemeralPrivateKey: R_B,
  });
  const m1 = alice.initiate();
  const m2 = bob.respond(m1);
  const m3 = alice.confirm(m2);
  return { kA: alice.getSharedKey(m3), kB: bob.getSharedKey(m3) };
}

describe('SM2 key exchange with PEM inputs', () => {
  beforeAll(async () => {
    await sm2.ensureLoaded();
  });

  it('round-trips SM2 PEM encode/parse', () => {
    const pubA = sm2.getPublicKey(D_A); // 64 字节 hex（x || y）
    const privPem = encodeSm2PrivateKeyPem(D_A, pubA);
    const pubPem = encodeSm2PublicKeyPem(pubA);

    expect(privPem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(pubPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(Buffer.from(parseSm2PrivateKeyPem(privPem)).toString('hex')).toBe(D_A);
    expect(Buffer.from(parseSm2PublicKeyPem(pubPem)).toString('hex')).toBe(`04${pubA}`);
  });

  it('completes a key exchange when given PEM keys', async () => {
    const pubA = sm2.getPublicKey(D_A);
    const pubB = sm2.getPublicKey(D_B);
    const { kA, kB } = await runExchange(
      encodeSm2PrivateKeyPem(D_A, pubA),
      encodeSm2PublicKeyPem(pubB),
      encodeSm2PrivateKeyPem(D_B, pubB),
      encodeSm2PublicKeyPem(pubA),
    );
    expect(kA).toBe(kB);
    expect(kA).toHaveLength(64);
  });

  it('yields the same shared key for PEM and raw-hex inputs', async () => {
    const pubA = sm2.getPublicKey(D_A);
    const pubB = sm2.getPublicKey(D_B);

    const viaHex = await runExchange(D_A, pubB, D_B, pubA);
    const viaPem = await runExchange(
      encodeSm2PrivateKeyPem(D_A, pubA),
      encodeSm2PublicKeyPem(pubB),
      encodeSm2PrivateKeyPem(D_B, pubB),
      encodeSm2PublicKeyPem(pubA),
    );

    expect(viaPem.kA).toBe(viaHex.kA);
    expect(viaPem.kB).toBe(viaHex.kB);
  });

  it('accepts 65-byte uncompressed public keys too', async () => {
    const pubA = sm2.getPublicKey(D_A); // 64 字节
    const pubB = sm2.getPublicKey(D_B);
    const { kA, kB } = await runExchange(D_A, `04${pubB}`, D_B, `04${pubA}`);
    expect(kA).toBe(kB);
  });

  it('rejects malformed PEM input', () => {
    // 合法 base64，但内容不是合法 DER。
    expect(() =>
      parseSm2PrivateKeyPem('-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n'),
    ).toThrow(InvalidKeyError);
    expect(() => parseSm2PublicKeyPem('not a pem at all')).toThrow(InvalidKeyError);
  });
});

// ---------- OpenSSL 权威 oracle ----------

function hasOpenSslSm2(): boolean {
  try {
    return /SM2/.test(execFileSync('openssl', ['ecparam', '-list_curves'], { encoding: 'utf8' }));
  } catch {
    return false;
  }
}

const describeMaybe = hasOpenSslSm2() ? describe : describe.skip;

interface OsslKey {
  privPem: string;
  pubPem: string;
  d: string;
  pub: string;
}

/** 用 OpenSSL 生成一对 SM2 密钥，并抽出 d / 未压缩公钥（65 字节 hex）。 */
function generateOsslKey(): OsslKey {
  const dir = mkdtempSync(join(tmpdir(), 'sm2-kex-pem-'));
  const privPath = join(dir, 'priv.pem');
  const pubPath = join(dir, 'pub.pem');
  execFileSync('openssl', ['genpkey', '-algorithm', 'SM2', '-out', privPath]);
  execFileSync('openssl', ['pkey', '-in', privPath, '-pubout', '-out', pubPath]);

  const privText = execFileSync('openssl', ['pkey', '-in', privPath, '-text', '-noout'], {
    encoding: 'utf8',
  });
  const d = privText
    .replace(/[\s\S]*?priv:/, '')
    .replace(/pub:[\s\S]*/, '')
    .replace(/[^0-9a-f]/gi, '')
    .toLowerCase();

  const pubText = execFileSync('openssl', ['pkey', '-in', privPath, '-pubout', '-text', '-noout'], {
    encoding: 'utf8',
  });
  const pub = pubText
    .replace(/[\s\S]*?pub:/, '')
    .replace(/ASN1[\s\S]*/, '')
    .replace(/[^0-9a-f]/gi, '')
    .toLowerCase();

  return { privPem: readFileSync(privPath, 'utf8'), pubPem: readFileSync(pubPath, 'utf8'), d, pub };
}

describeMaybe('SM2 PEM parsing vs OpenSSL (authoritative oracle)', () => {
  let A: OsslKey;
  let B: OsslKey;

  beforeAll(async () => {
    await sm2.ensureLoaded();
    A = generateOsslKey();
    B = generateOsslKey();
  }, 30_000);

  it('parses the private scalar and public point exactly as OpenSSL does', () => {
    expect(Buffer.from(parseSm2PrivateKeyPem(A.privPem)).toString('hex')).toBe(A.d);
    expect(`04${sm2.getPublicKey(A.d)}`).toBe(A.pub);
    expect(Buffer.from(parseSm2PublicKeyPem(A.pubPem)).toString('hex')).toBe(A.pub);
  });

  it('runs a full key exchange on OpenSSL-generated PEMs', async () => {
    const alice = await sm2.createExchangeInitiator(A.privPem, B.pubPem, {
      idSelf: 'Alice',
      idPeer: 'Bob',
    });
    const bob = await sm2.createExchangeResponder(B.privPem, A.pubPem, {
      idSelf: 'Bob',
      idPeer: 'Alice',
    });
    const m1 = alice.initiate();
    const m2 = bob.respond(m1);
    const m3 = alice.confirm(m2);
    const kA = alice.getSharedKey(m3);
    const kB = bob.getSharedKey(m3);
    expect(kA).toBe(kB);
    expect(kA).toHaveLength(64);
  });

  it('rejects a non-SM2 curve key', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sm2-bad-curve-'));
    const p256 = join(dir, 'p256.pem');
    execFileSync('openssl', [
      'genpkey',
      '-algorithm',
      'EC',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-out',
      p256,
    ]);
    expect(() => parseSm2PrivateKeyPem(readFileSync(p256, 'utf8'))).toThrow(InvalidKeyError);
  });
});

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import * as sm2 from '@/sm2';

/**
 * SM2 与 OpenSSL 的权威交叉验证。
 *
 * 用 OpenSSL CLI（3.x，支持 SM2）生成密钥、验签，作为**独立权威 oracle**；
 * gmkitx 只作二级参考。OpenSSL 的 SM2 签名必须走：
 *   openssl pkeyutl -rawin -digest sm3 -pkeyopt distid:<ID>
 * （`openssl dgst -sm3` 对 SM2 key 走的是纯 ECDSA，不含 Z 值，不能用）。
 *
 * 若环境无 openssl 或版本不支持 SM2，则整组跳过。
 */
function hasOpenSslSm2(): boolean {
  try {
    const out = execFileSync('openssl', ['ecparam', '-list_curves'], { encoding: 'utf8' });
    return /SM2/.test(out);
  } catch {
    return false;
  }
}

const SSL = hasOpenSslSm2();
const describeMaybe = SSL ? describe : describe.skip;

describeMaybe('SM2 vs OpenSSL (authoritative oracle)', () => {
  let dir = '';
  let privPem = '';
  let pubPem = '';
  let privHex = '';
  let pubHex = '';

  beforeAll(async () => {
    await sm2.ensureLoaded();
    dir = mkdtempSync(join(tmpdir(), 'sm2-ossl-'));
    privPem = join(dir, 'priv.pem');
    pubPem = join(dir, 'pub.pem');
    execFileSync('openssl', ['genpkey', '-algorithm', 'SM2', '-out', privPem]);
    execFileSync('openssl', ['pkey', '-in', privPem, '-pubout', '-out', pubPem]);
    const privText = execFileSync('openssl', ['pkey', '-in', privPem, '-text', '-noout'], {
      encoding: 'utf8',
    });
    const privBlock = privText.replace(/[\s\S]*?priv:/, '').replace(/pub:[\s\S]*/, '');
    privHex = privBlock.replace(/[^0-9a-f]/gi, '').toLowerCase();
    const pubText = execFileSync('openssl', ['pkey', '-pubin', '-in', pubPem, '-text', '-noout'], {
      encoding: 'utf8',
    });
    const pubBlock = pubText.replace(/[\s\S]*?pub:/, '').replace(/ASN1[\s\S]*/, '');
    pubHex = pubBlock.replace(/[^0-9a-f]/gi, '').toLowerCase();
    // 去掉 04 未压缩前缀。
    if (pubHex.startsWith('04')) pubHex = pubHex.slice(2);
  }, 30_000);

  it('public key derivation matches OpenSSL', () => {
    expect(sm2.getPublicKey(privHex)).toBe(pubHex);
  });

  it('our signature is accepted by OpenSSL pkeyutl -verify', () => {
    const msg = Buffer.from('openssl interop message', 'utf8');
    const msgPath = join(dir, 'message.bin');
    writeFileSync(msgPath, msg);
    const sig = sm2.sign(privHex, msg);
    const sigPath = join(dir, 'sig.der');
    writeFileSync(sigPath, rawToDer(sig));
    // 不抛异常即验证通过。
    const out = execFileSync(
      'openssl',
      [
        'pkeyutl',
        '-verify',
        '-rawin',
        '-digest',
        'sm3',
        '-pkeyopt',
        'distid:1234567812345678',
        '-pubin',
        '-inkey',
        pubPem,
        '-in',
        msgPath,
        '-sigfile',
        sigPath,
      ],
      { encoding: 'utf8' },
    );
    expect(out).toMatch(/Verified Successfully/i);
  });

  it('OpenSSL signature is accepted by our impl', () => {
    const msg = Buffer.from('verify ossl sig', 'utf8');
    const msgPath = join(dir, 'message2.bin');
    writeFileSync(msgPath, msg);
    const osslSigPath = join(dir, 'ossl-sig.der');
    execFileSync('openssl', [
      'pkeyutl',
      '-sign',
      '-rawin',
      '-digest',
      'sm3',
      '-pkeyopt',
      'distid:1234567812345678',
      '-inkey',
      privPem,
      '-in',
      msgPath,
      '-out',
      osslSigPath,
    ]);
    const der = readFileSync(osslSigPath);
    const sig = derToRaw(der);
    expect(sm2.verify(pubHex, msg, sig)).toBe(true);
  });
});

/** r||s（64 字节 hex）→ DER SEQUENCE{INTEGER r, INTEGER s}。 */
function rawToDer(sigHex: string): Buffer {
  const r = sigHex.slice(0, 64);
  const s = sigHex.slice(64, 128);
  const body = Buffer.concat([intDer(r), intDer(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function intDer(hex: string): Buffer {
  let b = Buffer.from(hex, 'hex');
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  if ((b[0] ?? 0) & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([Buffer.from([0x02, b.length]), b]);
}

/** DER SEQUENCE{INTEGER,INTEGER} → r||s（128 hex）。 */
function derToRaw(der: Buffer): string {
  let pos = 0;
  if (der[pos] !== 0x30) throw new Error('bad der');
  pos++;
  let len = der[pos++] ?? 0;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | (der[pos++] ?? 0);
  }
  const readInt = (): Buffer => {
    if (der[pos] !== 0x02) throw new Error('bad int');
    pos++;
    const l = der[pos++] ?? 0;
    const v = der.subarray(pos, pos + l);
    pos += l;
    return v;
  };
  const r = readInt();
  const s = readInt();
  return hex32(r) + hex32(s);
}

function hex32(v: Buffer): string {
  let b = Buffer.from(v);
  while (b.length > 32 && b[0] === 0) b = b.subarray(1);
  return b.toString('hex').padStart(64, '0');
}

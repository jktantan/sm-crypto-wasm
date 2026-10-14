/**
 * SM4 基准。
 *
 * 覆盖：ECB / CBC / CTR / GCM 四种典型模式；
 * 短/中两档输入（16 字节与 1KB），命中"分块一次"与"多块循环"两套路径。
 */
import { bench, group } from 'mitata';
import { encryptECB, encryptCBC, cryptCTR, encryptGCM, ensureLoaded } from '../src/sm4/index.js';

const KEY = new Uint8Array(16).fill(0x11);
const IV = new Uint8Array(16).fill(0x22);
const GCM_IV = new Uint8Array(12).fill(0x33);

const SIZES: Array<[string, Uint8Array]> = [
  ['16B', new Uint8Array(16).fill(0x01)],
  ['1KB', new Uint8Array(1024).fill(0x02)],
];
const SIZES_NO_16B = SIZES.slice(1);

export async function benchSm4(): Promise<void> {
  await ensureLoaded();
  for (const [, msg] of SIZES) encryptECB(KEY, msg);
  encryptGCM(KEY, GCM_IV, SIZES_NO_16B[0][1]);
  group('SM4', () => {
    for (const [label, msg] of SIZES) {
      bench(`ECB encrypt ${label}`, () => {
        encryptECB(KEY, msg);
      });
    }
    for (const [label, msg] of SIZES_NO_16B) {
      bench(`CBC encrypt ${label}`, () => {
        encryptCBC(KEY, IV, msg);
      });
      bench(`CTR encrypt ${label}`, () => {
        cryptCTR(KEY, IV, msg);
      });
      bench(`GCM encrypt ${label}`, () => {
        encryptGCM(KEY, GCM_IV, msg);
      });
    }
  });
}

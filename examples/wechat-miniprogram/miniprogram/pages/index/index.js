import * as sm2 from '../../vendor/sm-crypto-wasm/dist/sm2/index.js';
import * as sm3 from '../../vendor/sm-crypto-wasm/dist/sm3/index.js';
import * as sm4 from '../../vendor/sm-crypto-wasm/dist/sm4/index.js';
import * as sm9 from '../../vendor/sm-crypto-wasm/dist/sm9/index.js';
import * as zuc from '../../vendor/sm-crypto-wasm/dist/zuc/index.js';
import { bytesToHex } from '../../vendor/sm-crypto-wasm/dist/runtime/convert.js';
import { primeRandom } from '../../vendor/sm-crypto-wasm/dist/runtime/random.js';

const SM3_ABC = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';

// ZUC 的复用保护是模块级状态：同一个 (key, iv, counter) 只能加密一次。
// 页面重复运行时换一个 counter，避免测试本身触发保护。
let zucCounter = Date.now() % 0x7fffffff;

Page({
  data: {
    lines: [],
    running: false,
    summary: '',
  },

  onLoad() {
    this.run();
  },

  async run() {
    if (this.data.running) return;
    const started = Date.now();
    const lines = [];
    this.setData({ lines: [], running: true, summary: '测试中…' });

    const log = (ok, name, detail = '') => {
      const line = `${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  ${detail}` : ''}`;
      lines.push(line);
      this.setData({ lines });
      console.log('[sm-crypto-wasm]', line);
    };
    const fail = (name, e) => log(false, name, (e && e.message) || String(e));

    try {
      await sm3.ensureLoaded();
      const h = sm3.hash('616263');
      log(h === SM3_ABC, 'SM3 hash', h);
    } catch (e) {
      fail('SM3', e);
    }

    try {
      await sm4.ensureLoaded();
      const key = '0123456789abcdeffedcba9876543210';
      const iv = '000102030405060708090a0b0c0d0e0f';
      const ct = sm4.encryptCBC(key, iv, '616263');
      log(sm4.decryptCBC(key, iv, ct) === '616263', 'SM4 CBC 往返');
      const gcm = sm4.encryptGCM(key, iv, '616263', 'aabbccdd');
      log(sm4.decryptGCM(key, iv, gcm.ct, gcm.tag, 'aabbccdd') === '616263', 'SM4 GCM 往返');
    } catch (e) {
      fail('SM4', e);
    }

    try {
      await zuc.ensureLoaded();
      const key = '000102030405060708090a0b0c0d0e0f';
      const iv = '00000000000000000000000000000000';
      const counter = zucCounter++;
      const ct = zuc.zucEncrypt(key, iv, '616263', counter);
      log(
        bytesToHex(zuc.zucDecrypt(key, iv, ct, counter)) === '616263',
        'ZUC 往返',
        `counter=${counter}`,
      );
    } catch (e) {
      fail('ZUC', e);
    }

    try {
      await sm2.ensureLoaded();
      // 关键：wx.getRandomValues 是异步的，先把它填进同步随机数池。
      await primeRandom(65536);
      const kp = await sm2.generateKeyPair();
      const sig = sm2.sign(kp.privateKeyPem, '616263');
      log(sm2.verify(kp.publicKeyPem, '616263', sig), 'SM2 签名/验签');
      const ct = sm2.encrypt(kp.publicKeyPem, '616263');
      log(sm2.decrypt(kp.privateKeyPem, ct) === '616263', 'SM2 加解密');
    } catch (e) {
      fail('SM2', e);
    }

    try {
      await sm9.ensureLoaded();
      const kp = await sm9.generateKeyPair({ id: 'alice@foo.com' });
      const sig = sm9.sign(kp.masterPrivatePem, 'alice@foo.com', '616263');
      log(sm9.verify(kp.masterPublicPem, 'alice@foo.com', '616263', sig), 'SM9 签名/验签');
    } catch (e) {
      fail('SM9', e);
    }

    const failed = lines.filter((line) => line.startsWith('FAIL')).length;
    this.setData({
      running: false,
      summary:
        failed === 0
          ? `全部通过（${lines.length} 项，${Date.now() - started} ms）`
          : `${failed} 项失败`,
    });
  },
});

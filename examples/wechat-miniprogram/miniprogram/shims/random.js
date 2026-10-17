/**
 * 微信小程序版随机数（prepare 脚本会覆盖 dist/runtime/random.js）。
 *
 * 小程序没有 globalThis.crypto，只有基础库 2.15.0+ 的 wx.getRandomValues。
 * 它是**异步回调**，而本库的 randomBytes/randomScalarBelow 是同步 API，
 * 因此启动时先预取一块 CSPRNG 缓冲，业务调用从缓冲里同步取用。
 *
 * 安全姿态不变：缓冲耗尽时抛错，绝不回退到 Math.random。
 */

let pool = new Uint8Array(0);
let offset = 0;

/**
 * 预取随机数。必须在调用 SM2/SM9 的密钥生成、签名前 await 一次。
 * @param {number} length 预取字节数，默认 64 KiB（wx.getRandomValues 上限 1 MiB）。
 */
export function primeRandom(length = 65536) {
  return new Promise((resolve, reject) => {
    if (typeof wx === 'undefined' || typeof wx.getRandomValues !== 'function') {
      reject(new Error('wx.getRandomValues 不可用：请把基础库升到 2.15.0+'));
      return;
    }
    wx.getRandomValues({
      length,
      success: (res) => {
        pool = new Uint8Array(res.randomValues);
        offset = 0;
        resolve();
      },
      fail: reject,
    });
  });
}

export function randomBytes(n) {
  if (!Number.isInteger(n) || n < 0 || n > 65536) {
    throw new RangeError(`randomBytes: length must be integer in [0, 65536], got ${n}`);
  }
  if (n > pool.length - offset) {
    throw new Error('随机数池不足：请先 await primeRandom()，或增大预取字节数');
  }
  const out = pool.slice(offset, offset + n);
  offset += n;
  return out;
}

export function randomScalarBelow(order) {
  if (order <= 1n) throw new RangeError('randomScalarBelow: order must be > 1');
  for (;;) {
    const buf = randomBytes(32);
    let candidate = 0n;
    for (let i = 0; i < 32; i++) {
      candidate = (candidate << 8n) | BigInt(buf[i] ?? 0);
    }
    if (candidate > 0n && candidate < order) return candidate;
  }
}

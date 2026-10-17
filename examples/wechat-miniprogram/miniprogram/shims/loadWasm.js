/**
 * 微信小程序版 wasm 加载器（prepare 脚本会覆盖 dist/runtime/loadWasm.js）。
 *
 * 与浏览器版的区别：
 * - 小程序没有 fetch / WebAssembly.Module，只有基础库 2.13.0+ 的 WXWebAssembly；
 * - WXWebAssembly.instantiate 只接受**代码包内路径**（/ 开头，相对小程序根目录）。
 *
 * 保持 ESM，与 dist 其他文件一致。
 */

const WASM_PATHS = {
  sm2: '/vendor/sm-crypto-wasm/dist/sm2/sm2.wasm',
  sm3: '/vendor/sm-crypto-wasm/dist/sm3/sm3.wasm',
  sm4: '/vendor/sm-crypto-wasm/dist/sm4/sm4.wasm',
  sm9: '/vendor/sm-crypto-wasm/dist/sm9/sm9.wasm',
  zuc: '/vendor/sm-crypto-wasm/dist/zuc/zuc.wasm',
};

const ENV = {
  env: {
    abort() {
      throw new Error('wasm: abort');
    },
    trace() {},
    __assert_fail() {
      throw new Error('wasm: assert_fail');
    },
  },
};

const cache = new Map();

export function loadWasm(name) {
  const path = WASM_PATHS[name];
  if (!path) return Promise.reject(new RangeError(`loadWasm: unknown algo ${String(name)}`));

  let p = cache.get(name);
  if (!p) {
    p = (async () => {
      if (typeof WXWebAssembly === 'undefined') {
        throw new Error('WXWebAssembly 不可用：请把调试基础库/微信版本升到 2.13.0+');
      }
      // 不同基础库/平台上返回值可能是 Instance，也可能是 { instance }，两种都兼容。
      const r = await WXWebAssembly.instantiate(path, ENV);
      const inst = r && r.instance ? r.instance : r;
      return Object.freeze({ exports: inst.exports, memory: inst.exports.memory });
    })();
    cache.set(name, p);
  }
  return p;
}

export function loadWasmSync() {
  throw new Error('loadWasmSync: 小程序里请先 await loadWasm(name)');
}

export function getCachedWasm(name) {
  return loadWasm(name);
}

export function _resetCacheForTests() {
  cache.clear();
}

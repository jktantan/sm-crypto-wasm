# WeChat и мини-программы

`sm-crypto-wasm` работает в обеих средах WeChat, но подключается по-разному:

| Среда | Как подключать |
| --- | --- |
| **Встроенный браузер WeChat (H5)** | Как обычный браузер — через сборщик |
| **Мини-программа WeChat** | Нужен адаптер среды: `WXWebAssembly` + `wx.getRandomValues` |

## Встроенный браузер WeChat

Встроенный браузер WeChat — полноценный WebView: доступны `fetch`, `WebAssembly` и
`crypto.getRandomValues`. Используйте браузерную схему из
[сред выполнения](/ru/guide/cross-runtime):

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');
```

Замечания:

- Страница должна быть на **HTTPS** (или localhost), иначе `crypto.getRandomValues`
  недоступен. Библиотека в этом случае **бросает ошибку** (fail-closed) и не переходит на
  `Math.random`.
- Собирайте через Vite / Webpack / esbuild. Не подключайте `dist/*.js` напрямую через
  `<script type="module">`.

## Мини-программа WeChat

Мини-программа — другая среда выполнения. Браузерную точку входа нельзя использовать
напрямую:

- нет `fetch`, а `import.meta.url` не позволяет найти wasm-файлы;
- нет стандартного `WebAssembly`; базовая библиотека **2.13.0+** даёт `WXWebAssembly`;
- нет `globalThis.crypto`; базовая библиотека **2.15.0+** даёт `wx.getRandomValues`
  (асинхронный вызов);
- нет `btoa` / `atob` (в библиотеке есть встроенный JS-fallback); в старых базовых библиотеках также нет `TextEncoder` / `TextDecoder`.

### Быстрый старт

В репозитории есть минимальный проект, который можно сразу открыть в WeChat DevTools:

```bash
pnpm build
pnpm example:wechat:prepare
```

Затем импортируйте `examples/wechat-miniprogram` в WeChat DevTools и выберите базовую
библиотеку **2.15.0+**. Демо само проверяет SM2 / SM3 / SM4 / SM9 / ZUC и показывает
результаты на странице.

Оставьте только нужные алгоритмы (в нативных мини-программах нет tree-shaking):

```bash
pnpm example:wechat:prepare --algos sm3,sm4
```

Для `sm2` / `sm9` автоматически добавляются зависимости `sm4`, `pem` и `common`.

### Почему не «Сборка npm»

WeChat DevTools не учитывает поле `browser` из `package.json`: он подключает Node-версии
`loadWasm.js` (`node:fs`) и `random.js` (`node:crypto`), а браузерная версия с
`import.meta.url` падает с `Cannot use 'import.meta' outside a module`. Wasm-файлы при этом
не попадают в пакет кода.

Правильный путь: положить `dist/` в пакет мини-программы, загружать wasm через
`WXWebAssembly` и добавить три адаптера ниже. Скрипт `prepare` в примере делает это
автоматически.

### Адаптер 1: загрузка wasm

`WXWebAssembly.instantiate(path, imports)` принимает только **путь внутри пакета кода**
(начинается с `/`). Положите `dist/` в `miniprogram/vendor/sm-crypto-wasm/dist/` и
замените `dist/runtime/loadWasm.js` на:

```js
const WASM_PATHS = {
  sm2: '/vendor/sm-crypto-wasm/dist/sm2/sm2.wasm',
  sm3: '/vendor/sm-crypto-wasm/dist/sm3/sm3.wasm',
  sm4: '/vendor/sm-crypto-wasm/dist/sm4/sm4.wasm',
  sm9: '/vendor/sm-crypto-wasm/dist/sm9/sm9.wasm',
  zuc: '/vendor/sm-crypto-wasm/dist/zuc/zuc.wasm',
};

const ENV = {
  env: {
    abort() { throw new Error('wasm: abort'); },
    trace() {},
    __assert_fail() { throw new Error('wasm: assert_fail'); },
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
        throw new Error('WXWebAssembly требует базовую библиотеку 2.13.0+');
      }
      // Возврат может быть Instance или { instance } — поддерживаем оба варианта.
      const r = await WXWebAssembly.instantiate(path, ENV);
      const inst = r && r.instance ? r.instance : r;
      return Object.freeze({ exports: inst.exports, memory: inst.exports.memory });
    })();
    cache.set(name, p);
  }
  return p;
}

export function loadWasmSync() {
  throw new Error('loadWasmSync: в мини-программе сначала await loadWasm(name)');
}

export function getCachedWasm(name) { return loadWasm(name); }
export function _resetCacheForTests() { cache.clear(); }
```

### Адаптер 2: случайные числа

`wx.getRandomValues` асинхронен, а `randomBytes` / `randomScalarBelow` в библиотеке
синхронны. Поэтому при старте заранее забираем 64 KiB в пул и потом выдаём срезы
синхронно; при исчерпании пула бросаем ошибку (fail-closed):

```js
let pool = new Uint8Array(0);
let offset = 0;

export function primeRandom(length = 65536) {
  return new Promise((resolve, reject) => {
    if (typeof wx === 'undefined' || typeof wx.getRandomValues !== 'function') {
      reject(new Error('wx.getRandomValues требует базовую библиотеку 2.15.0+'));
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
    throw new Error('пул случайных чисел исчерпан: вызовите await primeRandom()');
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
    for (let i = 0; i < 32; i++) candidate = (candidate << 8n) | BigInt(buf[i] ?? 0);
    if (candidate > 0n && candidate < order) return candidate;
  }
}
```

> **Перед генерацией ключей и подписью SM2 / SM9 обязательно вызовите
> `await primeRandom()`.** SM3 / SM4 / ZUC случайные числа не нужны.

### Адаптер 3: кодировка текста

base64 **не требует** polyfill на стороне хоста: в `runtime/convert.ts` уже есть
встроенный JS-fallback (`Buffer` → `btoa`/`atob` → чистый JS), который автоматически
используется в мини-программах.

`TextEncoder` / `TextDecoder` всё ещё могут потребовать fallback (их используют SM9 и
обмен ключами SM2). Реализация из примера:
[`polyfills/textEncoding.js`](https://github.com/jktantan/sm-crypto-wasm/blob/main/examples/wechat-miniprogram/miniprogram/polyfills/textEncoding.js).
Подключите её в `app.js`:

```js
import './polyfills/textEncoding.js';
```

### Вызов библиотеки

```js
import * as sm3 from '../../vendor/sm-crypto-wasm/dist/sm3/index.js';
import * as sm2 from '../../vendor/sm-crypto-wasm/dist/sm2/index.js';
import { primeRandom } from '../../vendor/sm-crypto-wasm/dist/runtime/random.js';

export async function run() {
  await sm3.ensureLoaded();
  const digest = sm3.hash('616263');

  await sm2.ensureLoaded();
  await primeRandom(65536);           // заполняем синхронный пул
  const kp = await sm2.generateKeyPair();
  const sig = sm2.sign(kp.privateKeyPem, '616263');
  return { digest, verified: sm2.verify(kp.publicKeyPem, '616263', sig) };
}
```

Импортируйте по подпутям (`dist/sm3/index.js` и т.д.), а не через общий
`dist/index.js` — так неиспользуемые алгоритмы не попадут в граф JS-модулей.

### Размер пакета и обрезка

Нативные мини-программы **не делают tree-shaking**: все файлы под `miniprogramRoot`
попадают в пакет кода, а `import * as` не удаляет неиспользуемые экспорты. Полный
`vendor` примера занимает около **297 KB**; обрезка по алгоритмам даёт:

| Подготовка | Размер |
| --- | ---: |
| Все (по умолчанию) | ~297 KB |
| `--algos sm3` | ~33 KB |
| `--algos zuc` | ~38 KB |
| `--algos sm3,sm4` | ~59 KB |
| `--algos sm2` (добавляет sm4/pem/common) | ~160 KB |
| `--algos sm9` (добавляет sm4/pem/common) | ~195 KB |

Если используете Taro / uni-app / esbuild / Rollup / Webpack, сначала дайте сборщику
сделать настоящий ESM tree-shaking:

- **именованные импорты**, не namespace:
  ```ts
  import { hash } from 'sm-crypto-wasm/sm3';   // можно выбросить лишнее
  import * as sm3 from 'sm-crypto-wasm/sm3';   // неиспользуемые экспорты останутся
  ```
- в пакете указано `"sideEffects": false`;
- `.wasm` — отдельный бинарник, он **не участвует** в tree-shaking; копируйте только
  нужные алгоритмы;
- адаптеры `loadWasm` / `random` всё равно нужны на стороне мини-программы.

Другие способы: включить «сжатие кода» при загрузке, вынести редкие алгоритмы в отдельный
субпакет, использовать `.wasm.br` на базовой библиотеке 2.14+.

### Частые вопросы

- **`WXWebAssembly is not defined`**: базовая библиотека ниже 2.13.0.
- **`wx.getRandomValues is not defined`**: базовая библиотека ниже 2.15.0.
- **`TextEncoder is not defined`**: не подключён polyfill кодировки или не скопирован `app.js`.
- **Пул случайных чисел исчерпан**: вызовите `await primeRandom()` перед SM2 / SM9.
- **ZUC сообщает о повторном использовании**: одна и та же пара `(key, iv, counter)` может
  шифровать только один раз; увеличивайте counter или используйте новый IV.
- **В симуляторе нет WXWebAssembly**: используйте «Отладку на реальном устройстве» или
  «Предпросмотр».

Полный пример:
[`examples/wechat-miniprogram`](https://github.com/jktantan/sm-crypto-wasm/tree/main/examples/wechat-miniprogram).

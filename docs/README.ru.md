# sm-crypto-wasm

[简体中文](https://github.com/jktantan/sm-crypto-wasm/blob/main/README.md) · [English](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/README.en.md) · **Русский** · [Полная документация](https://jktantan.github.io/sm-crypto-wasm/ru/)

Реализация китайских криптографических стандартов (**SM2 / SM3 / SM4 / SM9 /
ZUC**) на **AssemblyScript → WebAssembly**. Работает на Node 18+ и в
современных браузерах (включая Web Workers). Алгоритмы разделены по
подпакетам и подгружаются лениво.

- **Производительность**: горячие пути (модульная арифметика больших чисел,
  сжатие хэша, раунды блочного шифра) выполняются в WASM. По сравнению с чистой
  JS-реализацией SM3 быстрее в 3.1\~3.5×, ZUC — в 2.3×, шесть режимов SM4 —
  в 3.6\~11.2×, SM2 — в 1.8\~7.6×; см. **Производительность** ниже;
- **Без инструментария**: на выходе `.wasm` плюс тонкая TS-прослойка;
  пользователю не нужны `node-gyp`, Rust или компилятор;
- **Кросс-рантайм**: один и тот же API работает в Node, браузере и
  Worker'е;
- **Соответствие стандартам**: реализации следуют серии GM/T 0003 / 0004 /
  0002 / 0044 / 0001 и сверяются с официальными векторами через
  OpenSSL / GmSSL / gmkitx.

---

## Производительность

Горячие пути (модульная арифметика больших чисел, сжатие хэша, раунды блочного
шифра, спаривания) выполняются внутри WASM. **Каждая операция, у которой есть
чистый JS-аналог, быстрее его**: SM3 — в 3.1–3.5×, ZUC — в 2.3×, шесть режимов
SM4 — в 3.6–11.2×, SM2 — в 1.8–7.6×.

Полная таблица по операциям, сравнение с `gmkitx` и разбор «почему именно так» —
на **[странице производительности](https://jktantan.github.io/sm-crypto-wasm/ru/performance)**.
Локально воспроизводится через `pnpm bench`.

## Установка

```bash
npm install sm-crypto-wasm
# либо: pnpm add sm-crypto-wasm / yarn add sm-crypto-wasm
```

Требуется Node **>= 18** (в браузере — поддержка WebAssembly и
`crypto.getRandomValues`).

---

## Быстрый старт

> **Перед первым использованием каждого алгоритма нужен
> `await algo.ensureLoaded()`** — инстанцирование WASM-модуля
> асинхронное; после него все рабочие функции синхронные. Загружаются
> только те `.wasm`, которые вы реально используете.

### SM3 — хеш и HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                          // '66c7f0f4…8f4ba8e0' — hex-строка декодируется побайтово
sm3.hash(new Uint8Array([0x61, 0x62, 0x63])); // тот же результат; байтовый ввод удобнее всего
sm3.hmac('00112233445566778899aabbccddeeff', '616263');
```

### SM4 — симметричное шифрование (ECB / CBC / CTR / CFB / OFB / GCM)

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key   = '0123456789abcdeffedcba9876543210';
const iv    = '000102030405060708090a0b0c0d0e0f';
const msg16 = '00112233445566778899aabbccddeeff';  // 16 байт
const aad   = 'aabbccdd';                          // дополнительные аутентифицируемые данные (hex)

sm4.encryptECB(key, msg16);                    // ECB без паддинга: ввод должен быть кратен 16 байтам
sm4.encryptCBC(key, iv, '616263');             // CBC с PKCS#7-паддингом; допустима любая длина
sm4.decryptCBC(key, iv, sm4.encryptCBC(key, iv, '616263'));
sm4.encryptCTR(key, iv, '616263');             // CTR/OFB — потоковые режимы (алиасы cryptCTR / cryptOFB)
const { ct, tag } = sm4.encryptGCM(key, iv, '616263', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);         // при ошибке аутентификации бросает DecryptionError; можно передать { safeMode: true }
```

### SM2 — генерация ключей / подпись / проверка / шифрование

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();  // async; возвращает PKCS#8 / SPKI PEM

const sig = sm2.sign(privateKeyPem, '616263');          // по умолчанию SM3withSM2; на выходе r||s в hex
sm2.verify(publicKeyPem, '616263', sig);                // → true

const ct  = sm2.encrypt(publicKeyPem, '616263');                  // по умолчанию C1C3C2
const ct2 = sm2.encrypt(publicKeyPem, '616263', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct);                         // на стороне расшифровки автоматически распознаётся C1C3C2 / C1C2C3
sm2.decrypt(privateKeyPem, ct, { safeMode: true });     // при ошибке возвращает null вместо исключения
```

Ключи также можно передавать как «сырой» hex или `Uint8Array` (32 байта для
закрытого ключа, 64 или 65 байт для открытого).

### SM2 — инкапсуляция ключа и гибридное шифрование

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();

// KEM: защитить случайный симметричный ключ открытым ключом (16 или 32 байта).
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);       // === key

// Гибридное шифрование: один вызов выполняет KEM + SM4-GCM; подходит для больших сообщений.
// Возвращает версионированный sealed: version || klen || encapLen || encapsulation || iv || tag || ct
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);               // → '616263' (открытый текст в hex)

// sealed можно представить в виде самоописывающего объекта.
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
```

- Каждый вызов `hybridEncrypt` создаёт новые 16-байтовый DEK и 12-байтовый IV; строки сообщений интерпретируются как **hex** (для пустого сообщения передайте `new Uint8Array(0)`).
- Гибридному режиму нужны и `sm2.wasm`, и `sm4.wasm`; перед первым вызовом выполните `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])`.
- `hybridDecrypt` поддерживает `{ safeMode: true }` и возвращает `null` при ошибках, связанных с шифртекстом.
- В SM2 нет стандартизованной конструкции KEM; `kemEncrypt` — общепринятый приём «зашифровать случайный ключ открытым ключом SM2».

### SM2 — протокол обмена ключами (GM/T 0003.3)

```ts
import { sm2 } from 'sm-crypto-wasm';

const A = await sm2.generateKeyPair();
const B = await sm2.generateKeyPair();

const alice = await sm2.createExchangeInitiator(A.privateKeyPem, B.publicKeyPem, {
  idSelf: 'Alice', idPeer: 'Bob',
});
const bob = await sm2.createExchangeResponder(B.privateKeyPem, A.publicKeyPem, {
  idSelf: 'Bob', idPeer: 'Alice',
});

const r1 = alice.initiate();      // инициатор → ответчик, первое сообщение
const r2 = bob.respond(r1);       // ответчик → инициатор, ответ
const r3 = alice.confirm(r2);     // подтверждение инициатора (содержит S_A для проверки ответчиком)

alice.getSharedKey(r3);           // обе стороны получают один и тот же общий секрет
bob.getSharedKey(r3);
```

### SM9 — подпись / шифрование / инкапсуляция ключей (GM/T 0044)

```ts
import { sm9 } from 'sm-crypto-wasm';

// В SM9 два мастер-ключа (различаются по purpose): мастер-ключ подписи
// использует мастер-публичный ключ в G2, мастер-ключ шифрования — в G1.
const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });                 // по умолчанию purpose: 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', '616263');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', '616263', sig);
// Первый аргумент verify / encrypt также принимает мастер-приватный ключ (для обратной совместимости).

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);      // → '616263'

// Инкапсуляция ключа (KEM): согласование симметричного ключа без передачи сообщения.
// Обратите внимание: первый аргумент — это *мастер-приватный ключ шифрования*
// (KEM нуждается в нём, чтобы вывести Ppub-e; для encrypt выше допустим мастер-публичный ключ).
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);  // === key

// Гибридное шифрование: инкапсулировать 16-байтовый DEK мастер-публичным (или приватным)
// ключом и id, затем зашифровать сообщение через SM4-GCM.
const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.hybridDecrypt(encKp.masterPrivatePem, 'alice@foo.com', sealed);  // → '616263'
```

> Гибридному режиму SM9 нужны и `sm9.wasm`, и `sm4.wasm`: перед первым вызовом выполните `await sm9.ensureLoaded()` и `await sm4.ensureLoaded()`.

### ZUC — конфиденциальность EEA3 и целостность EIA3

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

zuc.zucKeystream(key, iv, 16);                  // поток ключей (Uint8Array)
zuc.zucEncrypt(key, iv, '616263');              // EEA3 — каждая тройка (key, iv, counter) может шифроваться лишь единожды
zuc.zucDecrypt(key, iv, ct);                    // расшифровка (защита от повторного использования не действует)

// Тег целостности EIA3 (32 бита); IV собирается из COUNT / BEARER / DIRECTION
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
zuc.zucMac(key, macIv, '616263');               // → 4-байтовый тег
```

---

### X.509 · CMS · WebCrypto

```ts
import { x509, cms, webcrypto } from 'sm-crypto-wasm';

const cert = x509.parseCertificate(pem);
const signed = cms.signData({ data, privateKey, certificate: cert });
const digest = await webcrypto.subtle.digest('SM3', data);
```

- **X.509** — разбор, проверка одного сертификата, самоподпись / выпуск через простой CA ([документация](https://jktantan.github.io/sm-crypto-wasm/ru/guide/x509));
- **CMS** — detached / attached SignedData, проверка по исходным DER `signedAttrs`, BER ([документация](https://jktantan.github.io/sm-crypto-wasm/ru/guide/cms));
- **WebCrypto** — подмножество в стиле `subtle`: SM3 / HMAC(SM3) / SM2 / SM4 ([документация](https://jktantan.github.io/sm-crypto-wasm/ru/guide/webcrypto)).

Для X.509 / CMS нет проверки цепочки и CRL/OCSP; WebCrypto — не polyfill нативного `crypto.subtle`.

---

## Сводка API

В таблице перечислены основные API. Каждый модуль также экспортирует `ensureLoaded()`;
полный список см. в `dist/index.d.ts` или в `.d.ts` соответствующего подпути.

| Модуль | Функции |
|---|---|
| `sm2` | `generateKeyPair` (async) · `getPublicKey` · `sign` · `signWithID` · `verify` · `verifyWithID` · `encrypt` · `decrypt` · `configurePublicKeyCache` · `clearPublicKeyCache` · `preparePublicKey` (async) · `configurePreparedKeyCache` · `clearPreparedPublicKey` · `getPreparedPublicKey` · `clearPreparedPublicKeys` · `getPreparedPublicKeys` · `createSignaturePointPool` (async) · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `webcrypto` | `subtle` · `CryptoKey` |
| `cms` | `signData` · `verifySignedData` · `parseSignedData` · `CmsError` |
| `x509` | `parseCertificate` · `parseCertificates` · `createSelfSignedCertificate` · `issueCertificate` · `parseDistinguishedName` · `verifyCertificateSignature` |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB` / `decryptECB` · `encryptCBC` / `decryptCBC` · `encryptCTR` / `decryptCTR` · `encryptCFB` / `decryptCFB` · `encryptOFB` / `decryptOFB` · `encryptGCM` / `decryptGCM` |
| `sm9` | `generateKeyPair` (async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `zuc` | `zucKeystream` · `zucEncrypt` · `zucDecrypt` · `zucMac` · `zucEia3Iv` · `configureReuseGuard` · `resetReuseGuard` |

Документированные алиасы (указывают на ту же реализацию):
`sm4.encryptCTR` / `decryptCTR` — алиасы `cryptCTR`,
`encryptOFB` / `decryptOFB` — алиасы `cryptOFB`;
`zuc.encrypt` / `decrypt` / `generateKeystream` / `mac` / `eia3` — алиасы
`zucEncrypt` / `zucDecrypt` / `zucKeystream` / `zucMac`.

---

## Использование одного алгоритма (импорт по подпутям)

В сценариях, критичных к размеру, можно обойти агрегированную точку входа
и подгружать только нужный `.wasm`:

```ts
import { hash } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

Доступные подпути: `sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/x509` · `/cms` · `/webcrypto` · `/zuc`; также есть `sm-crypto-wasm/esbuild-plugin` (см. раздел о сборщиках ниже).

---

## Кросс-рантайм

| Среда | Путь загрузки |
|---|---|
| Node 18+ | читает `dist/<algo>/<algo>.wasm` через `fs/promises`; доступен `loadWasmSync()` |
| Браузер (через сборщик) | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`; сборщик кладёт файл в вывод и переписывает URL |
| Web Worker | загрузчик не зависит от DOM и работает внутри Worker'а |
| Deno / Bun | идут по Node-пути |
| Встроенный браузер WeChat | как обычный браузер (`fetch` + `crypto.getRandomValues`); см. [WeChat и мини-программы](https://jktantan.github.io/sm-crypto-wasm/ru/guide/wechat) |
| Мини-программа WeChat | `WXWebAssembly` + `wx.getRandomValues`; см. [WeChat и мини-программы](https://jktantan.github.io/sm-crypto-wasm/ru/guide/wechat) |

### Поддержка сборщиков

Пакет поставляет две реализации (Node-версия читает файлы, браузерная использует
`fetch`), а поле `browser` в `package.json` переключает их на этапе сборки. Поэтому
**`node:*` не попадает в браузерный бандл** — сборщики, которые не выносят встроенные
модули Node наружу (Webpack, esbuild, Rspack), больше не падают на этапе разбора
с `Can't resolve 'node:fs'`.

| Сборщик | Нужна настройка? | Ресурс wasm |
|---|---|---|
| **Vite 5** | нет | автоматически попадает в вывод (`assets/*.wasm`) |
| **Webpack 5** | нет | автоматически выдаётся как asset |
| **Rspack 2** | нет | выдаётся как asset (имена с hash) |
| **Turbopack** (по умолчанию в Next.js 16) | нет | попадает в `static/media/*.wasm` |
| **esbuild** | одна строка плагина (ниже) | esbuild не обрабатывает файлы, на которые указывает `new URL(..., import.meta.url)` |
| **Node 18+** | нет | читает `dist/<algo>/<algo>.wasm` |

Пользователи esbuild подключают небольшой встроенный плагин — он кладёт wasm туда,
откуда его берёт рантайм:

```ts
import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outdir: 'dist/assets',        // сюда попадает выходной JS
  plugins: [smCryptoWasm()],    // → wasm копируется в dist/<algo>/<algo>.wasm
});
```

Не хотите плагин? Скопируйте `node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc}`
в **родительский** каталог выходного JS (в примере выше — `dist/`).

Браузеру нужен **защищённый контекст** (`https://` или `localhost`) для
`crypto.getRandomValues`; если его нет, библиотека **бросает ошибку** (fail-closed), а не
откатывается к некриптографическому источнику.

Среды со строго потоковой загрузкой WASM, такие как Cloudflare Workers / Vercel Edge,
**вне области поддержки**; загрузка «сырого» ESM напрямую через `<script type="module">`
(без сборщика) — тоже.

---

## Обработка ошибок

Все ошибки вида «отклонено из-за ввода» — подклассы `SmCryptoError`, в двух
ветках:

```ts
import { SmCryptoError, InvalidKeyError, InvalidPublicKeyError,
         CiphertextError, InvalidCiphertextError, DecryptionError } from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (e instanceof DecryptionError) { /* шифртекст не соответствует ключу */ }
  else if (e instanceof CiphertextError) { /* проблема структуры или валидации */ }
  else if (e instanceof InvalidKeyError) { /* формат / длина / кривая ключа */ }
  else throw e;
}
```

- Ветка ключей: `InvalidKeyError` (с подклассом `InvalidPublicKeyError`);
- Ветка шифртекста: `CiphertextError` (с подклассом
  `InvalidCiphertextError` для структурных ошибок и `DecryptionError` —
  для ошибок валидации);
- Проблемы с типом или диапазоном (например, ограничения длины,
  недопустимые значения перечислений) сохраняют нативные `TypeError` /
  `RangeError` среды исполнения.

---

## Замечания по безопасности

- **Используется только ГПСЧ среды исполнения**: `crypto.getRandomValues`
  (браузеры / Node 19+) либо `node:crypto`-shim для Node 18. **Собственный
  ГПСЧ в библиотеке не реализован.**
- **Закрытые ключи не пишутся на диск и не журналируются**: библиотека
  не выполняет никакой сериализации ключей на диск и не пишет их в логи.
- **Защита от повторного использования ZUC**: повторное шифрование с той
  же тройкой `(key, iv, counter)` приводит к исключению (повторное
  использование потока ключей — инцидент конфиденциальности). Если
  счётчик ведётся внешне, защиту можно отключить глобально через
  `configureReuseGuard({ enabled: false })` либо разово передав
  `{ reuseGuard: false }`.
- **Корректность открытого ключа SM2**: `encrypt` бросает
  `InvalidPublicKeyError` для точек вне кривой; `verify` возвращает
  просто `false`.
- Нет интеграции с криптографическим оборудованием / HSM / PKCS#11 /
  программными сертификатами; форматы ключей за пределами PEM не
  разбираются.

---

## Разработка

```bash
pnpm install
pnpm build          # clean + asc (5 .wasm-файлов) + tsc → dist/ (без source map)
pnpm build:ts:debug # для отладки: пересборка TS в dist/ с .js.map / .d.ts.map
pnpm test           # сборка wasm + Node-тесты (vitest)
pnpm test:browser   # сборка wasm + браузерный раннер (happy-dom)
pnpm bench          # микро-бенчмарки mitata (5 блоков алгоритмов)
pnpm lint           # biome (lint + format)
pnpm typecheck      # tsc --noEmit
```

`pnpm build` — это путь релиза: он сначала очищает `dist/`, а `tsconfig.build.json` отключает
`sourceMap` / `declarationMap`, поэтому в артефактах нет ни `.map`, ни комментариев
`//# sourceMappingURL=`. Причина: в пакет попадает только `dist/`, а `sources` в map указывают
на `../src/*.ts`, которых в пакете нет (и `sourcesContent` не встроен) — потребитель не получит ни
исходников, ни перехода к определениям, но заплатит примерно +35% размера. Для отладки внутри
репозитория используйте `pnpm build:ts:debug` (`tsconfig.build.debug.json`) — он кладёт map в
`dist/`.

**Все wasm-модули собираются только с `--optimize`, без `--enable simd`**: скорость SM4
даёт скалярное чередование блоков, которое не зависит ни от какого набора SIMD-инструкций.
Поэтому все пять модулей предъявляют одинаковые требования к среде, и `sm4.wasm` больше
не требует **WASM SIMD**.

Файлы в `src/**/assembly/**` — это исходники AssemblyScript, компилируемые
`asc`. **Не используйте** в них `import { type X }` и не позволяйте
форматтеру переставлять импорты — `asc` 0.28 не понимает модификатор типа
(соответствующие правила уже отключены для этого каталога в конфиге
biome).

В каждом каталоге `src/*/assembly/` лежит одно-строчный `tsconfig.json`,
который лишь `extends` корневой `tsconfig.assembly.json`. Он подтягивает
определения типов AS **исключительно ради того, чтобы IDE проверяла эти
файлы по семантике AS** — иначе при редактировании появляется `TS2304`
для `usize`, `u32`, `StaticArray` и т. п. Корневой `tsconfig.json`
`exclude`ит этот каталог, поэтому CLI-`tsc` их не трогает; эти
конфигурации не влияют ни на сборку, ни на проверку типов.

---

## Участие в проекте

Issues и pull requests приветствуются. Настройка окружения, команды тестов и
требования к PR описаны в
[CONTRIBUTING.md](https://github.com/jktantan/sm-crypto-wasm/blob/main/CONTRIBUTING.md).
Об уязвимостях сообщайте через канал, указанный в
[SECURITY.md](https://github.com/jktantan/sm-crypto-wasm/blob/main/SECURITY.md).

Перед отправкой выполните:

```bash
pnpm lint && pnpm typecheck && pnpm test:unit
```

---

## Лицензия

[Apache-2.0](../LICENSE).

Реализации алгоритмов в этом проекте ссылаются на или портированы из
следующих проектов под Apache-2.0; сведения об авторстве — в
[`NOTICE`](../NOTICE):

- [GmSSL](https://github.com/guanzhi/GmSSL) — базовый источник семантики
  и наименований SM2 / SM9;
- [gmkit / gmkitx](https://github.com/gmkits/gmkit) — источник, из
  которого портирована реализация ZUC.


# Установка и быстрый старт

## Установка

```bash
pnpm add sm-crypto-wasm
# или
npm i sm-crypto-wasm
# или
yarn add sm-crypto-wasm
```

Требуется **Node >= 18**; браузерам нужны WebAssembly и `crypto.getRandomValues`.
Пакет содержит `.wasm` и тонкую прослойку на TS — **без `node-gyp`, Rust и компилятора**.

## Асинхронная граница: сначала `ensureLoaded()`

Каждый алгоритм — своё пространство имён с **`ensureLoaded()`**:

```ts
import { sm3, sm4 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();   // прогрев перед первым использованием
sm3.hash('616263');         // дальше все вызовы синхронные
```

Создание экземпляра WASM асинхронно, всё после него — синхронно. Поскольку wasm **разбит по
алгоритмам**, `sm4.wasm` скачивается только при `await sm4.ensureLoaded()`; неиспользуемые
алгоритмы ничего не стоят.

Повторные вызовы `ensureLoaded()` дешёвы: мемоизация на уровне модуля, конкурентные вызовы
разделяют один Promise.

## Пять алгоритмов

### SM3 — хеш и HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                                     // 32-байтный хеш в hex
sm3.hash(new TextEncoder().encode('abc'));              // то же, текст через явный UTF-8
sm3.hmac('00112233445566778899aabbccddeeff', '616263'); // HMAC-SM3
```

### SM4 — симметричное шифрование

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key = '0123456789abcdeffedcba9876543210';
const iv  = '000102030405060708090a0b0c0d0e0f';

sm4.encryptCBC(key, iv, 'hello');                        // выравнивание PKCS#7, любая длина
const { ct, tag } = sm4.encryptGCM(key, iv, 'hello', 'aad');
sm4.decryptGCM(key, iv, ct, tag, 'aad');                 // при подмене — DecryptionError
```

### SM2 — подпись и шифрование

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

const sig = sm2.sign(privateKeyPem, 'abc');              // SM3withSM2
sm2.verify(publicKeyPem, 'abc', sig);                    // → true

const ct = sm2.encrypt(publicKeyPem, 'abc');             // по умолчанию C1C3C2
sm2.decrypt(privateKeyPem, ct);                          // порядок определяется автоматически
```

### SM9 — идентификационная криптография

```ts
import { sm9 } from 'sm-crypto-wasm';

const id = 'alice@example.com';
const signKp = await sm9.generateKeyPair({ id });            // purpose по умолчанию 'sign'
const encKp  = await sm9.generateKeyPair({ id, purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, id, 'abc');
sm9.verify(signKp.masterPublicPem, id, 'abc', sig);

const ct = sm9.encrypt(encKp.masterPublicPem, id, 'abc');
sm9.decrypt(encKp.masterPrivatePem, id, ct);
```

### ZUC — EEA3 / EIA3

```ts
import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

const ct = zuc.zucEncrypt(key, iv, 'abc', 0);            // возвращает Uint8Array
zuc.zucDecrypt(key, iv, ct, 0);

const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
bytesToHex(zuc.zucMac(key, macIv, 'abc'));               // тег из 4 байт
```

## Соглашения о вводе и выводе

| Направление | Соглашение |
| --- | --- |
| Ввод-строка | Определяется в порядке **PEM → hex → base64**; `Uint8Array` используется как есть |
| Вывод (SM2 / SM3 / SM4 / SM9) | **hex** в нижнем регистре |
| Вывод (ZUC) | **`Uint8Array`** (четыре основные функции ZUC) |
| Ключи | Строки распознаются; **«текстового UTF-8 ключа» не существует** |

## Дальше

- Важен размер бандла? См. [**Один алгоритм**](/ru/guide/subpath-imports).
- Браузеры и Worker'ы? См. [**Среды выполнения**](/ru/guide/cross-runtime).
- Поймали исключение? См. [**Обработка ошибок**](/ru/guide/error-handling).

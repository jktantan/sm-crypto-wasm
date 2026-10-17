# SM9 — идентификационная криптография

SM9 — идентификационная криптосистема на билинейных спариваниях (**серия GM/T 0044-2016**).
Её отличительная черта: **идентификатор пользователя (например, email) *и есть* открытый
ключ**, поэтому цепочки сертификатов нет — центр генерации ключей (KGC) выводит приватный
ключ каждой идентичности из главного секрета.

| Возможность | Стандарт | Точки входа |
| --- | --- | --- |
| Цифровая подпись | GM/T 0044.2 | `sign` / `verify` |
| Обмен ключами | GM/T 0044.3 | `createExchangeInitiator` / `createExchangeResponder` |
| KEM, шифрование и гибридное шифрование | GM/T 0044.4 | `encrypt` / `decrypt`, `kemEncrypt` / `kemDecrypt`, `hybridEncrypt` / `hybridDecrypt` |

::: warning Два главных ключа не взаимозаменяемы
Подпись и шифрование используют **независимые** главные ключи (`purpose: 'sign' | 'enc'`):
главный открытый ключ подписи — точка **G2** (128 байт), шифрования — точка **G1** (64 байта).
Использование не того назначения ломает проверку длины или спаривание.
:::

Главные приватные ключи, главные открытые ключи и пользовательские приватные ключи кодируются
в PEM по **PKCS#8 с собственным OID `1.2.156.10197.1.100`**.

## Импорт

```ts
import { sm9 } from 'sm-crypto-wasm';

await sm9.ensureLoaded();
```

## API

### `sm9.generateKeyPair(opts)`

```ts
function generateKeyPair(opts: {
  id: string | Uint8Array;          // идентификатор пользователя
  purpose?: 'sign' | 'enc';          // по умолчанию 'sign'
}): Promise<Sm9KeyPair>
```

Возвращаются четыре части материала:

| Поле | Назначение | Форма |
| --- | --- | --- |
| `masterPrivatePem` | главный приватный ключ (подпись `ks` / шифрование `ke`) | PKCS#8 PEM (скаляр 32 байта) |
| `masterPublicPem` | главный открытый ключ (подпись `[ks]P2` / шифрование `[ke]P1`) | SPKI PEM (G2 128B / G1 64B) |
| `userPrivatePem` | приватный ключ пользователя (`ds` G1 64B / `de` G2 128B) | PKCS#8 PEM |
| `userPublicPem` | открытый ключ пользователя `Q = [H1(id,hid)]P + Ppub` | SPKI PEM |

`userPublicPem` — **детерминированная функция** от `(id, главный открытый ключ)`, а не
независимый секрет: третья сторона может пересчитать его через `getUserPublicKey`.

### Вывод открытых ключей

| Функция | Сигнатура | Возвращает |
| --- | --- | --- |
| `getSignPublicKey` | `(ks: string \| Uint8Array) => string` | 128 байт в hex (G2, аффинные) |
| `getEncPublicKey` | `(ke: string \| Uint8Array) => string` | 64 байта в hex (G1, аффинные) |
| `getUserPublicKey` | `(masterPublicKey, id) => string` | SPKI PEM |

Все три принимают главный приватный ключ как 32 сырых байта (hex / `Uint8Array` / PKCS#8 PEM).

### Подпись / проверка

```ts
function sign(ks, id, msg, r?): string      // → подпись 96 байт в hex (h‖Sx‖Sy, 192 символа)
function verify(publicKey, id, msg, sig): boolean
```

| Параметр | Описание |
| --- | --- |
| `ks` / `publicKey` | подпись принимает либо **главный приватный ключ 32 байта** (или PKCS#8 PEM), либо **главный открытый ключ подписи 128 байт** (или SPKI PEM) — различаются по длине |
| `id` | идентификатор пользователя (строка или `Uint8Array`) |
| `msg` | сообщение; строки кодируются в UTF-8 |
| `r` | необязательный одноразовый номер 32 байта (тестовая инъекция); иначе используется CSPRNG хоста |

### Шифрование / расшифрование

```ts
function encrypt(publicKey, id, msg, r?): string      // → шифротекст в hex (C1 65B ‖ C3 32B ‖ C2)
function decrypt(ke, id, ct, opts?: { safeMode?: boolean }): string
```

Первым аргументом `encrypt` может быть **главный приватный ключ шифрования 32 байта** или
**главный открытый ключ шифрования 64 байта** (SPKI PEM тоже подходит). `decrypt` требует
**главный приватный ключ шифрования** (или выведенный приватный ключ пользователя); неудачная
аутентификация бросает `DecryptionError` либо возвращает `null` при `{ safeMode: true }`.

### Инкапсуляция ключа (GM/T 0044.4)

```ts
function kemEncrypt(ke, id, klen = 32, r?): { key: string; encapsulation: string }
function kemDecrypt(ke, id, encapsulation, klen = 32): string
```

| Параметр | Описание |
| --- | --- |
| `ke` | **главный приватный ключ шифрования** — KEM нужен он для вывода `Ppub-e`, в отличие от `encrypt`, который принимает и открытый ключ |
| `id` | идентификатор получателя |
| `klen` | длина сессионного ключа в байтах, по умолчанию 32 |
| `encapsulation` | точка инкапсуляции 65 байт (`04 ‖ x ‖ y`) в hex |

### Гибридное шифрование (KEM + SM4-GCM)

```ts
function hybridEncrypt(
  key, id, msg, opts?: { iv?: string | Uint8Array },
): string
function hybridDecrypt(
  ke, id, sealed, opts?: { safeMode?: boolean },
): string
```

`key` может быть **64-байтовым главным открытым ключом шифрования** (SPKI PEM тоже
подходит) или **32-байтовым главным приватным ключом шифрования** (PKCS#8 PEM тоже
подходит) — отправителю обычно нужен только главный открытый ключ. Один вызов выполняет
KEM + SM4-GCM: KEM инкапсулирует 16-байтовый DEK, а сообщение обрабатывает SM4-GCM.

- `sealed` использует тот же версионированный формат, что и SM2 hybrid:
  `version(1) ‖ klen(1) ‖ encapLen(2) ‖ encapsulation ‖ iv(12) ‖ tag(16) ‖ ct`.
- Каждый вызов создаёт новые DEK и IV; строки `msg` интерпретируются как **hex**;
  для пустого сообщения передайте `new Uint8Array(0)`.
- В C1 у SM9 KEM нет C3/HMAC; целостность обеспечивает тег GCM. Неверный id /
  главный открытый ключ проявляется как `DecryptionError` в `hybridDecrypt`.
- AAD привязан к `encapsulation`; при `safeMode: true` ошибки со стороны шифротекста
  возвращают `null`.
- Гибридному режиму нужны и `sm9.wasm`, и `sm4.wasm`: перед первым вызовом выполните `await sm9.ensureLoaded()` и `await sm4.ensureLoaded()`.
- `sealedToObject` / `sealedFromObject` также доступны.

### Обмен ключами (GM/T 0044.3)

```ts
const initiator = await sm9.createExchangeInitiator(keSelf, idPeer, idSelf, opts?);
const responder = await sm9.createExchangeResponder(keSelf, idPeer, idSelf, opts?);

const m1 = initiator.initiate();          // фаза 1
const m2 = responder.respond(m1);         // фаза 2 (несёт confirm)
const m3 = initiator.confirm(m2);         // фаза 3
initiator.getSharedKey(m2, kLen?);        // обе стороны получают один сессионный ключ
responder.getSharedKey(m3, kLen?);
```

`options.kLen` задаёт длину сессионного ключа (по умолчанию 32); `options.ephemeral` —
**тестовая инъекция** одноразового приватного ключа.

## Использование

```ts
import { sm9 } from 'sm-crypto-wasm';

const id = 'alice@example.com';

// по одной главной ключевой паре на назначение
const signKp = await sm9.generateKeyPair({ id });                 // purpose по умолчанию 'sign'
const encKp  = await sm9.generateKeyPair({ id, purpose: 'enc' });

// подпись / проверка
const sig = sm9.sign(signKp.masterPrivatePem, id, 'abc');
sm9.verify(signKp.masterPublicPem, id, 'abc', sig);                // → true

// шифрование / расшифрование
const ct = sm9.encrypt(encKp.masterPublicPem, id, 'abc');
sm9.decrypt(encKp.masterPrivatePem, id, ct);                       // → '616263'

// KEM: договариваемся о симметричном ключе, сообщение не передаётся
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, id, 32);
sm9.kemDecrypt(encKp.masterPrivatePem, id, encapsulation, 32);     // === key
```

Гибридное шифрование (подходит для больших сообщений):

```ts
// Инкапсулировать 16-байтовый DEK главным открытым (или приватным) ключом + id,
// затем зашифровать сообщение через SM4-GCM.
const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, id, '616263');
sm9.hybridDecrypt(encKp.masterPrivatePem, id, sealed);             // → '616263'
```

## Playground

<Sm9Playground />

::: details Почему SM9 медленнее остальных
Доминируют спаривания: одна подпись — примерно 4 мс, проверка — около 8 мс, шифрование —
примерно 3,7 мс, на порядок больше SM2. Это математическая стоимость спариваний, а не
недостаток реализации — см. [страницу производительности](/ru/performance).
:::

## Ошибки и граничные случаи

| Ситуация | Бросается |
| --- | --- |
| `id` пустой в `generateKeyPair` / `getUserPublicKey` | `RangeError` |
| `purpose` не `'sign'` и не `'enc'` | `RangeError` |
| главный приватный ключ не 32 байта | `InvalidKeyError` |
| длина подписи не 96 байт | `InvalidCiphertextError` |
| шифротекст короче 97 байт | `InvalidCiphertextError` |
| проверка HMAC по C3 не прошла | `DecryptionError` |
| `encapsulation` в `kemDecrypt` не 65 байт | `RangeError` |
| `hybridDecrypt`: некорректная структура sealed | `InvalidCiphertextError` |
| `hybridDecrypt`: проверка тега GCM не прошла (включая неверный id / главный открытый ключ) | `DecryptionError` |
| `hybridEncrypt`: `iv` не 12 байт | `RangeError` |
| `klen` не положительное целое | `RangeError` |

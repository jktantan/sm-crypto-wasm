# SM2 — эллиптические кривые

SM2 — китайский национальный алгоритм на эллиптических кривых (**серия GM/T 0003-2012**),
кривая **`sm2p256v1`** (256-битное простое поле, `a = p - 3`). Библиотека покрывает
четыре части:

| Возможность | Стандарт | Точки входа |
| --- | --- | --- |
| Цифровая подпись | GM/T 0003.2 | `sign` / `verify` (по умолчанию **SM3withSM2**) |
| Шифрование открытым ключом | GM/T 0003.4 | `encrypt` / `decrypt` (шифротекст по умолчанию **C1C3C2**) |
| Инкапсуляция ключа / гибридное шифрование | — (соглашение) | `kemEncrypt` / `kemDecrypt`, `hybridEncrypt` / `hybridDecrypt` |
| Обмен ключами | GM/T 0003.3 | `createExchangeInitiator` / `createExchangeResponder` |
| Генерация ключей | — | `generateKeyPair` / `getPublicKey` |

::: tip Значения по умолчанию
Подпись всегда **SM3withSM2** с идентификатором пользователя `"1234567812345678"`
(идентификатор по умолчанию из GM/T 0003.2). Шифротекст по умолчанию собирается как
**C1C3C2**, а принимающая сторона **определяет порядок автоматически**.
:::

## Импорт

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();   // асинхронна только generateKeyPair
```

## Форматы ключей

Параметры ключей принимают три формы — используйте ту, что у вас уже есть:

| Форма | Приватный ключ | Открытый ключ |
| --- | --- | --- |
| сырые байты / hex | 32 байта | 64 байта `x‖y` или 65 байт с префиксом `04` |
| PEM | PKCS#8 (`PRIVATE KEY`), SEC1 (`EC PRIVATE KEY`) | SPKI (`PUBLIC KEY`) |
| `Uint8Array` | 32 байта | 64 / 65 байт |

Строки всегда распознаются по кодировке (`-----BEGIN` → PEM; hex чётной длины → hex;
иначе base64). **«Текстовой формы ключа в UTF-8» не существует.**

## API

### Генерация пары ключей `sm2.generateKeyPair()`

```ts
function generateKeyPair(): Promise<{ privateKeyPem: string; publicKeyPem: string }>
```

Асинхронно: создаёт экземпляр wasm и берёт приватный ключ `d` из CSPRNG хоста. Возвращает
**приватный ключ в PEM (PKCS#8)** и **открытый ключ в PEM (SPKI)**, которые читают
OpenSSL / GmSSL.

### Вывод открытого ключа `sm2.getPublicKey(privateKey)`

```ts
function getPublicKey(privateKey: string | Uint8Array): string
```

Выводит открытый ключ из приватного. **Возвращает** 128 hex-символов (64 байта `x‖y`).
Метод **всегда пересчитывает** (без кеша), сохраняя смысл операции «вывести открытый ключ».

### Подпись `sm2.sign(privateKey, message, opts?)`

```ts
function sign(
  privateKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { pointPool?: SignaturePoint[] },
): string
```

| Параметр | Тип | Обязателен | Описание |
| --- | --- | --- | --- |
| `privateKey` | `string \| Uint8Array` | да | 32 байта / PKCS#8 / SEC1 |
| `message` | `string \| Uint8Array` | да | подписываемое сообщение (строки трактуются как байты UTF-8) |
| `opts.pointPool` | `SignaturePoint[]` | нет | предвычисленные точки подписи; см. `createSignaturePointPool`. Расходуется на месте |

**Возвращает** 64-байтную подпись в hex (`r‖s`, 128 символов). Одноразовый `k` берётся
из CSPRNG хоста; ничтожная вероятность нулевых `r` или `s` вызывает повторный выбор
(до 16 попыток).

### Проверка подписи `sm2.verify(publicKey, message, signature)`

```ts
function verify(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  signature: string | Uint8Array,
): boolean
```

**Открытый ключ, не лежащий на кривой, просто возвращает `false`** (без исключения) — так
«плохой открытый ключ» не путается с «неверной подписью» через два разных пути исключений.
Подпись длиной не 64 байта бросает `InvalidCiphertextError`.

### Шифрование `sm2.encrypt(publicKey, message, opts?)`

```ts
function encrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { outputFormat?: 'C1C3C2' | 'C1C2C3' },
): string
```

**Возвращает** шифротекст в hex: `C1(65B) ‖ C3(32B) ‖ C2` по умолчанию, либо `C1 ‖ C2 ‖ C3`
при `outputFormat: 'C1C2C3'`. Открытый ключ не на кривой бросает `InvalidPublicKeyError`.

### Расшифрование `sm2.decrypt(privateKey, ciphertext, opts?)`

```ts
function decrypt(
  privateKey: string | Uint8Array,
  ciphertext: string | Uint8Array,
  opts?: { inputFormat?: 'C1C3C2' | 'C1C2C3' | 'auto'; safeMode?: boolean },
): string
```

| Опция | По умолчанию | Описание |
| --- | --- | --- |
| `inputFormat` | `'auto'` | `auto` сначала расшифровывает как C1C3C2, затем при неудаче проверки C3 пробует C1C2C3 |
| `safeMode` | `false` | при `true` ошибка со стороны шифротекста возвращает `null` вместо исключения |

`safeMode` глушит только ошибки **со стороны шифротекста**; ошибки типов аргументов
(`TypeError` / `RangeError`) всё равно бросаются.

### Инкапсуляция ключа `sm2.kemEncrypt(publicKey, klen = 32)` / `sm2.kemDecrypt(privateKey, encapsulation, klen = 32, opts?)`

```ts
function kemEncrypt(publicKey: string | Uint8Array, klen?: number):
  { key: string; encapsulation: string }
function kemDecrypt(
  privateKey: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen?: number,
  opts?: { safeMode?: boolean },
): string
```

**В SM2 нет стандартизованной отдельной конструкции KEM.** Здесь используется
общепринятый приём «зашифровать случайный симметричный ключ открытым ключом SM2».
`encapsulation` — полный шифротекст SM2 (C1C3C2, `97 + klen` байт) с собственной
проверкой C3; неверный приватный ключ или подмена данных бросает `DecryptionError`.
При `safeMode: true` возвращается `null`.

### Гибридное шифрование `sm2.hybridEncrypt(publicKey, message, opts?)` / `sm2.hybridDecrypt(privateKey, sealed, opts?)`

```ts
function hybridEncrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { iv?: string | Uint8Array },
): string
function hybridDecrypt(
  privateKey: string | Uint8Array,
  sealed: string | Uint8Array,
  opts?: { safeMode?: boolean },
): string
```

Один вызов выполняет **KEM + SM4-GCM**: открытый ключ защищает только 16-байтовый DEK,
а сообщение обрабатывает симметричный алгоритм. Это правильная форма для больших
сообщений — длинные данные не попадают в KDF / точечные операции SM2.

- Каждый вызов создаёт новые 16-байтовый DEK и 12-байтовый IV; `iv` предназначен только
  для тестов / совместимости протоколов — в обычном коде его не передавайте.
- Строки `message` интерпретируются как **hex**; для пустого сообщения передайте
  `new Uint8Array(0)`.
- Возвращаемый `sealed` версионирован:
  `version(1) ‖ klen(1) ‖ encapLen(2) ‖ encapsulation ‖ iv(12) ‖ tag(16) ‖ ct`.
- AAD привязан к `encapsulation`; подмена или неверный приватный ключ бросает
  `DecryptionError`.
- При `safeMode: true` ошибки со стороны шифротекста возвращают `null`.
- Гибридному режиму нужны и `sm2.wasm`, и `sm4.wasm`: перед первым вызовом выполните `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])`.

### Преобразование sealed в объект `sm2.sealedToObject(sealed)` / `sm2.sealedFromObject(obj)`

```ts
function sealedToObject(sealed: string | Uint8Array): {
  v: number; klen: number; encapsulation: string; iv: string; tag: string; ct: string;
}
function sealedFromObject(obj: SealedObject): string
```

Преобразует `sealed` между hex-строкой и самоописывающим объектом — удобно для отладки
или для совместимости с ручной сборкой `kemEncrypt` + `sm4.encryptGCM`.

### Кеш открытого ключа `sm2.configurePublicKeyCache(opts)` / `sm2.clearPublicKeyCache()`

```ts
function configurePublicKeyCache(opts: { enabled?: boolean; capacity?: number }): void
function clearPublicKeyCache(): void
```

`sign` при каждом вызове нужен открытый ключ для вычисления Z, а открытый ключ зависит
только от приватного. Кеш в памяти процесса **включён по умолчанию** (ключ — hex приватного
ключа, ёмкость 32, вытеснение FIFO); попадание избавляет от умножения на фиксированную
базовую точку — измерено 252 µs → 142 µs для `sign`.

**Компромисс**: кеш держит выведенные открытые ключи (и hex приватного ключа) в памяти
процесса. Если ваша модель угроз это запрещает, отключите его через
`configurePublicKeyCache({ enabled: false })` — вернётесь к пересчёту каждый раз.

### Пул точек подписи `sm2.createSignaturePointPool(n)`

```ts
class SignaturePoint {
  readonly point: string; // k·G в аффинных координатах x‖y (64 байта hex); публичные данные
}
async function createSignaturePointPool(n: number): Promise<SignaturePoint[]>
```

Предвычисляет `n` одноразовых точек подписи для опции `pointPool` у `sign`. Умножение на
базовую точку `k·G` занимает около **56%** времени одной подписи; если амортизировать его
заранее, на критическом пути остаются только `e = SM3(Z‖M)` и две модульные операции —
измерено **141 µs → 24 µs (в 5.9×)** на подпись. Это оправдано только при массовой подписи
(сервер, выдающий подписи подряд); для единичных подписей используйте обычный путь.

```ts
const pool = await sm2.createSignaturePointPool(10000);
for (const msg of messages) {
  const sig = sm2.sign(privateKey, msg, { pointPool: pool }); // каждая подпись берёт одну точку
}
```

**«Никогда не переиспользуйте `k`» обеспечено структурно — думать об этом не нужно.**
Одноразовый `k` хранится внутри библиотеки: он не раскрывается и не может быть скопирован
(в `SignaturePoint` есть только публичные координаты `k·G`), а `sign` сразу извлекает его из
индекса и затирает байты. Повторная передача той же точки **сразу выбрасывает ошибку**, а не
тихо переиспользует `k` — при переиспользовании в SM2 закрытый ключ раскрывается напрямую.
Поддельный `SignaturePoint` также бесполезен (его нет в индексе).

Когда пул исчерпан, `sign` автоматически возвращается к вычислению `k` на месте (подписи не
пропускаются и не портятся). `n` должно быть неотрицательным целым, иначе `RangeError`.

## Обмен ключами (GM/T 0003.3)

```ts
const alice = await sm2.createExchangeInitiator(privA, pubB, { idSelf: 'Alice', idPeer: 'Bob' });
const bob = await sm2.createExchangeResponder(privB, pubA, { idSelf: 'Bob', idPeer: 'Alice' });

const r1 = alice.initiate();     // фаза 1: инициатор → ответчик (RA)
const r2 = bob.respond(r1);      // фаза 2: ответчик → инициатор (RB + S_B)
const r3 = alice.confirm(r2);    // фаза 3: инициатор → ответчик (S_A)

const kA = alice.getSharedKey(r3);
const kB = bob.getSharedKey(r3);  // обе стороны получают один и тот же общий ключ
```

| Опция | По умолчанию | Описание |
| --- | --- | --- |
| `idSelf` | `"1234567812345678"` | идентификатор своей стороны |
| `idPeer` | `"1234567812345678"` | идентификатор партнёра |
| `ephemeralPrivateKey` | CSPRNG хоста | **только для тестовой инъекции**; в продакшене не передавайте |

| Метод | Возвращает | Примечание |
| --- | --- | --- |
| `initiator.initiate()` | `{ ephemeralPub }` | можно вызвать один раз |
| `initiator.confirm(r2)` | `{ confirm }` | **проверяет полученное S_B** и бросает исключение при неудаче |
| `initiator.getSharedKey(r3?, kLen?)` | hex | требует предшествующего `confirm()` |
| `responder.respond(r1)` | `{ ephemeralPub, confirm }` | можно вызвать один раз |
| `responder.getSharedKey(r3, kLen?)` | hex | проверяет S_A инициатора |

## Использование

```ts
import { sm2 } from 'sm-crypto-wasm';

// 1) генерация ключевой пары (PEM)
const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

// 2) подпись / проверка
const sig = sm2.sign(privateKeyPem, 'abc');
sm2.verify(publicKeyPem, 'abc', sig);                    // → true

// 3) шифрование / расшифрование
const ct = sm2.encrypt(publicKeyPem, 'abc');             // по умолчанию C1C3C2
sm2.decrypt(privateKeyPem, ct);                          // → '616263'

// обмен со старой системой, которая знает только C1C2C3
const ct2 = sm2.encrypt(publicKeyPem, 'abc', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct2, { inputFormat: 'C1C2C3' });
```

KEM и гибридное шифрование:

```ts
// 4) KEM: защитить случайный сессионный ключ открытым ключом
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);        // === key

// 5) Гибридное шифрование: один вызов выполняет KEM + SM4-GCM
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);                 // → '616263'

// sealed можно преобразовать в объект и обратно
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
```

Сырые hex-ключи работают так же:

```ts
const d = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const pub = sm2.getPublicKey(d);                          // 128 hex-символов
const sig = sm2.sign(d, 'abc');
sm2.verify(pub, 'abc', sig);
```

## Playground

<Sm2Playground />

## Ошибки и граничные случаи

| Ситуация | Бросается |
| --- | --- |
| приватный ключ не 32 байта | `InvalidKeyError` |
| открытый ключ не 64 / 65 байт | `InvalidKeyError` |
| открытый ключ в `encrypt` не на кривой | `InvalidPublicKeyError` |
| открытый ключ в `verify` не на кривой | исключения нет — **возвращается `false`** |
| длина подписи не 64 байта | `InvalidCiphertextError` |
| шифротекст короче 97 байт | `InvalidCiphertextError` |
| проверка C3 не прошла (несовпадение ключа / шифротекста) | `DecryptionError` |
| `kemDecrypt`: проверка C3 не прошла / неверный приватный ключ | `DecryptionError` |
| `hybridDecrypt`: некорректная структура sealed (версия / длина / обрезка) | `InvalidCiphertextError` |
| `hybridDecrypt`: проверка тега GCM не прошла | `DecryptionError` |
| `hybridEncrypt`: `iv` не 12 байт | `RangeError` |
| `kemEncrypt` / `kemDecrypt`: `klen` вне [1, 65536] | `RangeError` |
| неизвестное значение `outputFormat` / `inputFormat` | `RangeError` |
| `configurePublicKeyCache({ capacity: 0 })` | `RangeError` |

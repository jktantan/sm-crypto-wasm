# SM4 — блочный шифр

SM4 — китайский национальный блочный шифр (**GM/T 0002-2012**): **блок 128 бит**,
**ключ 128 бит**, 32 раунда. Раундовая функция работает в `sm4.wasm`; шесть режимов
(ECB / CBC / CTR / CFB / OFB / GCM) собираются на стороне TS из вызовов блочного уровня.

- Ключ всегда **16 байт**;
- Четыре блочных режима (ECB / CBC / CFB) принимают **16-байтный** IV; в GCM обычно 12 байт;
- Шифрование и расшифрование возвращают **hex-строки**.

## Импорт

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
```

## Как выбрать режим

| Режим | IV | Выравнивание | Распространение ошибок | Для чего |
| --- | --- | --- | --- | --- |
| ECB | нет | нет | — | **только тесты / совместимость**; одинаковые блоки открытого текста дают одинаковые блоки шифротекста |
| CBC | 16 B | PKCS#7 | повреждённый блок влияет на следующий | выбор по умолчанию для общего случая |
| CTR | 16 B | нет | нет | потоково, произвольный доступ; **никогда не повторяйте IV+counter** |
| CFB | 16 B | нет | влияет на последующие сегменты | самосинхронизирующийся поток |
| OFB | 16 B | нет | нет | когда важен характер распространения ошибок |
| GCM | обычно 12 B | нет | — | **рекомендуемый вариант с аутентификацией (AEAD)** |

::: tip Наша рекомендация по умолчанию
Нужны и конфиденциальность, и целостность → **GCM**. Только конфиденциальность и не хочется
управлять выравниванием → **CTR**. К ECB / CBC стоит прибегать лишь ради совместимости
формата со старыми системами.
:::

## API

Все функции принимают ключ как `string | Uint8Array`: строки распознаются как hex / base64
(**«текстового ключа в UTF-8» не существует** — ключи это байты). Все они возвращают hex
в нижнем регистре.

### Блочные режимы

| Функция | Сигнатура | Примечание |
| --- | --- | --- |
| `encryptECB` | `(key, msg) => string` | без выравнивания; длина `msg` должна быть **ненулевой кратной 16** |
| `decryptECB` | `(key, ct) => string` | то же ограничение |
| `encryptCBC` | `(key, iv, msg) => string` | выравнивание PKCS#7, любая длина (включая пустую) |
| `decryptCBC` | `(key, iv, ct) => string` | снимает выравнивание |
| `encryptCFB` | `(key, iv, msg) => string` | CFB128, обратная связь берётся из сегмента шифротекста |
| `decryptCFB` | `(key, iv, ct) => string` | |

### Потоковые режимы

| Функция | Сигнатура | Примечание |
| --- | --- | --- |
| `encryptCTR` / `decryptCTR` | `(key, iv, data) => string` | **одна и та же реализация** (псевдоним `cryptCTR`); XOR с потоком ключей, любая длина |
| `encryptOFB` / `decryptOFB` | `(key, iv, data) => string` | то же (псевдоним `cryptOFB`) |

CTR и OFB — инволюции: `decrypt(encrypt(x)) === x`, поэтому шифрование и расшифрование
имеют одну точку входа. Канонические имена в исходниках — `cryptCTR` / `cryptOFB`;
написания `encrypt*` / `decrypt*` — псевдонимы к тем же функциям.

### GCM (AEAD)

```ts
function encryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
  aad?: string | Uint8Array,
): { ct: string; tag: string }

function decryptGCM(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  ct: string | Uint8Array,
  tag: string | Uint8Array,
  aad?: string | Uint8Array | { aad?: string | Uint8Array; safeMode?: boolean },
): string
```

| Параметр | Тип | Обязателен | Описание |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | да | 16 байт |
| `iv` | `string \| Uint8Array` | да | не может быть пустым; 12-байтный IV используется напрямую как J0 по спецификации GCM |
| `msg` / `ct` | `string \| Uint8Array` | да | **может быть пустым** (пустой открытый текст допустим) |
| `tag` | `string \| Uint8Array` | при расшифровании | 16-байтный тег аутентификации |
| `aad` | `string \| Uint8Array` | нет | дополнительные аутентифицируемые данные: не шифруются, но аутентифицируются |

Пятый аргумент `decryptGCM` принимает либо `aad`, либо `{ aad, safeMode: true }` —
при `safeMode` неудачная аутентификация возвращает `null` вместо исключения `DecryptionError`.

## Использование

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();

const key = '0123456789abcdeffedcba9876543210';  // 16 байт
const iv  = '000102030405060708090a0b0c0d0e0f';  // 16 байт

// ECB: без выравнивания, длина кратна 16
sm4.encryptECB(key, '00112233445566778899aabbccddeeff');

// CBC: выравнивание PKCS#7, любая длина
const ct = sm4.encryptCBC(key, iv, 'hello');
sm4.decryptCBC(key, iv, ct);                     // → '68656c6c6f'

// CTR / OFB: инволюции
sm4.encryptCTR(key, iv, '616263');
sm4.decryptCTR(key, iv, sm4.encryptCTR(key, iv, '616263'));

// GCM: дополнительно выдаётся 16-байтный тег
const { ct: gcmCt, tag } = sm4.encryptGCM(key, iv, '616263', 'aabbccdd');
sm4.decryptGCM(key, iv, gcmCt, tag, 'aabbccdd');                          // вернёт текст только при успешной проверке
sm4.decryptGCM(key, iv, gcmCt, tag, { aad: 'aabbccdd', safeMode: true }); // → null при неудаче
```

## Playground

<Sm4Playground />

## Ошибки и граничные случаи

| Ситуация | Бросается |
| --- | --- |
| `key` не 16 байт | `InvalidKeyError` |
| `iv` в CBC / CFB / OFB не 16 байт | `InvalidKeyError` |
| `iv` в GCM пустой | `InvalidKeyError` |
| длина открытого текста в ECB не ненулевая кратная 16 | `RangeError` |
| длина шифротекста в ECB не ненулевая кратная 16 | `InvalidCiphertextError` |
| длина шифротекста в CBC не кратна 16 | `InvalidCiphertextError` |
| выравнивание PKCS#7 после расшифрования в CBC некорректно | `DecryptionError` |
| `tag` в GCM не 16 байт | `InvalidCiphertextError` |
| аутентификация GCM не прошла (изменён шифротекст / тег / AAD) | `DecryptionError` |

Аргументы, которые вообще не являются криптографическими объектами (неверные значения
перечислений и подобное), сохраняют нативные `TypeError` / `RangeError`.

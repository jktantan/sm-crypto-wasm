# ZUC — поточный шифр

ZUC — китайский национальный поточный шифр (**GM/T 0001-2012**, то есть **ZUC-128** из 3GPP
TS 35.221). Здесь покрыты два алгоритма:

| Возможность | Стандарт | Точки входа |
| --- | --- | --- |
| **EEA3** конфиденциальность | GM/T 0001.2-2012 | `zucEncrypt` / `zucDecrypt` / `zucKeystream` |
| **EIA3** целостность | GM/T 0001.3-2012 | `zucMac` / `zucEia3Iv` |

::: warning Только ZUC-128
ZUC-256 (GM/T 0001.1-2021) — другой алгоритм: его LFSR, инициализация и загрузка ключа не
являются параметризацией ZUC-128, и он **не реализован**. Поэтому `zucMac` принимает только
32-битные теги.
:::

::: danger Никогда не повторяйте поток ключей
Поток ключей, полученный для одной тройки `(key, iv, counter)` и применённый к двум
сообщениям, раскрывает их XOR — это провал конфиденциальности. Поэтому **путь шифрования
явно отказывает при повторе** (`InvalidKeyError`), а не пропускает его молча.
:::

## Импорт

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
```

::: tip Возвращаются байты, а не hex
Четыре основные функции ZUC возвращают **`Uint8Array`** (в отличие от SM2 / SM3 / SM4,
которые возвращают hex-строки). Для вывода используйте экспортируемый помощник `bytesToHex`.
:::

## API

### `zuc.zucKeystream(key, iv, nBytes)`

```ts
function zucKeystream(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  nBytes: number,
): Uint8Array
```

| Параметр | Тип | Обязателен | Описание |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | да | **16 байт** |
| `iv` | `string \| Uint8Array` | да | **16 байт** |
| `nBytes` | `number` | да | число выходных байт, неотрицательное целое |

Сам поток ключей защитой от повтора не покрывается — за его неповторяемость отвечаете вы.

### `zuc.zucEncrypt(key, iv, data, counter?, opts?)`

```ts
function zucEncrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  counter?: number,                       // по умолчанию 0
  opts?: { reuseGuard?: boolean },        // участвовать в защите от повтора, по умолчанию true
): Uint8Array
```

XOR данных с потоком ключей. **Второй вызов с той же тройкой `(key, iv, counter)` бросает
`InvalidKeyError`.** Если это действительно нужно (например, ключ/IV строго управляются внешним
счётчиком), передайте `{ reuseGuard: false }` или отключите глобально через
`configureReuseGuard({ enabled: false })`.

### `zuc.zucDecrypt(key, iv, data, counter?)`

```ts
function zucDecrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  counter?: number,
): Uint8Array
```

EEA3 — инволюция (тот же поток ключей XOR-ится снова). **Путь расшифрования освобождён от
защиты от повтора** — шифротекст может проверяться или воспроизводиться более одного раза.

### `zuc.zucMac(key, iv, msg, bitLengthOrOptions?, tagBits?)`

```ts
function zucMac(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  msg: string | Uint8Array,
  bitLengthOrOptions?: number | { bitLength?: number; tagBits?: number },
  tagBits?: number,
): Uint8Array
```

| Параметр | Тип | По умолчанию | Описание |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | — | ключ целостности 16 байт |
| `iv` | `string \| Uint8Array` | — | IV 16 байт (см. `zucEia3Iv`) |
| `msg` | `string \| Uint8Array` | — | защищаемое сообщение |
| `bitLength` | `number` | `msg.length * 8` | число **бит** сообщения, участвующих в вычислении (для сообщений, не кратных байту, задайте явно) |
| `tagBits` | `number` | `32` | поддерживается только 32 |

**Возвращает** тег из 4 байт (32 бита).

### `zuc.zucEia3Iv(count, bearer, direction)`

```ts
function zucEia3Iv(count: number, bearer: number, direction: number): Uint8Array
```

Собирает 16-байтный IV как `COUNT(32) ‖ BEARER(5) ‖ DIRECTION(1) ‖ 0(26)` по GM/T 0001.3 /
TS 35.221, что совпадает с `zuc_set_eia_iv` из GmSSL.

| Параметр | Диапазон |
| --- | --- |
| `count` | 32-битное беззнаковое целое |
| `bearer` | 0..31 |
| `direction` | 0 или 1 |

### Переключатели защиты от повтора

```ts
function configureReuseGuard(opts: { enabled?: boolean; capacity?: number }): void
function resetReuseGuard(): void
```

По умолчанию `{ enabled: true, capacity: 4096 }`: использованные тройки `(key, iv, counter)`
запоминаются, самая старая запись вытесняется по FIFO (**таблица обязана оставаться
ограниченной**, иначе долго живущий процесс будет расти без предела). `resetReuseGuard()`
очищает записи — только для тестов и осознанной ротации ключей.

## Использование

```ts
import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();

const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

// поток ключей
bytesToHex(zuc.zucKeystream(key, iv, 16));

// шифрование/расшифрование EEA3 (счётчик надо вести строго, чтобы не было повтора)
const ct = zuc.zucEncrypt(key, iv, 'abc', 0);
const pt = zuc.zucDecrypt(key, iv, ct, 0);

// тег целостности EIA3
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
bytesToHex(zuc.zucMac(key, macIv, 'abc'));          // → тег из 4 байт

// сообщения, не кратные байту: указываем длину в битах явно
zuc.zucMac(key, macIv, msg, { bitLength: 577 });
```

## Playground

<ZucPlayground />

## Ошибки и граничные случаи

| Ситуация | Бросается |
| --- | --- |
| `key` или `iv` не 16 байт | `InvalidKeyError` |
| тройка `(key, iv, counter)` в `zucEncrypt` уже использовалась | `InvalidKeyError` |
| `counter` в `zucEncrypt` не неотрицательное целое | `RangeError` |
| `nBytes` в `zucKeystream` не неотрицательное целое | `RangeError` |
| `tagBits` в `zucMac` не 32 | `RangeError` |
| `bitLength` в `zucMac` вне `[0, msg.length * 8]` | `RangeError` |
| `count` / `bearer` / `direction` в `zucEia3Iv` вне диапазона | `RangeError` |

Псевдонимы (указывают на те же реализации): `zuc.encrypt` = `zucEncrypt`,
`zuc.decrypt` = `zucDecrypt`, `zuc.generateKeystream` = `zucKeystream`,
`zuc.mac` = `zuc.eia3` = `zucMac`.

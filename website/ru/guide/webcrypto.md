# Адаптер WebCrypto

`sm-crypto-wasm/webcrypto` предоставляет **отдельный** объект `subtle` с той же
формой, что и `crypto.subtle`, но на алгоритмах SM2 / SM3 / SM4.

::: warning Это не polyfill
Браузеры не позволяют регистрировать собственные алгоритмы. Модуль **не**
подключается к нативному `crypto.subtle`, и сторонние библиотеки его не подхватят.
Импортируйте `sm-crypto-wasm/webcrypto` явно.
:::

```ts
import { subtle, CryptoKey } from 'sm-crypto-wasm/webcrypto';
```

Все методы асинхронные; нужный wasm-модуль загружается при первом вызове.

## Хеширование

```ts
const digest = await subtle.digest('SM3', data);
// ArrayBuffer(32)
```

## HMAC

```ts
const hmacKey = await subtle.importKey(
  'raw',
  keyBytes,
  { name: 'HMAC', hash: 'SM3' },
  true,
  ['sign', 'verify'],
);

const mac = await subtle.sign({ name: 'HMAC' }, hmacKey, data);
const ok = await subtle.verify({ name: 'HMAC' }, hmacKey, mac, data);
```

`generateKey({ name: 'HMAC', hash: 'SM3', length: 256 }, ...)` создаёт случайный
ключ (`length` в битах, кратно 8).

## SM2

```ts
const { privateKey, publicKey } = await subtle.generateKey(
  { name: 'SM2' },
  true,
  ['sign', 'verify'],
);

const signature = await subtle.sign({ name: 'SM2' }, privateKey, data); // 64 байта r‖s
const ok = await subtle.verify({ name: 'SM2' }, publicKey, signature, data);
```

- подпись — 64 байта `r ‖ s`, как у `sm2.sign`;
- идентификатор пользователя по умолчанию совпадает с `sm2.sign` / `sm2.verify`;
  переопределяется через `{ name: 'SM2', userID }`;
- форматы ключей: `pkcs8` (DER закрытого) и `spki` (DER открытого);
- `exportKey('pkcs8' | 'spki', ...)` можно передать бэкенду/HSM.

```ts
const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
const spki = await subtle.exportKey('spki', publicKey);

const imported = await subtle.importKey('spki', spki, { name: 'SM2' }, true, ['verify']);
```

## SM4

```ts
const key = await subtle.generateKey(
  { name: 'SM4-GCM', length: 128 },
  true,
  ['encrypt', 'decrypt'],
);

const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await subtle.encrypt(
  { name: 'SM4-GCM', iv, additionalData },
  key,
  plaintext,
);
const pt = await subtle.decrypt(
  { name: 'SM4-GCM', iv, additionalData },
  key,
  ct,
);
```

Поддержка: `SM4-ECB` · `SM4-CBC` · `SM4-CTR` · `SM4-CFB` · `SM4-OFB` · `SM4-GCM`.

| Алгоритм | Параметры | Примечание |
| --- | --- | --- |
| `SM4-ECB` | — | без дополнения; длина кратна 16 |
| `SM4-CBC` | `iv` | дополнение PKCS#7 |
| `SM4-CTR` | `iv`, `length` | `length` только 128 |
| `SM4-CFB` | `iv` | |
| `SM4-OFB` | `iv` | |
| `SM4-GCM` | `iv`, `additionalData?`, `tagLength?` | выдаёт `ciphertext ‖ tag`; `tagLength` только 128 |

Ключ SM4 всегда 128 бит; используйте
`importKey('raw', keyBytes, { name: 'SM4-*' }, ...)`.

## extractable / usages

- `exportKey` для неэкспортируемого ключа выбрасывает `InvalidAccessError`;
- если `usages` ключа не содержит операцию, выбрасывается `InvalidAccessError`;
- `generateKey` фильтрует usages SM2 по типу ключа:
  - закрытый ключ сохраняет `sign` / `decrypt`;
  - открытый — `verify` / `encrypt`.

## Отображение ошибок

| Ситуация | DOMException |
| --- | --- |
| неизвестный алгоритм / формат / параметр | `NotSupportedError` |
| нарушение usage или `extractable` | `InvalidAccessError` |
| некорректный ключ/данные | `DataError` |
| ошибка расшифрования/проверки | `OperationError` |

## Область

| Возможность | Статус |
| --- | --- |
| `SM3` digest | ✅ |
| `HMAC(SM3)` sign / verify | ✅ |
| `SM2` sign / verify, pkcs8/spki | ✅ |
| все шесть режимов SM4 | ✅ |
| `CryptoKey` / `extractable` / `usages` | ✅ |
| JWK | ❌ |
| `deriveKey` / `deriveBits` | ❌ |
| `wrapKey` / `unwrapKey` | ❌ |
| подключение к нативному `crypto.subtle` | ❌ (платформа не позволяет) |

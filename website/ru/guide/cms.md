# CMS SignedData

`sm-crypto-wasm/cms` предоставляет подпись и проверку CMS SignedData с SM2:

- режимы detached (по умолчанию) и attached;
- формирование атрибутов `contentType` / `messageDigest` / `signingTime`;
- проверка по **исходным DER-байтам** `signedAttrs`, без перекодирования;
- поддержка BER indefinite-length;
- структурированные причины ошибок.

Реализован только SignedData — без EnvelopedData и RFC 3161. Библиотека
**не строит цепочку доверия**; проверка срока действия, назначения и CRL/OCSP —
задача вызывающего кода.

## Подпись

```ts
import { cms, sm2, sm3 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();
await sm3.ensureLoaded();

const signed = cms.signData({
  data: 'сообщение',              // строки кодируются в UTF-8 (не hex/base64)
  privateKey: privateKeyPem,
  certificate: certificatePem,    // сертификат подписанта
  certificates: [caPem],          // необязательные сертификаты цепочки
  detached: true,                 // по умолчанию
  signingTime: new Date(),        // по умолчанию сейчас; false — не добавлять
});

signed.der;     // Uint8Array
signed.pem;     // -----BEGIN CMS-----
signed.base64;
```

Идентификатор подписанта — `issuerAndSerialNumber` из сертификата подписанта.

## Проверка

```ts
const result = cms.verifySignedData(signed.der, {
  detachedData: 'сообщение',
  certificates: [extraPem],       // необязательные дополнительные кандидаты
});

result.valid;                     // true, только если все подписанты валидны
result.signers[0]?.valid;
result.signers[0]?.certificate;
result.signers[0]?.signingTime;
result.signers[0]?.errorCode;
result.signers[0]?.error;
```

`errorCode`:

| Значение | Смысл |
| --- | --- |
| `NO_CERTIFICATE` | сертификат подписанта не встроен и не передан |
| `DIGEST_MISMATCH` | `messageDigest` / `contentType` не совпадает с содержимым |
| `SIGNATURE_INVALID` | некорректная подпись или ошибка проверки SM2 |
| `UNSUPPORTED_ALGORITHM` | алгоритм не SM3 / SM3withSM2 |
| `MALFORMED` | некорректный CMS или отсутствует `detachedData` |

Полностью неразбираемый вход возвращает результат `MALFORMED`, а не исключение;
ошибки окружения (незагруженный wasm) по-прежнему выбрасываются.

## Форматы входа

`verifySignedData` / `parseSignedData` принимают:

- PEM (`-----BEGIN CMS-----` или `-----BEGIN PKCS7-----`);
- base64 / hex;
- байты DER или BER.

## Идентификатор пользователя

По умолчанию CMS использует **пустой** идентификатор SM2, как и путь CMS в
OpenSSL. Для идентификатора GM/T:

```ts
import { DEFAULT_SM2_USER_ID } from 'sm-crypto-wasm/x509';

cms.signData({ data, privateKey, certificate, userID: DEFAULT_SM2_USER_ID });
cms.verifySignedData(der, { detachedData: data, userID: DEFAULT_SM2_USER_ID });
```

Если `userID` не указан при проверке, сначала пробуется пустой идентификатор,
затем идентификатор GM/T по умолчанию.

## Границы безопасности

- проверяется только соответствие подписи содержимому — **не доверие к
  сертификату**; цепочка, политики и срок действия проверяются вызывающим кодом;
- назначение сертификата не проверяется;
- `signData` не генерирует и не хранит закрытые ключи.

# WebCrypto adapter

`sm-crypto-wasm/webcrypto` exposes a **standalone** `subtle` object with the same
shape as `crypto.subtle`, backed by SM2 / SM3 / SM4.

::: warning Not a polyfill
Browsers do not allow registering custom algorithms. This module is **not**
attached to the native `crypto.subtle`, and third-party libraries will not pick
it up. Import `sm-crypto-wasm/webcrypto` explicitly.
:::

```ts
import { subtle, CryptoKey } from 'sm-crypto-wasm/webcrypto';
```

Every method is asynchronous; the corresponding wasm module is loaded on first use.

## Digest

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

`generateKey({ name: 'HMAC', hash: 'SM3', length: 256 }, ...)` generates a random
key (`length` in bits, a multiple of 8).

## SM2

```ts
const { privateKey, publicKey } = await subtle.generateKey(
  { name: 'SM2' },
  true,
  ['sign', 'verify'],
);

const signature = await subtle.sign({ name: 'SM2' }, privateKey, data); // 64-byte r‖s
const ok = await subtle.verify({ name: 'SM2' }, publicKey, signature, data);
```

- signatures are 64-byte `r ‖ s`, identical to `sm2.sign`;
- the default user id matches `sm2.sign` / `sm2.verify`; pass
  `{ name: 'SM2', userID }` to override;
- key formats: `pkcs8` (private DER) and `spki` (public DER);
- `exportKey('pkcs8' | 'spki', ...)` can be handed to a backend/HSM.

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

Supported: `SM4-ECB` · `SM4-CBC` · `SM4-CTR` · `SM4-CFB` · `SM4-OFB` · `SM4-GCM`.

| Algorithm | Parameters | Notes |
| --- | --- | --- |
| `SM4-ECB` | — | no padding; data length must be a multiple of 16 |
| `SM4-CBC` | `iv` | PKCS#7 padding |
| `SM4-CTR` | `iv`, `length` | `length` is 128 only |
| `SM4-CFB` | `iv` | |
| `SM4-OFB` | `iv` | |
| `SM4-GCM` | `iv`, `additionalData?`, `tagLength?` | emits `ciphertext ‖ tag`; `tagLength` is 128 only |

SM4 keys are always 128 bits; use
`importKey('raw', keyBytes, { name: 'SM4-*' }, ...)`.

## extractable / usages

- `exportKey` on a non-extractable key throws `InvalidAccessError`;
- a key whose `usages` do not include the requested operation throws
  `InvalidAccessError`;
- `generateKey` filters SM2 usages per key type:
  - private keys keep `sign` / `decrypt`;
  - public keys keep `verify` / `encrypt`.

## Error mapping

| Situation | DOMException |
| --- | --- |
| unknown algorithm / format / unsupported parameter | `NotSupportedError` |
| usage or `extractable` violation | `InvalidAccessError` |
| malformed key/data | `DataError` |
| decryption/verification failure | `OperationError` |

## Scope

| Capability | Status |
| --- | --- |
| `SM3` digest | ✅ |
| `HMAC(SM3)` sign / verify | ✅ |
| `SM2` sign / verify, pkcs8/spki | ✅ |
| all six SM4 modes | ✅ |
| `CryptoKey` / `extractable` / `usages` | ✅ |
| JWK | ❌ |
| `deriveKey` / `deriveBits` | ❌ |
| `wrapKey` / `unwrapKey` | ❌ |
| attaching to native `crypto.subtle` | ❌ (not allowed by platforms) |

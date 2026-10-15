# Error Handling

Everything rejected **because of its input** derives from `SmCryptoError`, split by the fix
you need to make — a key problem or a ciphertext problem:

```text
SmCryptoError
├── InvalidKeyError                bad key / scalar input
│   └── InvalidPublicKeyError      public key not on curve, coordinates out of range
└── CiphertextError                bad ciphertext / signature / protocol message
    ├── InvalidCiphertextError     malformed (length, ASN.1, point encoding)
    └── DecryptionError            well-formed but verification failed (C3 SM3 / GCM tag / C3 HMAC)
```

```ts
import { isSmCryptoError } from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (isSmCryptoError(e)) { /* the library rejected this input */ }
}
```

## Arguments of the wrong type are not wrapped

| Situation | Thrown |
| --- | --- |
| `null` / `number` / wrong shape | `TypeError` |
| Empty string input | `TypeError` |
| Length limit, negative counter, unknown enum value | `RangeError` |

These stay native — they are programming mistakes, not "cryptographic rejections".

## `safeMode`: get `null` instead of throwing

```ts
const pt  = sm2.decrypt(priv, ct, { safeMode: true });                          // string | null
const pt2 = sm4.decryptGCM(key, iv, ct, tag, { aad, safeMode: true });          // string | null
const pt3 = sm9.decrypt(ke, id, ct, { safeMode: true });                        // string | null
```

`safeMode` only swallows **ciphertext-side** failures; type errors still throw, so a typo in
your arguments never turns into a silent `null`.

::: tip `verify` never throws on a bad key
`sm2.verify` / `sm9.verify` **return `false`** for an off-curve key or a wrong signature —
"not verified" is an ordinary business result, not an exception. Only a structurally wrong
signature length raises `InvalidCiphertextError`.
:::

::: info Full reference
The [Chinese page](/guide/error-handling) has the per-algorithm table of typical errors.
:::

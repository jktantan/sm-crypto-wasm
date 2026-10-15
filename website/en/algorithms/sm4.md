# SM4 — block cipher

SM4 is the Chinese national block cipher (**GM/T 0002-2012**): a **128-bit block**, a
**128-bit key**, 32 rounds. The round function runs in `sm4.wasm`; the six modes
(ECB / CBC / CTR / CFB / OFB / GCM) are assembled on the TS side from block-level calls.

- The key is always **16 bytes**;
- The four block modes (ECB / CBC / CFB) also take a **16-byte** IV; GCM usually uses 12 bytes;
- Both encryption and decryption return **hex strings**.

## Import

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
```

## Choosing a mode

| Mode | IV | Padding | Error propagation | Use for |
| --- | --- | --- | --- | --- |
| ECB | no | none | — | **tests / legacy only**; equal plaintext blocks produce equal ciphertext blocks |
| CBC | 16 B | PKCS#7 | a damaged block affects the next one | the default for general use |
| CTR | 16 B | none | none | streaming, random access; **never reuse IV+counter** |
| CFB | 16 B | none | affects subsequent segments | self-synchronising streaming |
| OFB | 16 B | none | none | when error propagation matters |
| GCM | 12 B typical | none | — | **the recommended AEAD choice** |

::: tip Our default advice
Need confidentiality *and* integrity → **GCM**. Confidentiality only, and you'd rather not
manage padding → **CTR**. Reach for ECB / CBC only for format compatibility with older systems.
:::

## API

Every function takes its key as `string | Uint8Array`: strings are sniffed as hex / base64
(**there is no "UTF-8 text" key** — keys are bytes). All of them return a lowercase hex string.

### Block modes

| Function | Signature | Notes |
| --- | --- | --- |
| `encryptECB` | `(key, msg) => string` | no padding; `msg` length must be a **non-zero multiple of 16** |
| `decryptECB` | `(key, ct) => string` | same constraint |
| `encryptCBC` | `(key, iv, msg) => string` | PKCS#7 padded, any length (including empty) |
| `decryptCBC` | `(key, iv, ct) => string` | strips the padding |
| `encryptCFB` | `(key, iv, msg) => string` | CFB128, feedback taken from the ciphertext segment |
| `decryptCFB` | `(key, iv, ct) => string` | |

### Stream modes

| Function | Signature | Notes |
| --- | --- | --- |
| `encryptCTR` / `decryptCTR` | `(key, iv, data) => string` | **the same implementation** (alias `cryptCTR`); XORs a keystream, any length |
| `encryptOFB` / `decryptOFB` | `(key, iv, data) => string` | likewise (alias `cryptOFB`) |

CTR and OFB are involutions: `decrypt(encrypt(x)) === x`, which is why encryption and
decryption share one entry point. The canonical names in the source are `cryptCTR` /
`cryptOFB`; the `encrypt*` / `decrypt*` spellings are aliases pointing at the same function.

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

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | yes | 16 bytes |
| `iv` | `string \| Uint8Array` | yes | must not be empty; a 12-byte IV is used directly as J0 per the GCM spec |
| `msg` / `ct` | `string \| Uint8Array` | yes | **may be empty** (an empty plaintext is legal) |
| `tag` | `string \| Uint8Array` | decrypt only | the 16-byte authentication tag |
| `aad` | `string \| Uint8Array` | no | additional authenticated data: not encrypted, but authenticated |

The fifth argument of `decryptGCM` accepts either `aad` or `{ aad, safeMode: true }` —
`safeMode` returns `null` on authentication failure instead of throwing `DecryptionError`.

## Usage

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();

const key = '0123456789abcdeffedcba9876543210';  // 16 bytes
const iv  = '000102030405060708090a0b0c0d0e0f';  // 16 bytes

// ECB: no padding, length must be a multiple of 16
sm4.encryptECB(key, '00112233445566778899aabbccddeeff');

// CBC: PKCS#7 padded, any length
const ct = sm4.encryptCBC(key, iv, 'hello');
sm4.decryptCBC(key, iv, ct);                     // → '68656c6c6f'

// CTR / OFB: involutions
sm4.encryptCTR(key, iv, '616263');
sm4.decryptCTR(key, iv, sm4.encryptCTR(key, iv, '616263'));

// GCM: you also get the 16-byte tag
const { ct: gcmCt, tag } = sm4.encryptGCM(key, iv, '616263', 'aabbccdd');
sm4.decryptGCM(key, iv, gcmCt, tag, 'aabbccdd');                          // returns plaintext only if it verifies
sm4.decryptGCM(key, iv, gcmCt, tag, { aad: 'aabbccdd', safeMode: true }); // → null on failure
```

## Playground

<Sm4Playground />

## Errors and edge cases

| Situation | Thrown |
| --- | --- |
| `key` is not 16 bytes | `InvalidKeyError` |
| CBC / CFB / OFB `iv` is not 16 bytes | `InvalidKeyError` |
| GCM `iv` is empty | `InvalidKeyError` |
| ECB plaintext length is not a non-zero multiple of 16 | `RangeError` |
| ECB ciphertext length is not a non-zero multiple of 16 | `InvalidCiphertextError` |
| CBC ciphertext length is not a multiple of 16 | `InvalidCiphertextError` |
| CBC decrypted padding is invalid | `DecryptionError` |
| GCM `tag` is not 16 bytes | `InvalidCiphertextError` |
| GCM authentication fails (ciphertext / tag / AAD altered) | `DecryptionError` |

Arguments that are simply not cryptographic objects (bad enum values and the like) keep the
native `TypeError` / `RangeError`.

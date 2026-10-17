# SM3 — hash & HMAC

SM3 is the Chinese national hash algorithm (**GM/T 0004-2012**): a **256-bit digest** with a
512-bit block, used where SHA-256 would be. The implementation runs in `sm3.wasm`.

- Block length 512 bits, digest length 256 bits;
- The input may be an arbitrary bit string, **including the empty string** (`l = 0`);
- `hmac` is RFC 2104 HMAC-SM3 with a 64-byte block.

## Import

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();   // warm up once; everything after it is synchronous
```

## API

### Warm up WASM `sm3.ensureLoaded()`

```ts
function ensureLoaded(): Promise<void>
```

Loads and instantiates `sm3.wasm`. **You must `await` it once before `hash` / `hmac`.**
Repeated calls are cheap (module-level memoisation, concurrent callers share one Promise).

### Hash `sm3.hash(input)`

```ts
function hash(input: string | Uint8Array): string
```

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `input` | `string \| Uint8Array` | yes | the message to digest |

When `input` is a string, its encoding is sniffed in this order:

| Leading marker | Treated as |
| --- | --- |
| starts with `-----BEGIN` | PEM |
| has a `0x` prefix, or is pure `[0-9a-fA-F]` with even length | hex |
| any other string `atob` can decode | base64 |

**Returns** the 32-byte digest as a lowercase hex string (64 characters).

**Edge case**: an empty input is treated as a zero-length message — not an error. SM3 has a
well-defined result for the empty string. If you want a missing argument to fail loudly,
validate it in your own code.

### HMAC `sm3.hmac(key, msg)`

```ts
function hmac(key: string | Uint8Array, msg: string | Uint8Array): string
```

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | yes | any length; longer than 64 bytes is hashed first |
| `msg` | `string \| Uint8Array` | yes | the message |

**Returns** the 32-byte HMAC as a lowercase hex string. Both parameters follow the same
encoding-sniffing rules as `hash`.

## Usage

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();

// the UTF-8 bytes of the string 'abc'
sm3.hash(new TextEncoder().encode('abc'));
// → '66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0' (spaces removed)

// a hex input is decoded byte-wise — identical to the above
sm3.hash('616263');

// the empty string
sm3.hash('');

// HMAC-SM3 (RFC 2104)
sm3.hmac('00112233445566778899aabbccddeeff', '616263');
```

::: warning A string is not "text"
`sm3.hash('abc')` does **not** hash the UTF-8 text `abc` — the string is sniffed, `'abc'` is
not valid hex, so it falls through to base64 (2 bytes). To hash text, encode it explicitly
with `new TextEncoder().encode(text)` or pass a hex string.
:::

## Playground

The widget below loads `sm3.wasm` in your browser and runs for real — it is not a recorded
transcript. The message-encoding dropdown's `utf8` option is exactly
`new TextEncoder().encode(text)`.

<Sm3Playground />

## Related

- **[SM4](/en/algorithms/sm4)** GCM uses SM4 + GHASH and does not depend on SM3;
- **[SM2](/en/algorithms/sm2)** signing defaults to **SM3withSM2**, whose Z value is an SM3 digest;
- **[SM9](/en/algorithms/sm9)** derives user keys with SM3-based KDF and HMAC.

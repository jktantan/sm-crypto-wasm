# ZUC — stream cipher

ZUC is the Chinese national stream cipher (**GM/T 0001-2012**, i.e. **ZUC-128** from 3GPP
TS 35.221). Two algorithms are covered here:

| Capability | Standard | Entry points |
| --- | --- | --- |
| **EEA3** confidentiality | GM/T 0001.2-2012 | `zucEncrypt` / `zucDecrypt` / `zucKeystream` |
| **EIA3** integrity | GM/T 0001.3-2012 | `zucMac` / `zucEia3Iv` |

::: warning ZUC-128 only
ZUC-256 (GM/T 0001.1-2021) is a different algorithm — its LFSR, initialisation and key loading
are not a parameterisation of ZUC-128 — and it is **not implemented**. That is why `zucMac`
accepts only 32-bit tags.
:::

::: danger Never reuse a keystream
The keystream produced from one `(key, iv, counter)` XORed against two messages leaks their XOR —
a confidentiality failure. The **encryption path therefore refuses reuse explicitly**
(`InvalidKeyError`) rather than letting it slide.
:::

## Import

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
```

::: tip The return values are bytes, not hex
ZUC's four main functions return **`Uint8Array`** (unlike SM2 / SM3 / SM4, which return hex
strings). Use the `bytesToHex` helper this library also exports to display them.
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

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | yes | **16 bytes** |
| `iv` | `string \| Uint8Array` | yes | **16 bytes** |
| `nBytes` | `number` | yes | number of output bytes, a non-negative integer |

The keystream itself is not covered by the reuse guard — you are responsible for never reusing it.

### `zuc.zucEncrypt(key, iv, data, counter?, opts?)`

```ts
function zucEncrypt(
  key: string | Uint8Array,
  iv: string | Uint8Array,
  data: string | Uint8Array,
  counter?: number,                       // defaults to 0
  opts?: { reuseGuard?: boolean },        // participate in the reuse guard, default true
): Uint8Array
```

XORs the data with the keystream. **A second call with the same `(key, iv, counter)` throws
`InvalidKeyError`.** If you genuinely need to (say the key/IV come from a strictly managed
external counter), pass `{ reuseGuard: false }` or disable it globally with
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

EEA3 is an involution (the same keystream is XORed again). **The decryption path is exempt from
the reuse guard** — ciphertext may be verified or replayed more than once.

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

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `string \| Uint8Array` | — | 16-byte integrity key |
| `iv` | `string \| Uint8Array` | — | 16-byte IV (see `zucEia3Iv`) |
| `msg` | `string \| Uint8Array` | — | the protected message |
| `bitLength` | `number` | `msg.length * 8` | number of message **bits** participating (pass it explicitly for non-byte-aligned messages) |
| `tagBits` | `number` | `32` | only 32 is supported |

**Returns** the 4-byte (32-bit) tag.

### `zuc.zucEia3Iv(count, bearer, direction)`

```ts
function zucEia3Iv(count: number, bearer: number, direction: number): Uint8Array
```

Assembles a 16-byte IV as `COUNT(32) ‖ BEARER(5) ‖ DIRECTION(1) ‖ 0(26)` per GM/T 0001.3 /
TS 35.221, matching GmSSL's `zuc_set_eia_iv`.

| Parameter | Range |
| --- | --- |
| `count` | 32-bit unsigned integer |
| `bearer` | 0..31 |
| `direction` | 0 or 1 |

### Reuse-guard switches

```ts
function configureReuseGuard(opts: { enabled?: boolean; capacity?: number }): void
function resetReuseGuard(): void
```

The default is `{ enabled: true, capacity: 4096 }`: used `(key, iv, counter)` triples are
recorded and the oldest entry is evicted FIFO (**it must stay bounded**, or a long-running
process would grow without limit). `resetReuseGuard()` clears the record — use it only in tests
and for deliberate key rotation.

## Usage

```ts
import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();

const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

// keystream
bytesToHex(zuc.zucKeystream(key, iv, 16));

// EEA3 encryption/decryption (manage the counter strictly to avoid reuse)
const ct = zuc.zucEncrypt(key, iv, 'abc', 0);
const pt = zuc.zucDecrypt(key, iv, ct, 0);

// EIA3 integrity tag
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
bytesToHex(zuc.zucMac(key, macIv, 'abc'));          // → 4-byte tag

// non-byte-aligned messages: give the bit length explicitly
zuc.zucMac(key, macIv, msg, { bitLength: 577 });
```

## Playground

<ZucPlayground />

## Errors and edge cases

| Situation | Thrown |
| --- | --- |
| `key` or `iv` is not 16 bytes | `InvalidKeyError` |
| `zucEncrypt` `(key, iv, counter)` was already used | `InvalidKeyError` |
| `zucEncrypt` `counter` is not a non-negative integer | `RangeError` |
| `zucKeystream` `nBytes` is not a non-negative integer | `RangeError` |
| `zucMac` `tagBits` is not 32 | `RangeError` |
| `zucMac` `bitLength` outside `[0, msg.length * 8]` | `RangeError` |
| `zucEia3Iv` `count` / `bearer` / `direction` out of range | `RangeError` |

Named aliases (pointing at the same implementations): `zuc.encrypt` = `zucEncrypt`,
`zuc.decrypt` = `zucDecrypt`, `zuc.generateKeystream` = `zucKeystream`,
`zuc.mac` = `zuc.eia3` = `zucMac`.

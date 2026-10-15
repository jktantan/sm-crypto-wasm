# SM2 — elliptic-curve public key

SM2 is the Chinese national elliptic-curve public-key algorithm (**GM/T 0003-2012** series),
curve **`sm2p256v1`** (256-bit prime field, `a = p - 3`). This library covers four parts:

| Capability | Standard | Entry points |
| --- | --- | --- |
| Digital signature | GM/T 0003.2 | `sign` / `verify` (default **SM3withSM2**) |
| Public-key encryption | GM/T 0003.4 | `encrypt` / `decrypt` (ciphertext defaults to **C1C3C2**) |
| Key exchange | GM/T 0003.3 | `createExchangeInitiator` / `createExchangeResponder` |
| Key generation | — | `generateKeyPair` / `getPublicKey` |

::: tip Defaults
Signing is fixed to **SM3withSM2** with the user ID `"1234567812345678"` (the default ID from
GM/T 0003.2). Ciphertext is assembled as **C1C3C2** by default, and the decrypting side
**auto-detects** C1C3C2 vs C1C2C3.
:::

## Import

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();   // only generateKeyPair is async
```

## Key formats

SM2 key parameters accept three shapes — use whichever you already have:

| Shape | Private key | Public key |
| --- | --- | --- |
| raw bytes / hex | 32 bytes | 64 bytes `x‖y`, or 65 bytes with a `04` prefix |
| PEM | PKCS#8 (`PRIVATE KEY`), SEC1 (`EC PRIVATE KEY`) | SPKI (`PUBLIC KEY`) |
| `Uint8Array` | 32 bytes | 64 / 65 bytes |

Strings are always encoding-sniffed (`-----BEGIN` → PEM; even-length pure hex → hex;
otherwise base64). **There is no "UTF-8 text" key form.**

## API

### `sm2.generateKeyPair()`

```ts
function generateKeyPair(): Promise<{ privateKeyPem: string; publicKeyPem: string }>
```

Asynchronous: it instantiates the wasm and draws the private key `d` from the host CSPRNG.
Returns a **PKCS#8 private key PEM** and an **SPKI public key PEM**, both readable by
OpenSSL / GmSSL.

### `sm2.getPublicKey(privateKey)`

```ts
function getPublicKey(privateKey: string | Uint8Array): string
```

Derives the public key from a private key. **Returns** 128 hex characters (64 bytes `x‖y`).
This method **always recomputes** (it is not cached), preserving the semantics of "derive the
public key" as an operation.

### `sm2.sign(privateKey, message)`

```ts
function sign(privateKey: string | Uint8Array, message: string | Uint8Array): string
```

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `privateKey` | `string \| Uint8Array` | yes | 32 bytes / PKCS#8 / SEC1 |
| `message` | `string \| Uint8Array` | yes | the message to sign (strings are treated as UTF-8 bytes) |

**Returns** the 64-byte signature as hex (`r‖s`, 128 characters). The nonce `k` comes from the
host CSPRNG; the negligible chance that `r` or `s` is zero triggers a redraw (up to 16 attempts).

### `sm2.verify(publicKey, message, signature)`

```ts
function verify(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  signature: string | Uint8Array,
): boolean
```

**A public key that is not on the curve simply returns `false`** (no throw) — so "bad public
key" never gets confused with "bad signature" via two different exception paths. A signature
whose length is not 64 bytes throws `InvalidCiphertextError`.

### `sm2.encrypt(publicKey, message, opts?)`

```ts
function encrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { outputFormat?: 'C1C3C2' | 'C1C2C3' },
): string
```

**Returns** the ciphertext as hex: `C1(65B) ‖ C3(32B) ‖ C2` by default, or `C1 ‖ C2 ‖ C3` when
`outputFormat: 'C1C2C3'` is passed. A public key off the curve throws `InvalidPublicKeyError`.

### `sm2.decrypt(privateKey, ciphertext, opts?)`

```ts
function decrypt(
  privateKey: string | Uint8Array,
  ciphertext: string | Uint8Array,
  opts?: { inputFormat?: 'C1C3C2' | 'C1C2C3' | 'auto'; safeMode?: boolean },
): string
```

| Option | Default | Description |
| --- | --- | --- |
| `inputFormat` | `'auto'` | `auto` decrypts as C1C3C2 first, then retries as C1C2C3 if the C3 check fails |
| `safeMode` | `false` | when `true`, a ciphertext-side failure returns `null` instead of throwing |

`safeMode` only swallows **ciphertext-side** failures; argument type errors (`TypeError` /
`RangeError`) still throw.

### `sm2.configurePublicKeyCache(opts)` / `sm2.clearPublicKeyCache()`

```ts
function configurePublicKeyCache(opts: { enabled?: boolean; capacity?: number }): void
function clearPublicKeyCache(): void
```

`sign` needs the public key on every call to compute the Z value, and the public key depends
only on the private key. An in-process cache is **enabled by default** (keyed by the private
key's hex, capacity 32, FIFO eviction); a hit skips the fixed-base scalar multiplication —
measured at 252 µs → 142 µs for `sign`.

**The trade-off**: the cache keeps derived public keys (and the private key's hex form) in
process memory. If your threat model forbids that, turn it off with
`configurePublicKeyCache({ enabled: false })` and you are back to recomputing every time.

## Key exchange (GM/T 0003.3)

```ts
const alice = await sm2.createExchangeInitiator(privA, pubB, { idSelf: 'Alice', idPeer: 'Bob' });
const bob = await sm2.createExchangeResponder(privB, pubA, { idSelf: 'Bob', idPeer: 'Alice' });

const r1 = alice.initiate();     // phase 1: initiator → responder (RA)
const r2 = bob.respond(r1);      // phase 2: responder → initiator (RB + S_B)
const r3 = alice.confirm(r2);    // phase 3: initiator → responder (S_A)

const kA = alice.getSharedKey(r3);
const kB = bob.getSharedKey(r3);  // both sides end up with the same shared key
```

| Option | Default | Description |
| --- | --- | --- |
| `idSelf` | `"1234567812345678"` | this side's user ID |
| `idPeer` | `"1234567812345678"` | the peer's user ID |
| `ephemeralPrivateKey` | host CSPRNG | **test injection only**; do not pass it in production |

| Endpoint method | Returns | Notes |
| --- | --- | --- |
| `initiator.initiate()` | `{ ephemeralPub }` | may be called once |
| `initiator.confirm(r2)` | `{ confirm }` | **verifies the received S_B** and throws if it fails |
| `initiator.getSharedKey(r3?, kLen?)` | hex | requires a prior `confirm()` |
| `responder.respond(r1)` | `{ ephemeralPub, confirm }` | may be called once |
| `responder.getSharedKey(r3, kLen?)` | hex | verifies the initiator's S_A |

## Usage

```ts
import { sm2 } from 'sm-crypto-wasm';

// 1) generate a key pair (PEM)
const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

// 2) sign / verify
const sig = sm2.sign(privateKeyPem, 'abc');
sm2.verify(publicKeyPem, 'abc', sig);                    // → true

// 3) encrypt / decrypt
const ct = sm2.encrypt(publicKeyPem, 'abc');             // C1C3C2 by default
sm2.decrypt(privateKeyPem, ct);                          // → '616263'

// talking to an older system that only speaks C1C2C3
const ct2 = sm2.encrypt(publicKeyPem, 'abc', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct2, { inputFormat: 'C1C2C3' });
```

Raw hex keys work just as well:

```ts
const d = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
const pub = sm2.getPublicKey(d);                          // 128 hex characters
const sig = sm2.sign(d, 'abc');
sm2.verify(pub, 'abc', sig);
```

## Playground

<Sm2Playground />

## Errors and edge cases

| Situation | Thrown |
| --- | --- |
| private key is not 32 bytes | `InvalidKeyError` |
| public key is not 64 / 65 bytes | `InvalidKeyError` |
| `encrypt` public key is off the curve | `InvalidPublicKeyError` |
| `verify` public key is off the curve | no throw — **returns `false`** |
| signature length is not 64 bytes | `InvalidCiphertextError` |
| ciphertext is shorter than 97 bytes | `InvalidCiphertextError` |
| C3 check fails (key / ciphertext mismatch) | `DecryptionError` |
| unknown `outputFormat` / `inputFormat` value | `RangeError` |
| `configurePublicKeyCache({ capacity: 0 })` | `RangeError` |

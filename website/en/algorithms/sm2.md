# SM2 — elliptic-curve public key

SM2 is the Chinese national elliptic-curve public-key algorithm (**GM/T 0003-2012** series),
curve **`sm2p256v1`** (256-bit prime field, `a = p - 3`). This library covers four parts:

| Capability | Standard | Entry points |
| --- | --- | --- |
| Digital signature | GM/T 0003.2 | `sign` / `verify` (default **SM3withSM2**) |
| Public-key encryption | GM/T 0003.4 | `encrypt` / `decrypt` (ciphertext defaults to **C1C3C2**) |
| Key encapsulation / hybrid encryption | — (conventional) | `kemEncrypt` / `kemDecrypt`, `hybridEncrypt` / `hybridDecrypt` |
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

### `sm2.sign(privateKey, message, opts?)`

```ts
function sign(
  privateKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { pointPool?: SignaturePoint[] },
): string
```

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `privateKey` | `string \| Uint8Array` | yes | 32 bytes / PKCS#8 / SEC1 |
| `message` | `string \| Uint8Array` | yes | the message to sign (strings are treated as UTF-8 bytes) |
| `opts.pointPool` | `SignaturePoint[]` | no | pre-computed signing points; see `createSignaturePointPool`. Consumed in place |

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

### `sm2.kemEncrypt(publicKey, klen = 32)` / `sm2.kemDecrypt(privateKey, encapsulation, klen = 32, opts?)`

```ts
function kemEncrypt(publicKey: string | Uint8Array, klen?: number):
  { key: string; encapsulation: string }
function kemDecrypt(
  privateKey: string | Uint8Array,
  encapsulation: string | Uint8Array,
  klen?: number,
  opts?: { safeMode?: boolean },
): string
```

**SM2 has no standardized standalone KEM.** This is the conventional "encrypt a random
symmetric key with SM2" idiom. `encapsulation` is a complete SM2 ciphertext (C1C3C2,
`97 + klen` bytes) with its own C3 check; a wrong private key or tampering throws
`DecryptionError`. With `safeMode: true` it returns `null`.

### `sm2.hybridEncrypt(publicKey, message, opts?)` / `sm2.hybridDecrypt(privateKey, sealed, opts?)`

```ts
function hybridEncrypt(
  publicKey: string | Uint8Array,
  message: string | Uint8Array,
  opts?: { iv?: string | Uint8Array },
): string
function hybridDecrypt(
  privateKey: string | Uint8Array,
  sealed: string | Uint8Array,
  opts?: { safeMode?: boolean },
): string
```

One call performs **KEM + SM4-GCM**: the public key protects only a 16-byte DEK, and the
message goes through the symmetric cipher. This is the right shape for large messages and
keeps long data out of SM2's KDF / point-operation path.

- Every call generates a fresh 16-byte DEK and 12-byte IV; `iv` is for tests / protocol
  interop only — do not pass it in normal use.
- `message` strings are interpreted as **hex**; pass `new Uint8Array(0)` for an empty message.
- The returned `sealed` is versioned:
  `version(1) ‖ klen(1) ‖ encapLen(2) ‖ encapsulation ‖ iv(12) ‖ tag(16) ‖ ct`.
- AAD binds `encapsulation`; tampering or a wrong private key throws `DecryptionError`.
- With `safeMode: true`, ciphertext-side failures return `null`.
- Hybrid depends on both `sm2.wasm` and `sm4.wasm`: warm them up with `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])` before the first call.

### `sm2.sealedToObject(sealed)` / `sm2.sealedFromObject(obj)`

```ts
function sealedToObject(sealed: string | Uint8Array): {
  v: number; klen: number; encapsulation: string; iv: string; tag: string; ct: string;
}
function sealedFromObject(obj: SealedObject): string
```

Convert `sealed` between its hex string and a self-describing object — useful for debugging
or for interoperating with a manual `kemEncrypt` + `sm4.encryptGCM` assembly.

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

### `sm2.createSignaturePointPool(n)`

```ts
class SignaturePoint {
  readonly point: string; // k·G in affine x‖y (64-byte hex); public information
}
async function createSignaturePointPool(n: number): Promise<SignaturePoint[]>
```

Pre-computes `n` single-use signing points for `sign`'s `pointPool` option. The fixed-base
scalar multiplication `k·G` accounts for about **56%** of one signature; amortising it ahead
of time leaves only `e = SM3(Z‖M)` and two modular operations on the critical path — measured
at **141 µs → 24 µs (5.9×)** per signature. It only pays off for bulk signing (a server
issuing signatures back to back); for occasional signatures use the default path.

```ts
const pool = await sm2.createSignaturePointPool(10000);
for (const msg of messages) {
  const sig = sm2.sign(privateKey, msg, { pointPool: pool }); // consumes one point each
}
```

**"Never reuse `k`" is enforced structurally — you don't have to think about it.** The nonce
stays inside the library: it is never exposed and cannot be copied (`SignaturePoint` carries
only the public `k·G` coordinates), and `sign` removes it from the index and zeroes the bytes
the moment it is used. Feeding the same point twice **throws on the spot** instead of silently
reusing it — and reusing `k` under SM2 leaks the private key outright. A forged
`SignaturePoint` is equally useless (it is not in the index).

Once the pool runs dry, `sign` falls back to computing `k` on the fly (no skipped or wrong
signatures). `n` must be a non-negative integer, otherwise `RangeError`.

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

KEM and hybrid encryption:

```ts
// 4) KEM: protect a random session key with the public key
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);        // === key

// 5) Hybrid encryption: one call performs KEM + SM4-GCM; suited to large messages
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);                 // → '616263'

// sealed can also round-trip between hex and object form
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
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
| `kemDecrypt` C3 check fails / wrong private key | `DecryptionError` |
| `hybridDecrypt` sealed structure is malformed (version / length field / truncation) | `InvalidCiphertextError` |
| `hybridDecrypt` GCM tag check fails | `DecryptionError` |
| `hybridEncrypt` `iv` is not 12 bytes | `RangeError` |
| `kemEncrypt` / `kemDecrypt` `klen` is outside [1, 65536] | `RangeError` |
| unknown `outputFormat` / `inputFormat` value | `RangeError` |
| `configurePublicKeyCache({ capacity: 0 })` | `RangeError` |

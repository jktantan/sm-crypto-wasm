# SM9 — identity-based cryptography

SM9 is a pairing-based **identity-based** cryptosystem (**GM/T 0044-2016** series). Its
defining trait: **the user identity (an email, say) *is* the public key**, so there is no
certificate chain — a key generation centre (KGC) derives each identity's private key from a
master secret.

| Capability | Standard | Entry points |
| --- | --- | --- |
| Digital signature | GM/T 0044.2 | `sign` / `verify` |
| Key exchange | GM/T 0044.3 | `createExchangeInitiator` / `createExchangeResponder` |
| KEM, encryption & hybrid encryption | GM/T 0044.4 | `encrypt` / `decrypt`, `kemEncrypt` / `kemDecrypt`, `hybridEncrypt` / `hybridDecrypt` |

::: warning The two master keys are not interchangeable
Signing and encryption use **independent** master keys (`purpose: 'sign' | 'enc'`): the signing
master public key is a **G2 point** (128 bytes) and the encryption one a **G1 point** (64 bytes).
Using the wrong purpose fails a length check or the pairing verification.
:::

Master private keys, master public keys and user private keys are all encoded as PEM using
**PKCS#8 with the custom OID `1.2.156.10197.1.100`**.

## Import

```ts
import { sm9 } from 'sm-crypto-wasm';

await sm9.ensureLoaded();
```

## API

### Generate master key pair `sm9.generateKeyPair(opts)`

```ts
function generateKeyPair(opts: {
  id: string | Uint8Array;          // user identity
  purpose?: 'sign' | 'enc';          // defaults to 'sign'
}): Promise<Sm9KeyPair>
```

Four pieces of material come back:

| Field | Purpose | Form |
| --- | --- | --- |
| `masterPrivatePem` | master private key (signing `ks` / encryption `ke`) | PKCS#8 PEM (32-byte scalar) |
| `masterPublicPem` | master public key (signing `[ks]P2` / encryption `[ke]P1`) | SPKI PEM (G2 128B / G1 64B) |
| `userPrivatePem` | user private key (`ds` G1 64B / `de` G2 128B) | PKCS#8 PEM |
| `userPublicPem` | user public key `Q = [H1(id,hid)]P + Ppub` | SPKI PEM |

`userPublicPem` is a **deterministic function** of `(id, master public key)`, not an independent
secret — a third party can recompute it with `getUserPublicKey`.

### Deriving public keys

| Function | Signature | Returns |
| --- | --- | --- |
| `getSignPublicKey` | `(ks: string \| Uint8Array) => string` | 128-byte hex (G2 affine) |
| `getEncPublicKey` | `(ke: string \| Uint8Array) => string` | 64-byte hex (G1 affine) |
| `getUserPublicKey` | `(masterPublicKey, id) => string` | SPKI PEM |

All three take their master private key as 32 raw bytes (hex / `Uint8Array` / PKCS#8 PEM).

### Sign / verify

```ts
function sign(ks, id, msg, r?): string      // → 96-byte signature as hex (h‖Sx‖Sy, 192 chars)
function verify(publicKey, id, msg, sig): boolean
```

| Parameter | Description |
| --- | --- |
| `ks` / `publicKey` | signing accepts either a **32-byte master private key** (or PKCS#8 PEM) or a **128-byte signing master public key** (or SPKI PEM) — the length disambiguates |
| `id` | the user identity (string or `Uint8Array`) |
| `msg` | message; strings are UTF-8 encoded |
| `r` | optional 32-byte nonce (test injection); otherwise the host CSPRNG is used |

### Encrypt / decrypt

```ts
function encrypt(publicKey, id, msg, r?): string      // → ciphertext hex (C1 65B ‖ C3 32B ‖ C2)
function decrypt(ke, id, ct, opts?: { safeMode?: boolean }): string
```

The first argument of `encrypt` may be a **32-byte encryption master private key** or a
**64-byte encryption master public key** (SPKI PEM also works). `decrypt` requires the
**encryption master private key** (or a derived user private key); a failed authentication
throws `DecryptionError`, or returns `null` with `{ safeMode: true }`.

### Key encapsulation (GM/T 0044.4)

```ts
function kemEncrypt(ke, id, klen = 32, r?): { key: string; encapsulation: string }
function kemDecrypt(ke, id, encapsulation, klen = 32): string
```

| Parameter | Description |
| --- | --- |
| `ke` | **the encryption master private key** — KEM needs it to derive `Ppub-e`, unlike `encrypt`, which also accepts the public key |
| `id` | the recipient's identity |
| `klen` | session key length in bytes, default 32 |
| `encapsulation` | the 65-byte encapsulation point (`04 ‖ x ‖ y`) as hex |

### Hybrid encryption (KEM + SM4-GCM)

```ts
function hybridEncrypt(
  key, id, msg, opts?: { iv?: string | Uint8Array },
): string
function hybridDecrypt(
  ke, id, sealed, opts?: { safeMode?: boolean },
): string
```

`key` may be a **64-byte encryption master public key** (SPKI PEM also works) or a
**32-byte encryption master private key** (PKCS#8 PEM also works) — senders usually only
have the master public key. One call performs KEM + SM4-GCM: the KEM encapsulates a
16-byte DEK, and the message goes through SM4-GCM.

- `sealed` uses the same versioned layout as SM2 hybrid:
  `version(1) ‖ klen(1) ‖ encapLen(2) ‖ encapsulation ‖ iv(12) ‖ tag(16) ‖ ct`.
- Every call generates a fresh DEK and IV; `msg` strings are interpreted as **hex**;
  pass `new Uint8Array(0)` for an empty message.
- The SM9 KEM C1 carries no C3/HMAC; integrity comes from the GCM tag. A wrong id /
  master public key surfaces as `DecryptionError` from `hybridDecrypt`.
- AAD binds `encapsulation`; with `safeMode: true`, ciphertext-side failures return `null`.
- Hybrid depends on both `sm9.wasm` and `sm4.wasm`: call `await sm9.ensureLoaded()` and `await sm4.ensureLoaded()` before the first use.
- `sealedToObject` / `sealedFromObject` are available as well.

### Key exchange (GM/T 0044.3)

```ts
// Both sides must belong to the same KGC and share the encryption master key `ke`;
// each passes its own ID and the peer's ID.
const initiator = await sm9.createExchangeInitiator(ke, idSelf, idPeer, opts?);
const responder = await sm9.createExchangeResponder(ke, idSelf, idPeer, opts?);

const m1 = initiator.initiate();          // phase 1
const m2 = responder.respond(m1);         // phase 2 (carries confirm)
const m3 = initiator.confirm(m2);         // phase 3
initiator.getSharedKey(m2, kLen?);        // both sides derive the same session key
responder.getSharedKey(m3, kLen?);
```

`options.kLen` sets the session key length (default 32); `options.ephemeral` is a **test
injection** for the ephemeral private key.

## Usage

```ts
import { sm9 } from 'sm-crypto-wasm';

const id = 'alice@example.com';

// one master key pair per purpose
const signKp = await sm9.generateKeyPair({ id });                 // purpose defaults to 'sign'
const encKp  = await sm9.generateKeyPair({ id, purpose: 'enc' });

// sign / verify
const sig = sm9.sign(signKp.masterPrivatePem, id, 'abc');
sm9.verify(signKp.masterPublicPem, id, 'abc', sig);                // → true

// encrypt / decrypt
const ct = sm9.encrypt(encKp.masterPublicPem, id, 'abc');
sm9.decrypt(encKp.masterPrivatePem, id, ct);                       // → '616263'

// KEM: agree on a symmetric key, no message involved
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, id, 32);
sm9.kemDecrypt(encKp.masterPrivatePem, id, encapsulation, 32);     // === key
```

Hybrid encryption (suited to large messages):

```ts
// Encapsulate a 16-byte DEK with the master public (or private) key + id,
// then encrypt the message with SM4-GCM.
const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, id, '616263');
sm9.hybridDecrypt(encKp.masterPrivatePem, id, sealed);             // → '616263'
```

## Playground

<Sm9Playground />

::: details Why SM9 is slower than the rest
Pairings dominate: one signature is roughly 4 ms, a verification about 8 ms, an encryption
about 3.7 ms — an order of magnitude above SM2. That is the mathematical cost of pairings, not
an implementation shortcoming — see the [performance page](/en/performance).
:::

## Errors and edge cases

| Situation | Thrown |
| --- | --- |
| `id` is empty in `generateKeyPair` / `getUserPublicKey` | `RangeError` |
| `purpose` is neither `'sign'` nor `'enc'` | `RangeError` |
| master private key is not 32 bytes | `InvalidKeyError` |
| signature length is not 96 bytes | `InvalidCiphertextError` |
| ciphertext is shorter than 97 bytes | `InvalidCiphertextError` |
| the C3 HMAC check fails | `DecryptionError` |
| `kemDecrypt` `encapsulation` is not 65 bytes | `RangeError` |
| `hybridDecrypt` sealed structure is malformed | `InvalidCiphertextError` |
| `hybridDecrypt` GCM tag check fails (including wrong id / master public key) | `DecryptionError` |
| `hybridEncrypt` `iv` is not 12 bytes | `RangeError` |
| `klen` is not a positive integer | `RangeError` |

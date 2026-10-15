# Security Notes

## What the library handles for you

- **Randomness only from the host CSPRNG** — every `k`, `r` and private key `d` comes from
  `globalThis.crypto.getRandomValues` (falling back to `webcrypto` in Node). There is **no
  built-in RNG** and no path that degrades to `Math.random()`.
- **Rejection sampling for private keys** — 256-bit candidates are redrawn until below the
  curve order, rather than reduced modulo, which would skew the distribution.
- **Public keys must be on the curve** — `sm2.encrypt` verifies `y² ≡ x³ + ax + b (mod p)`
  and rejects out-of-range coordinates with `InvalidPublicKeyError`. `sm2.verify` simply
  returns `false` for such a key.
- **Keystream reuse is refused** — `zuc.zucEncrypt` remembers used `(key, iv, counter)`
  triples and throws `InvalidKeyError` on a repeat. The record is bounded (4096 entries, FIFO).
- **Constant-time confirmation checks** — the `S_A` / `S_B` comparisons in SM2 / SM9 key
  exchange are byte-wise constant time.

## What is your decision

- **SM2 public-key derivation cache (on by default)** — makes `sign` 252 → 142 µs, at the
  cost of keeping a private key's hex form and its derived public key in process memory. Turn
  it off with `sm2.configurePublicKeyCache({ enabled: false })` if your threat model forbids it.
- **ECB and unauthenticated encryption** — ECB leaks structure; CTR / OFB / ECB give you no
  integrity at all. Use **SM4-GCM** when you need both.
- **IV / nonce uniqueness** — a repeated GCM IV under the same key is fatal. The library never
  generates IVs for you; pass them in and guarantee uniqueness.
- **Key storage and lifecycle** — the library does the algorithms, not key management. It never
  writes to disk or logs, but `localStorage` / logging / error reporting is your code's concern.

## Out of scope

HSM / PKCS#11 handles; X.509 / PKCS#7 / CMS; hard real-time side-channel guarantees (WASM's
constant-time behaviour is not fully under the library's control).

## Recommended defaults

| Need | Choice |
| --- | --- |
| Hashing | SM3 |
| Symmetric encryption + integrity | **SM4-GCM** |
| Confidentiality only | SM4-CTR (unique IV) or SM4-CBC (unpredictable IV) |
| Digital signature | **SM2 + SM3withSM2** |
| Public-key encryption | **SM2** (C1C3C2) |
| Identity-based / certificate-free | **SM9** |
| Mobile protocol stacks | **ZUC** (EEA3 + EIA3) |

::: info Full reference
The [Chinese page](/guide/security) covers each point in more depth.
:::

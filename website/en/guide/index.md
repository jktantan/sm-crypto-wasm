# Introduction

`sm-crypto-wasm` compiles the hot paths of Chinese national cryptographic algorithms into
**WebAssembly**, so front-end and Node back-end engineers can call **SM2 / SM3 / SM4 / SM9 /
ZUC** through one API — without dealing with ASN.1, big-integer arithmetic or WASM glue.

AssemblyScript compiles to `.wasm`, wrapped in a thin TypeScript shim. Compared with pure-JS
implementations, elliptic curves and pairings are an order of magnitude faster. Compared with
C++ / Rust implementations, distributing it on npm requires no compiler toolchain on the
user's machine.

## The five algorithms

| Algorithm | Standard | What it is | Docs |
| --- | --- | --- | --- |
| **SM3** | GM/T 0004-2012 | 256-bit hash, SHA-256 class | [SM3](/en/algorithms/sm3) |
| **SM4** | GM/T 0002-2012 | 128-bit block cipher, six modes | [SM4](/en/algorithms/sm4) |
| **SM2** | GM/T 0003-2012 | Elliptic-curve public key (sign / encrypt / key exchange) | [SM2](/en/algorithms/sm2) |
| **SM9** | GM/T 0044-2016 | Identity-based crypto (sign / encrypt / KEM / key exchange) | [SM9](/en/algorithms/sm9) |
| **ZUC** | GM/T 0001-2012 | Stream cipher, EEA3 confidentiality + EIA3 integrity | [ZUC](/en/algorithms/zuc) |

## Design decisions

- **Split per algorithm, lazy-loaded**: one `.wasm` per algorithm; only what you call is
  fetched. A page that only hashes never pays for SM9's pairing tables.
- **Synchronous business API, async warm-up**: `ensureLoaded()` is async (WASM instantiation
  has to be); everything after it is synchronous, so you don't wrap every call in `await`.
- **Randomness always comes from the host**: `crypto.getRandomValues` /
  `crypto.randomBytes`. The library ships **no RNG** and never writes keys to disk or logs.
- **Input sniffing**: hex / base64 / PEM / Uint8Array are detected; output defaults to hex.
- **Layered errors**: anything rejected *because of its input* derives from `SmCryptoError`,
  split into a **key side** and a **ciphertext side**; arguments that are simply the wrong
  type keep the native `TypeError` / `RangeError`.

## Out of scope

Deliberately not included:

- **ZUC-256** (GM/T 0001.1-2021) — a different algorithm, not a parameterisation of ZUC-128;
- a WebCrypto (`crypto.subtle`) style adapter;
- HSM / PKCS#11 handles;
- X.509 / PKCS#7 / CMS protocol layers;
- "strictly streaming WASM" runtimes such as Cloudflare Workers / Vercel Edge.

## Next

- [**Installation & Quick Start**](/en/guide/getting-started)
- [**Performance**](/en/performance)

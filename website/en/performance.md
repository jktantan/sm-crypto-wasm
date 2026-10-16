# Performance

Hot paths (big-integer modular arithmetic, hash compression, block-cipher rounds, bilinear
pairings) execute inside WASM. The table covers **every public operation**; the `gmkitx`
column is a pure-JS reference implementation on the same machine, with the same parameters
and messages (**operations it does not have are left as `—`**). Measured on AMD Ryzen 7
7800X3D / Node 24.15 / Windows 11; reproduce with `pnpm bench`.

| Algorithm | Operation | sm-crypto-wasm | Pure-JS reference (gmkitx) | Ratio |
|---|---|---|---|---|
| SM3 | hash 32 B / 1 KB / 64 KB | 872 ns / 4.75 µs / 245 µs | 14.7 µs (1 KB) | 3.1× faster |
| SM3 | hmac 1 KB | 5.58 µs | 19.4 µs | 3.5× faster |
| SM4 | ECB 16 B / 1 KB | 0.94 µs / 6.98 µs | 37.3 µs (1 KB) | 5.3× faster |
| SM4 | CBC 1 KB | 10.5 µs | 41.6 µs | 4.0× faster |
| SM4 | CTR 1 KB | 7.43 µs | 36.5 µs | 4.9× faster |
| SM4 | CFB 1 KB | 10.0 µs | 37.9 µs | 3.8× faster |
| SM4 | OFB 1 KB | 9.98 µs | 36.3 µs | 3.6× faster |
| SM4 | GCM 1 KB | 19.8 µs | 221 µs | 11.2× faster |
| SM2 | key pair generation | 151 µs | — | — |
| SM2 | public key derivation | 110 µs | 197 µs | 1.8× faster |
| SM2 | sign 64 B | 142 µs | 446 µs | 3.1× faster |
| SM2 | verify 64 B | 402 µs | 2.85 ms | 7.1× faster |
| SM2 | encrypt 64 B | 499 µs | 2.96 ms | 5.9× faster |
| SM2 | decrypt 64 B | 343 µs | 2.59 ms | 7.6× faster |
| SM2 | key exchange (full A↔B) | 1.52 ms | 11.4 ms | 7.5× faster |
| SM9 | master key pair (sign / enc) | 2.07 / 1.73 ms | — | — |
| SM9 | master public key (sign / enc) | 97.1 / 49.1 µs | — | — |
| SM9 | user public key derivation | 563 µs | — | — |
| SM9 | sign 32 B | 4.11 ms | — | — |
| SM9 | verify 32 B | 8.00 ms | — | — |
| SM9 | encrypt 32 B | 3.69 ms | — | — |
| SM9 | decrypt 32 B | 5.40 ms | — | — |
| SM9 | KEM encapsulate / decapsulate | 3.42 / 4.92 ms | — | — |
| SM9 | key exchange (full A↔B) | 19.6 ms | — | — |
| ZUC | EEA3 encrypt 1 KB | 9.07 µs | 20.5 µs | 2.3× faster |
| ZUC | EEA3 keystream 1 KB | 6.15 µs | — | — |
| ZUC | EIA3 MAC 1 KB | 11.2 µs | — | — |

::: warning The SM2 row fluctuates
SM2 sits behind a TS facade (signing uses the public-key cache, encryption still does hex and
curve-point codecs plus a host CSPRNG call). Run-to-run variation reaches **±20%**, much
larger than SM3 / SM4 / SM9 / ZUC. The table takes the whole SM2 row from a single run.
:::

## Head-to-head with two other GM libraries

The table above benchmarks against the pure-JS `gmkitx`. Swapping in **two other real
Chinese-cryptography libraries**, with identical parameters, messages and keys:

- **Cubelrti/sm-crypto-wasm** — Rust + `wasm-bindgen` compiled to WebAssembly (⚠️ same
  package name as this project, but a different codebase);
- **sm-crypto-v2** — TypeScript + [noble-curves](https://github.com/paulmillr/noble-curves),
  among the fastest pure-JS options today.

Each side is its own **release build from source**, and the benchmark ships a self-check that
compares all three byte-for-byte (SM3 / SM4 must be identical, SM2 cross-verification must
pass) — any mismatch throws instead of reporting a bogus number.

| Operation | sm-crypto-wasm | Cubelrti/WASM | sm-crypto-v2 | Ratio |
|---|---|---|---|---|
| SM2 sign 64 B | **142 µs** | 4.56 ms | 293 µs | 32.0× / 2.1× faster |
| SM2 verify 64 B | **401 µs** | 4.65 ms | 2.74 ms | 11.6× / 6.8× faster |
| SM2 encrypt 64 B | **508 µs** | 4.57 ms | 2.73 ms | 9.0× / 5.4× faster |
| SM2 decrypt 64 B | **339 µs** | 2.24 ms | 2.45 ms | 6.6× / 7.2× faster |
| SM2 key pair generation | **148 µs** | 2.20 ms | 206 µs | 14.9× / 1.4× faster |
| SM3 hash 1 KB | **4.76 µs** | 25.1 µs | 6.43 µs | 5.3× / 1.35× faster |
| SM3 hmac 1 KB | **5.65 µs** | 29.4 µs | 9.29 µs | 5.2× / 1.64× faster |
| SM4 ECB encrypt 1 KB | **6.81 µs** | 12.2 µs | 12.5 µs | 1.8× / 1.8× faster |
| SM4 CBC encrypt 1 KB | **10.6 µs** | 19.9 µs | 15.1 µs | 1.9× / 1.4× faster |
| SM4 CBC decrypt 1 KB | **10.9 µs** | 22.4 µs | 14.1 µs | 2.1× / 1.3× faster |
| SM4 CTR encrypt 1 KB | **7.23 µs** | 12.1 µs | — (not implemented) | 1.7× faster |
| SM4 GCM encrypt 1 KB | **19.8 µs** | 27.0 µs | 30.2 µs | 1.4× / 1.5× faster |

Reproduce (the Cubelrti side builds its Rust/WASM inside a container, hence Docker):

```bash
bash bench/build-cubelrti-wasm.sh   # emits bench/.vendor/cubelrti/pkg/
pnpm bench:cubelrti
```

::: details Three observations worth noting
- **Rust→WASM is not automatically faster**: Cubelrti's SM2 trails the *pure-JS*
  `sm-crypto-v2` across the board (15× slower on signing). Its hot path uses `num-bigint`
  (a general-purpose, heap-allocating big integer) instead of fixed-width field arithmetic;
  every API call re-derives the public key (its `keypair` at 2.20 ms is about half its
  `sign` at 4.56 ms, i.e. signing performs two scalar multiplications); and every exported
  function runs a `console::log_1`.
- **`sm-crypto-v2` is the pure-JS ceiling**: on SM4 it roughly ties Cubelrti, and on SM3 it
  is only 1.35× behind this project.
- **Bulk signing has a dedicated path**: `sm2.createSignaturePointPool(n)` amortises the
  fixed-base scalar multiplication (56% of a signature) ahead of time, taking a signature
  from 141 µs to **24 µs (5.9×)** when the pool is hit.
:::

## Why it looks like this

- **SM3 got another round**: `compress` used to materialise W′ (`W[j] ^ W[j+4]`) in a separate
  pass of 64 stores + 128 loads; it is now computed in-place inside the round loop. The round
  loops use pointer increments, and the padding buffer is module-level reused (previously every
  `hash` call did `new StaticArray<u8>(totalLen)` and **zeroed the whole length**, while only the
  padding region actually needs zeroing). **HMAC now runs entirely inside WASM** (the ipad/opad
  concatenation and the two digest calls used to happen in JS: four boundary crossings plus three
  temporary arrays), backed by a two-segment input entry that lets `ipad ‖ msg` feed the padding
  directly. Net effect: hash **26%** faster, hmac **45%** faster.
- **SM4 / ZUC are S-box bound**: both are limited by the **8-bit S-box lookup**, and WebAssembly
  exposes neither ARMv8's `SM4E` nor AES-NI. SM4 briefly tried `v128` SIMD and it measured
  *slower* than 8-way scalar interleaving (four independent dependency chains per block, hiding
  L1 latency via out-of-order execution); that path was removed. SM3 is MD-chained (blocks cannot
  be parallelised) with a serial 64-round compression function.
- **SM4's CFB / OFB used to be slower than pure JS** — they called into wasm block-by-block
  (64 crossings per KB). Batch exports brought them to ~10 µs, i.e. 3.6~3.8× faster.
- **SM2's compute layer went through eight rounds of work** (Solinas reduction, Comba squaring,
  comb/wNAF scalar multiplication, in-place point arithmetic, mixed coordinates, joint scalar
  multiplication for verification, word-level inversion, public-key derivation caching for
  `sign`). Details in
  [`docs/performance-ceiling.md`](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/performance-ceiling.md).
- **SM9 is pairing-dominated.** Moving the base field to a Montgomery domain (CIOS) took one
  modular multiplication from 179 ns to 98 ns and sped up every end-to-end operation by
  **1.6~1.8×**. There is no comparable pure-JS SM9 implementation, so only absolute numbers
  are given.
- **hex codecs mattered**: switching encoding to `Buffer.toString('hex')` (with a lookup-table
  fallback in browsers) is ~27× faster; the input side now validates and parses in one pass.
  Together that made hex-input SM3 / SM4 / ZUC **27~32%** faster end to end.

::: tip Numbers vary by version and machine
The values above come from one specific machine — use `pnpm bench` / `pnpm bench:cubelrti` on
your own. The full experiment log and the "how much room is left" assessment live in
[`docs/performance-ceiling.md`](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/performance-ceiling.md).
:::

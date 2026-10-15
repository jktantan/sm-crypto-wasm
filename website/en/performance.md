# Performance

Hot paths (big-integer modular arithmetic, hash compression, block-cipher rounds, bilinear
pairings) execute inside WASM. The table covers **every public operation**; the `gmkitx`
column is a pure-JS reference implementation on the same machine, with the same parameters
and messages (**operations it does not have are left as `—`**). Measured on AMD Ryzen 7
7800X3D / Node 24.15 / Windows 11; reproduce with `pnpm bench`.

| Algorithm | Operation | sm-crypto-wasm | Pure-JS reference (gmkitx) | Ratio |
|---|---|---|---|---|
| SM3 | hash 32 B / 1 KB / 64 KB | 1.04 µs / 6.27 µs / 330 µs | 13.7 µs (1 KB) | 2.2× faster |
| SM3 | hmac 1 KB | 10.1 µs | 17.9 µs | 1.8× faster |
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

## Why it looks like this

- **SM3 / SM4 / ZUC are at the ceiling.** SM3 is MD-chained (blocks cannot be parallelised)
  with a serial 64-round compression function; SM4 and ZUC both hit the **8-bit S-box lookup**,
  and WebAssembly exposes neither ARMv8's `SM4E` nor AES-NI. SM4 briefly tried `v128` SIMD
  and it measured *slower* than 8-way scalar interleaving (four independent dependency chains
  per block, hiding L1 latency via out-of-order execution); that path was removed.
- **SM4's CFB / OFB used to be slower than pure JS** — they called into wasm block-by-block
  (64 crossings per KB). Batch exports brought them to ~10 µs, i.e. 3.6~3.8× faster.
- **SM9 is pairing-dominated.** Moving the base field to a Montgomery domain (CIOS) took one
  modular multiplication from 179 ns to 98 ns and sped up every end-to-end operation by
  **1.6~1.8×**. There is no comparable pure-JS SM9 implementation, so only absolute numbers
  are given.
- **hex codecs mattered**: switching encoding to `Buffer.toString('hex')` (with a lookup-table
  fallback in browsers) is ~27× faster; the input side now validates and parses in one pass.
  Together that made hex-input SM3 / SM4 / ZUC **27~32%** faster end to end.

::: tip Numbers vary by version and machine
Use `pnpm bench` on your own machine. The full experiment log and the "how much room is left"
assessment live in
[`docs/performance-ceiling.md`](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/performance-ceiling.md).
:::

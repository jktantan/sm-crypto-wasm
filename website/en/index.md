---
layout: home

hero:
  name: sm-crypto-wasm
  text: China crypto, compiled to WebAssembly
  tagline: SM2 / SM3 / SM4 / SM9 / ZUC — one API for Node 18+ and modern browsers. Split per algorithm, lazy-loaded on demand.
  image:
    src: /logo.svg
    alt: sm-crypto-wasm
  actions:
    - theme: brand
      text: Quick Start
      link: /en/guide/getting-started
    - theme: alt
      text: Algorithms
      link: /en/algorithms/sm3
    - theme: alt
      text: GitHub
      link: https://github.com/jktantan/sm-crypto-wasm

features:
  - title: An order of magnitude faster
    details: Elliptic curves and bilinear pairings run in WASM. SM4's six modes are 3.6~11.2× faster than a pure-JS reference, SM2 1.8~7.6×, SM3 / ZUC 1.8~2.3×.
  - title: Zero toolchain
    details: The published artifact is .wasm plus a thin TS shim. No node-gyp, no Rust, no compiler for your users.
  - title: Runtime-agnostic
    details: The same API works in Node 18+, modern browsers and Web Workers. Deno / Bun take the Node path.
  - title: Standards-aligned
    details: Implementations follow the GM/T 0003 / 0004 / 0002 / 0044 / 0001 series, cross-validated against official vectors, OpenSSL, GmSSL and gmkitx.
  - title: A Playground per algorithm
    details: Every algorithm page can load the real wasm in your browser, take parameters and show the result — including the exact error type the library throws.
  - title: Input sniffing
    details: hex / base64 / PEM / Uint8Array are detected automatically and output defaults to hex, so you skip a layer of hand-written encoding.
---

## Start here

- **[Installation & Quick Start](/en/guide/getting-started)** — install the package and run your first hash.
- **[SM3](/en/algorithms/sm3)** · **[SM4](/en/algorithms/sm4)** · **[SM2](/en/algorithms/sm2)** · **[SM9](/en/algorithms/sm9)** · **[ZUC](/en/algorithms/zuc)** — one page per algorithm.
- **[Using a Single Algorithm](/en/guide/subpath-imports)** — sub-path imports when bundle size matters.
- **[Error Handling](/en/guide/error-handling)** — key-side vs ciphertext-side failures.
- **[Performance](/en/performance)** — measured numbers for every public operation.

::: info Documentation status
The **Chinese pages are the complete reference** — full parameter tables, usage and live
Playgrounds for all five algorithms. These English pages carry the core material; the
per-algorithm API tables are being translated.
:::

::: tip The shape of this library
Each algorithm is its own namespace exposing `ensureLoaded()` plus business functions.
The wasm is split per algorithm: **only the algorithm you call gets loaded**.
`await algo.ensureLoaded()` once, then every business call is synchronous.
:::

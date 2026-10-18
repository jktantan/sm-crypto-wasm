# sm-crypto-wasm

[简体中文](https://github.com/jktantan/sm-crypto-wasm/blob/main/README.md) · **English** · [Русский](https://github.com/jktantan/sm-crypto-wasm/blob/main/docs/README.ru.md) · [Full documentation](https://jktantan.github.io/sm-crypto-wasm/en/)

An **AssemblyScript → WebAssembly** implementation of Chinese cryptography
standards (**SM2 / SM3 / SM4 / SM9 / ZUC**). Runs on Node 18+ and modern
browsers (including Web Workers). Algorithms are split into sub-packages and
lazy-loaded on demand.

- **Performance**: hot paths (bignum modular arithmetic, hash compression,
  block-cipher rounds) run inside WASM. Compared with the pure-JS reference
  implementation, SM3 is 3.1\~3.5× faster, ZUC 2.3×, the six SM4 modes
  3.6\~11.2×, and SM2 1.8\~7.6× — see **Performance** below;
- **Zero toolchain**: the published artifact is `.wasm` plus a thin TS shim;
  users don't need `node-gyp`, Rust, or a compiler;
- **Runtime-agnostic**: the same API works in Node, browsers, and Workers;
- **Standards-aligned**: implementations follow the GM/T 0003 / 0004 / 0002 /
  0044 / 0001 series and are cross-checked against official vectors using
  OpenSSL / GmSSL / gmkitx.

---

## Performance

Hot paths (bignum modular arithmetic, hash compression, block-cipher rounds,
pairings) run inside WASM. **Every operation with a pure-JS counterpart is faster
than it**: SM3 by 3.1–3.5×, ZUC by 2.3×, the six SM4 modes by 3.6–11.2×,
SM2 by 1.8–7.6×.

The full per-operation table, the head-to-head against `gmkitx`, and the
"why it looks like this" notes live on the
**[performance page](https://jktantan.github.io/sm-crypto-wasm/en/performance)**.
Reproduce locally with `pnpm bench`.

## Installation

```bash
npm install sm-crypto-wasm
# or: pnpm add sm-crypto-wasm / yarn add sm-crypto-wasm
```

Requires Node **>= 18** (browsers must support WebAssembly and
`crypto.getRandomValues`).

---

## Quick Start

> **Call `await algo.ensureLoaded()` once before the first use of each
> algorithm.** Instantiating a WASM module is asynchronous; afterwards every
> business function is synchronous. Only the `.wasm` files you actually use
> are downloaded.

### SM3 — hash & HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                          // '66c7f0f4…8f4ba8e0' — hex input is decoded byte-wise
sm3.hash(new Uint8Array([0x61, 0x62, 0x63])); // same output; byte input is the most ergonomic
sm3.hmac('00112233445566778899aabbccddeeff', '616263');
```

### SM4 — symmetric encryption (ECB / CBC / CTR / CFB / OFB / GCM)

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key   = '0123456789abcdeffedcba9876543210';
const iv    = '000102030405060708090a0b0c0d0e0f';
const msg16 = '00112233445566778899aabbccddeeff';  // 16 bytes
const aad   = 'aabbccdd';                          // additional authenticated data (hex)

sm4.encryptECB(key, msg16);                    // ECB has no padding; input must be a multiple of 16 bytes
sm4.encryptCBC(key, iv, '616263');             // CBC uses PKCS#7 padding; any length is fine
sm4.decryptCBC(key, iv, sm4.encryptCBC(key, iv, '616263'));
sm4.encryptCTR(key, iv, '616263');             // CTR / OFB are stream modes (aliases of cryptCTR / cryptOFB)
const { ct, tag } = sm4.encryptGCM(key, iv, '616263', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);         // throws DecryptionError on auth failure; pass { safeMode: true } to suppress
```

### SM2 — key generation / signature / verification / encryption

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();  // async; returns PKCS#8 / SPKI PEM

const sig = sm2.sign(privateKeyPem, '616263');          // default SM3withSM2; output is r||s as hex
sm2.verify(publicKeyPem, '616263', sig);                // → true

const ct  = sm2.encrypt(publicKeyPem, '616263');                  // default C1C3C2
const ct2 = sm2.encrypt(publicKeyPem, '616263', { outputFormat: 'C1C2C3' });
sm2.decrypt(privateKeyPem, ct);                         // decrypt side auto-detects C1C3C2 / C1C2C3
sm2.decrypt(privateKeyPem, ct, { safeMode: true });     // returns null instead of throwing on failure
```

Keys may also be passed as raw hex / `Uint8Array` (32-byte private key, 64- or
65-byte public key).

### SM2 — key encapsulation & hybrid encryption

```ts
import { sm2 } from 'sm-crypto-wasm';

await sm2.ensureLoaded();

// KEM: protect a random symmetric key with the public key (16 or 32 bytes).
const { key, encapsulation } = sm2.kemEncrypt(publicKeyPem, 32);
sm2.kemDecrypt(privateKeyPem, encapsulation, 32);       // === key

// Hybrid encryption: one call performs KEM + SM4-GCM; suited to large messages.
// Returns a versioned sealed value: version || klen || encapLen || encapsulation || iv || tag || ct
const sealed = sm2.hybridEncrypt(publicKeyPem, '616263');
sm2.hybridDecrypt(privateKeyPem, sealed);               // → '616263' (plaintext hex)

// The sealed value can also be inspected as a self-describing object.
const obj = sm2.sealedToObject(sealed);
sm2.hybridDecrypt(privateKeyPem, sm2.sealedFromObject(obj));
```

- Every `hybridEncrypt` call generates a fresh 16-byte DEK and 12-byte IV; message strings are interpreted as **hex** (pass `new Uint8Array(0)` for an empty message).
- Hybrid uses both `sm2.wasm` and `sm4.wasm`; warm them up with `await Promise.all([sm2.ensureLoaded(), sm4.ensureLoaded()])` before the first call.
- `hybridDecrypt` supports `{ safeMode: true }`, returning `null` for ciphertext-side failures.
- SM2 has no standardized KEM construction; `kemEncrypt` is the conventional "encrypt a random key with SM2" idiom.

### SM2 — key exchange (GM/T 0003.3)

```ts
import { sm2 } from 'sm-crypto-wasm';

const A = await sm2.generateKeyPair();
const B = await sm2.generateKeyPair();

const alice = await sm2.createExchangeInitiator(A.privateKeyPem, B.publicKeyPem, {
  idSelf: 'Alice', idPeer: 'Bob',
});
const bob = await sm2.createExchangeResponder(B.privateKeyPem, A.publicKeyPem, {
  idSelf: 'Bob', idPeer: 'Alice',
});

const r1 = alice.initiate();      // initiator → responder, round 1
const r2 = bob.respond(r1);       // responder → initiator, reply
const r3 = alice.confirm(r2);     // initiator confirmation (carries S_A for the responder to verify)

alice.getSharedKey(r3);           // both sides derive the same shared secret
bob.getSharedKey(r3);
```

### SM9 — sign / encrypt / KEM (GM/T 0044)

```ts
import { sm9 } from 'sm-crypto-wasm';

// SM9 has two master keys (distinguished by purpose): the sign master uses a
// G2 master public key, the encrypt master uses a G1 master public key.
const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });                 // default purpose: 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', '616263');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', '616263', sig);
// The first argument of verify / encrypt also accepts the master private key (legacy shape).

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);      // → '616263'

// Key encapsulation (KEM): negotiate a symmetric key without sending a message.
// Note the first parameter is the *encryption master private key* (KEM needs it to
// derive Ppub-e; encrypt() above can take a master public key instead).
const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);  // === key

// Hybrid encryption: encapsulate a 16-byte DEK with the master public (or private) key + id,
// then encrypt the message with SM4-GCM.
const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, 'alice@foo.com', '616263');
sm9.hybridDecrypt(encKp.masterPrivatePem, 'alice@foo.com', sealed);  // → '616263'
```

> SM9 hybrid uses both `sm9.wasm` and `sm4.wasm`: call `await sm9.ensureLoaded()` and `await sm4.ensureLoaded()` before the first use.

### ZUC — EEA3 confidentiality + EIA3 integrity

```ts
import { zuc } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

zuc.zucKeystream(key, iv, 16);                  // keystream (Uint8Array)
zuc.zucEncrypt(key, iv, '616263');              // EEA3 — each (key, iv, counter) may be encrypted once
zuc.zucDecrypt(key, iv, ct);                    // decryption (exempt from the reuse guard)

// EIA3 integrity tag (32-bit); IV is assembled from COUNT / BEARER / DIRECTION
const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
zuc.zucMac(key, macIv, '616263');               // → 4-byte tag
```

---

### X.509 · CMS · WebCrypto

```ts
import { x509, cms, webcrypto } from 'sm-crypto-wasm';

const cert = x509.parseCertificate(pem);
const signed = cms.signData({ data, privateKey, certificate: cert });
const digest = await webcrypto.subtle.digest('SM3', data);
```

- **X.509** — parsing, single-certificate verification, self-signed / simple CA issuing ([docs](https://jktantan.github.io/sm-crypto-wasm/en/guide/x509));
- **CMS** — detached / attached SignedData, original-DER `signedAttrs` verification, BER ([docs](https://jktantan.github.io/sm-crypto-wasm/en/guide/cms));
- **WebCrypto** — a `subtle`-style subset: SM3 / HMAC(SM3) / SM2 / SM4 ([docs](https://jktantan.github.io/sm-crypto-wasm/en/guide/webcrypto)).

No certificate-chain validation or CRL/OCSP for X.509/CMS; the WebCrypto adapter is not a polyfill of native `crypto.subtle`.

---

## API at a glance

The table lists the main APIs. Every module also exports `ensureLoaded()`; the full
surface is defined by `dist/index.d.ts` or the `.d.ts` file of the corresponding subpath.

| Module | Functions |
|---|---|
| `sm2` | `generateKeyPair` (async) · `getPublicKey` · `sign` · `signWithID` · `verify` · `verifyWithID` · `encrypt` · `decrypt` · `configurePublicKeyCache` · `clearPublicKeyCache` · `preparePublicKey` (async) · `configurePreparedKeyCache` · `clearPreparedPublicKey` · `getPreparedPublicKey` · `clearPreparedPublicKeys` · `getPreparedPublicKeys` · `createSignaturePointPool` (async) · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `webcrypto` | `subtle` · `CryptoKey` |
| `cms` | `signData` · `verifySignedData` · `parseSignedData` · `CmsError` |
| `x509` | `parseCertificate` · `parseCertificates` · `createSelfSignedCertificate` · `issueCertificate` · `parseDistinguishedName` · `verifyCertificateSignature` |
| `sm3` | `hash` · `hmac` |
| `sm4` | `encryptECB` / `decryptECB` · `encryptCBC` / `decryptCBC` · `encryptCTR` / `decryptCTR` · `encryptCFB` / `decryptCFB` · `encryptOFB` / `decryptOFB` · `encryptGCM` / `decryptGCM` |
| `sm9` | `generateKeyPair` (async) · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` · `kemDecrypt` · `hybridEncrypt` · `hybridDecrypt` · `sealedToObject` · `sealedFromObject` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator` (async) · `createExchangeResponder` (async) |
| `zuc` | `zucKeystream` · `zucEncrypt` · `zucDecrypt` · `zucMac` · `zucEia3Iv` · `configureReuseGuard` · `resetReuseGuard` |

Documented aliases (they point to the same implementation):
`sm4.encryptCTR` / `decryptCTR` alias `cryptCTR`,
`encryptOFB` / `decryptOFB` alias `cryptOFB`;
`zuc.encrypt` / `decrypt` / `generateKeystream` / `mac` / `eia3` alias
`zucEncrypt` / `zucDecrypt` / `zucKeystream` / `zucMac`.

---

## Using a single algorithm (sub-path imports)

For size-sensitive scenarios, you can skip the aggregated entry point and
load just the `.wasm` you need:

```ts
import { hash } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

Available sub-paths: `sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/x509` · `/cms` · `/webcrypto` · `/zuc`; there is also `sm-crypto-wasm/esbuild-plugin` (see Bundler support below).

---

## Cross-runtime

| Environment | Loading path |
|---|---|
| Node 18+ | reads `dist/<algo>/<algo>.wasm` via `fs/promises`; `loadWasmSync()` available |
| Browser (via a bundler) | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`; the bundler archives and rewrites it |
| Web Worker | the loader is DOM-free and works inside a Worker |
| Deno / Bun | follows the Node path |
| WeChat built-in browser | same as browsers (`fetch` + `crypto.getRandomValues`); see [WeChat & Mini Programs](https://jktantan.github.io/sm-crypto-wasm/en/guide/wechat) |
| WeChat Mini Program | `WXWebAssembly` + `wx.getRandomValues`; see [WeChat & Mini Programs](https://jktantan.github.io/sm-crypto-wasm/en/guide/wechat) |

### Bundler support

The package ships two implementations (a Node one reading files, a browser one
using `fetch`) and `package.json`'s `browser` field switches between them at
build time. So **`node:*` never appears in a browser bundle** — bundlers that do
not externalise node built-ins (Webpack, esbuild, Rspack) no longer fail at
resolve time with `Can't resolve 'node:fs'`.

| Bundler | Configuration | wasm asset |
|---|---|---|
| **Vite 5** | none | archived into the output (`assets/*.wasm`) |
| **Webpack 5** | none | emitted as an asset |
| **Rspack 2** | none | emitted as an asset (hashed filenames) |
| **Turbopack** (Next.js 16 default) | none | archived under `static/media/*.wasm` |
| **esbuild** | one plugin line (below) | esbuild does not handle files pointed at by `new URL(..., import.meta.url)` |
| **Node 18+** | none | reads `dist/<algo>/<algo>.wasm` |

esbuild users add a small bundled plugin that drops the wasm where the runtime looks for it:

```ts
import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outdir: 'dist/assets',        // output JS lands here
  plugins: [smCryptoWasm()],    // → wasm copied to dist/<algo>/<algo>.wasm
});
```

Prefer no plugin? Copy `node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc}`
into the **parent** directory of the output JS (i.e. `dist/` in the example above).

Browsers need a **secure context** (`https://` or `localhost`) for
`crypto.getRandomValues`; when it is missing the library **throws** (fail-closed)
rather than falling back to a non-cryptographic source.

Strict-streaming WASM environments such as Cloudflare Workers / Vercel Edge are
**out of scope**; so is loading the raw ESM output directly via
`<script type="module">` (without a bundler).

---

## Error handling

All "rejected because of input" errors are subclasses of `SmCryptoError`, in
two branches:

```ts
import { SmCryptoError, InvalidKeyError, InvalidPublicKeyError,
         CiphertextError, InvalidCiphertextError, DecryptionError } from 'sm-crypto-wasm';

try {
  sm2.decrypt(priv, ct);
} catch (e) {
  if (e instanceof DecryptionError) { /* ciphertext / key mismatch */ }
  else if (e instanceof CiphertextError) { /* structure or validation issue */ }
  else if (e instanceof InvalidKeyError) { /* key format / length / curve */ }
  else throw e;
}
```

- Key branch: `InvalidKeyError` (with `InvalidPublicKeyError` as a subclass);
- Ciphertext branch: `CiphertextError` (with `InvalidCiphertextError` for
  structural errors and `DecryptionError` for validation failures);
- Type or range problems (e.g. length caps, invalid enum values) keep the
  host's native `TypeError` / `RangeError`.

---

## Security notes

- **The library uses only the host's RNG**: `crypto.getRandomValues`
  (browsers / Node 19+) or the Node 18 `node:crypto` shim. **No RNG is
  implemented inside the library.**
- **No disk writes, no logs of private keys**: the library never serializes
  keys to disk or to logs.
- **ZUC reuse guard**: encrypting twice with the same `(key, iv, counter)`
  throws (keystream reuse is a confidentiality breach). If you manage the
  counter yourself, you can disable the guard globally with
  `configureReuseGuard({ enabled: false })` or per call via `{ reuseGuard: false }`.
- **SM2 public-key validity**: `encrypt` throws `InvalidPublicKeyError` for
  points not on the curve; `verify` simply returns `false`.
- No integration with crypto hardware / HSM / PKCS#11 / soft-cert handles;
  no key parsing outside PEM.

---

## Development

```bash
pnpm install
pnpm build          # clean + asc (5 .wasm files) + tsc → dist/ (no source maps)
pnpm build:ts:debug # for debugging: recompile TS to dist/ with .js.map / .d.ts.map
pnpm test           # build wasm + Node tests (vitest)
pnpm test:browser   # build wasm + browser runner (happy-dom)
pnpm bench          # mitata micro-benchmarks (5 algorithm blocks)
pnpm lint           # biome (lint + format)
pnpm typecheck      # tsc --noEmit
```

`pnpm build` is the release path: it empties `dist/` first, and `tsconfig.build.json` turns off
`sourceMap` / `declarationMap`, so the output carries neither `.map` files nor
`//# sourceMappingURL=` comments. The reason: the published package ships only `dist/`, while a
map's `sources` point at `../src/*.ts`, which is not published (and the maps embed no
`sourcesContent`) — downstream can neither read the sources nor jump to definitions, yet pays
roughly 35% extra size for it. For in-repo debugging use `pnpm build:ts:debug`
(`tsconfig.build.debug.json`), which emits maps into `dist/`.

**Every wasm module is built with `--optimize` only, no `--enable simd`**: SM4's speed
comes from scalar multi-block interleaving and depends on no SIMD instruction set. All
five algorithm modules therefore share the same runtime requirements, and `sm4.wasm`
no longer requires **WASM SIMD**.

Files under `src/**/assembly/**` are AssemblyScript sources compiled by
`asc`. **Do not** use `import { type X }` in those files or let the
formatter reorder imports — `asc` 0.28 doesn't recognize the type modifier
(those rules are already turned off for the directory in the biome config).

Each `src/*/assembly/` directory contains a single-line `tsconfig.json`
that just `extends` the root `tsconfig.assembly.json`. It pulls in the AS
type definitions **only so that IDEs type-check these files with AS
semantics** — otherwise editing them reports `TS2304` for things like
`usize`, `u32`, `StaticArray`. The root `tsconfig.json` `exclude`s the
directory, so the CLI `tsc` doesn't touch them; these per-directory
configs don't affect the build or typecheck.

---

## Contributing

Issues and pull requests are welcome. See
[CONTRIBUTING.md](https://github.com/jktantan/sm-crypto-wasm/blob/main/CONTRIBUTING.md)
for the development setup, test commands and PR expectations. Report security
issues through the channel described in
[SECURITY.md](https://github.com/jktantan/sm-crypto-wasm/blob/main/SECURITY.md).

Before submitting, run:

```bash
pnpm lint && pnpm typecheck && pnpm test:unit
```

---

## License

[Apache-2.0](../LICENSE).

The algorithm implementations in this project reference or are ported from
the following Apache-2.0 projects; attribution details are in [`NOTICE`](../NOTICE):

- [GmSSL](https://github.com/guanzhi/GmSSL) — the alignment baseline for
  SM2 / SM9 semantics and naming;
- [gmkit / gmkitx](https://github.com/gmkits/gmkit) — the source the ZUC
  implementation was ported from.


# Installation & Quick Start

## Install

```bash
pnpm add sm-crypto-wasm
# or
npm i sm-crypto-wasm
# or
yarn add sm-crypto-wasm
```

Requires **Node >= 18**; browsers need WebAssembly and `crypto.getRandomValues`.
The package ships `.wasm` plus a thin TS shim — **no `node-gyp`, Rust or compiler needed**.

## The async boundary: `ensureLoaded()` first

Each algorithm is its own namespace exposing an **`ensureLoaded()`**:

```ts
import { sm3, sm4 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();   // warm up before first use
sm3.hash('616263');         // every call after this is synchronous
```

WASM instantiation is asynchronous; every business function after it is synchronous.
Because the wasm is **split per algorithm**, `sm4.wasm` is only downloaded when you
`await sm4.ensureLoaded()` — algorithms you never touch cost nothing.

Repeated `ensureLoaded()` calls are cheap: module-level memoisation, concurrent callers
share one Promise.

## All five algorithms, briefly

### SM3 — hash & HMAC

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');                                     // 32-byte digest as hex
sm3.hash(new TextEncoder().encode('abc'));              // same, text via explicit UTF-8
sm3.hmac('00112233445566778899aabbccddeeff', '616263'); // HMAC-SM3
```

### SM4 — symmetric encryption

```ts
import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
const key = '0123456789abcdeffedcba9876543210';
const iv  = '000102030405060708090a0b0c0d0e0f';

sm4.encryptCBC(key, iv, 'hello');                        // PKCS#7 padded, any length
const { ct, tag } = sm4.encryptGCM(key, iv, 'hello', 'aad');
sm4.decryptGCM(key, iv, ct, tag, 'aad');                 // throws DecryptionError on tampering
```

### SM2 — signature / encryption

```ts
import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

const sig = sm2.sign(privateKeyPem, 'abc');              // SM3withSM2
sm2.verify(publicKeyPem, 'abc', sig);                    // → true

const ct = sm2.encrypt(publicKeyPem, 'abc');             // C1C3C2 by default
sm2.decrypt(privateKeyPem, ct);                          // order auto-detected
```

### SM9 — identity-based cryptography

```ts
import { sm9 } from 'sm-crypto-wasm';

const id = 'alice@example.com';
const signKp = await sm9.generateKeyPair({ id });            // purpose defaults to 'sign'
const encKp  = await sm9.generateKeyPair({ id, purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, id, 'abc');
sm9.verify(signKp.masterPublicPem, id, 'abc', sig);

const ct = sm9.encrypt(encKp.masterPublicPem, id, 'abc');
sm9.decrypt(encKp.masterPrivatePem, id, ct);
```

### ZUC — EEA3 / EIA3

```ts
import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
const key = '000102030405060708090a0b0c0d0e0f';
const iv  = '00000000000000000000000000000000';

const ct = zuc.zucEncrypt(key, iv, 'abc', 0);            // returns Uint8Array
zuc.zucDecrypt(key, iv, ct, 0);

const macIv = zuc.zucEia3Iv(0x66035492, 0x0f, 0);
bytesToHex(zuc.zucMac(key, macIv, 'abc'));               // 4-byte tag
```

## Input / output conventions

| Direction | Convention |
| --- | --- |
| String input | Sniffed in the order **PEM → hex → base64**; `Uint8Array` is used as-is |
| Output (SM2 / SM3 / SM4 / SM9) | lowercase **hex** |
| Output (ZUC) | **`Uint8Array`** (ZUC's four main functions) |
| Keys | Strings are sniffed; **there is no "UTF-8 text key"** |

## Next

- Bundle-size sensitive? See [**Using a Single Algorithm**](/en/guide/subpath-imports).
- Browsers / Workers? See [**Cross-runtime**](/en/guide/cross-runtime).
- Hit an exception? See [**Error Handling**](/en/guide/error-handling).

# Using a Single Algorithm

The aggregate entry `import { ... } from 'sm-crypto-wasm'` hangs all five namespaces off the
import, though the wasm is still loaded on demand. When bundle size matters, import the
sub-path instead:

```ts
import { hash, hmac } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

Available sub-paths: `sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/zuc`.

|  | Aggregate entry | Sub-path |
| --- | --- | --- |
| Bundle: algorithms you never import | depends on the bundler | **tree-shaken away** |
| Error classes / codec helpers | immediately available | import from `sm-crypto-wasm` |
| wasm loading | lazy per `ensureLoaded()` | same |

::: tip
The **wasm is always lazy per algorithm** — a sub-path import saves JS glue, not `.wasm`.
Each `.wasm` is only requested when that algorithm's `ensureLoaded()` is awaited.
:::

Error classes and codec helpers always come from the root entry:

```ts
import { DecryptionError, bytesToHex } from 'sm-crypto-wasm';
import { zucMac, zucEia3Iv } from 'sm-crypto-wasm/zuc';
```

::: info Full reference
The [Chinese page](/guide/subpath-imports) has the complete per-sub-path export listing.
:::

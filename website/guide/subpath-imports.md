# 只用一个算法（子路径导入）

聚合入口 `import { ... } from 'sm-crypto-wasm'` 会把五个命名空间都挂上，尽管 wasm
仍然是按需加载。体积敏感的场景（比如页面里只做 SM3 摘要）可以直接走子路径：

```ts
import { hash, hmac } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

## 可用子路径

| 子路径 | 导出 |
| --- | --- |
| `sm-crypto-wasm/sm2` | `ensureLoaded` · `generateKeyPair` · `getPublicKey` · `sign` · `verify` · `encrypt` · `decrypt` · `createExchangeInitiator` · `createExchangeResponder` · `configurePublicKeyCache` · `clearPublicKeyCache` |
| `sm-crypto-wasm/sm3` | `ensureLoaded` · `hash` · `hmac` |
| `sm-crypto-wasm/sm4` | `ensureLoaded` · `encryptECB` / `decryptECB` · `encryptCBC` / `decryptCBC` · `encryptCTR` / `decryptCTR` · `encryptCFB` / `decryptCFB` · `encryptOFB` / `decryptOFB` · `encryptGCM` / `decryptGCM` |
| `sm-crypto-wasm/sm9` | `ensureLoaded` · `generateKeyPair` · `sign` · `verify` · `encrypt` · `decrypt` · `kemEncrypt` / `kemDecrypt` · `getSignPublicKey` · `getEncPublicKey` · `getUserPublicKey` · `createExchangeInitiator` / `createExchangeResponder` |
| `sm-crypto-wasm/zuc` | `ensureLoaded` · `zucKeystream` · `zucEncrypt` / `zucDecrypt` · `zucMac` · `zucEia3Iv` · `configureReuseGuard` / `resetReuseGuard` |

## 两种入口的区别

| | 聚合入口 | 子路径 |
| --- | --- | --- |
| 打包器能否 tree-shake 掉未用到的算法 | 取决于打包器 | **能**，没 import 的模块不会进包 |
| 错误类型 / 编解码工具 | 直接可用（`SmCryptoError`、`bytesToHex` …） | 需要再 `import ... from 'sm-crypto-wasm'` |
| wasm 加载 | 按 `ensureLoaded()` 的算法懒加载 | 同左 |

::: tip 注意
**wasm 永远是按算法懒加载的** —— 子路径导入省下的是 JS 胶水层，不是 `.wasm`。
`.wasm` 只在对应算法的 `ensureLoaded()` 被 `await` 时才请求。
:::

错误类型与编解码工具（`SmCryptoError` / `bytesToHex` / `hexToBytes` / `loadWasm`）始终
从根入口导入：

```ts
import { DecryptionError, bytesToHex } from 'sm-crypto-wasm';
import { zucMac, zucEia3Iv } from 'sm-crypto-wasm/zuc';
```

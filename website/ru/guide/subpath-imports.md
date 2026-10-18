# Один алгоритм

Агрегированный вход `import { ... } from 'sm-crypto-wasm'` подключает все пять пространств
имён, хотя wasm всё равно загружается по требованию. Когда важен размер бандла, используйте
подпуть:

```ts
import { hash, hmac } from 'sm-crypto-wasm/sm3';
import { encryptCBC } from 'sm-crypto-wasm/sm4';
```

Доступные подпути: `sm-crypto-wasm/sm2` · `/sm3` · `/sm4` · `/sm9` · `/x509` · `/cms` · `/webcrypto` · `/zuc`.

|  | Агрегированный вход | Подпуть |
| --- | --- | --- |
| Бандл: неиспользуемые алгоритмы | зависит от сборщика | **удаляются tree-shaking** |
| Классы ошибок / кодеки | доступны сразу | импорт из `sm-crypto-wasm` |
| Загрузка wasm | ленивая по `ensureLoaded()` | так же |

::: tip
**wasm всегда ленивый по алгоритму** — подпуть экономит JS-обвязку, а не `.wasm`.
Каждый `.wasm` запрашивается только при `await` соответствующего `ensureLoaded()`.
:::

```ts
import { DecryptionError, bytesToHex } from 'sm-crypto-wasm';
import { zucMac, zucEia3Iv } from 'sm-crypto-wasm/zuc';
```

::: info Полный справочник
Полный список экспортов по подпутям — на [китайской странице](/guide/subpath-imports).
:::

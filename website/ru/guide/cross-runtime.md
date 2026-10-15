# Среды выполнения

Один и тот же API работает в Node, браузерах и Web Worker. Разница только в том, **откуда
`ensureLoaded()` берёт байты `.wasm`**:

| Среда | Путь загрузки |
| --- | --- |
| **Node 18+** | `node:fs/promises` читает `dist/<algo>/<algo>.wasm`; доступен `loadWasmSync()` |
| **Браузеры / Vite / Webpack / Rollup** | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`, URL переписывает сборщик |
| **Web Worker** | загрузчик не зависит от DOM, работает как есть |
| **Deno / Bun** | идут по пути Node (оба предоставляют `node:fs`) |

## Браузер

Создание экземпляра WASM асинхронно, поэтому **всегда `await ensureLoaded()`** до первого
вызова:

```ts
import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();
sm3.hash('616263');
```

Сборщик должен разрешать `new URL(..., import.meta.url)`. Vite, Webpack 5 и Rollup это умеют.

## Node

```ts
import { loadWasm, loadWasmSync } from 'sm-crypto-wasm';

await loadWasm('sm3');            // прогрев (мемоизация)
const mod = loadWasmSync('sm3');  // синхронный доступ, только Node
```

`loadWasmSync` в браузере бросает ошибку — там нужен `await loadWasm()`.

## Конкурентность

`loadWasm()` / `ensureLoaded()` мемоизированы: конкурентные вызовы делят один Promise,
`.wasm` не создаётся дважды.

## Вне области

Среды «строго потокового WASM» (**Cloudflare Workers / Vercel Edge**) не поддерживаются —
их модель загрузки модулей несовместима с `WebAssembly.instantiate(ArrayBuffer)`.

::: info Полный справочник
[Китайская страница](/guide/cross-runtime) содержит тот же материал и пример для Worker.
:::

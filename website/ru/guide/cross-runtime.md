# Среды выполнения

Один и тот же API работает в Node, браузерах и Web Worker. Разница только в том, **откуда
`ensureLoaded()` берёт байты `.wasm`**:

| Среда | Путь загрузки |
| --- | --- |
| **Node 18+** | `node:fs/promises` читает `dist/<algo>/<algo>.wasm`; доступен `loadWasmSync()` |
| **Браузеры (через сборщик)** | `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))`, файл кладёт в вывод и URL переписывает сборщик |
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

### Поддержка сборщиков

Пакет поставляет **две реализации** (Node-версия читает файлы, браузерная использует
`fetch`), а `browser`-поле в `package.json` переключает их на этапе сборки. Практическое
следствие: **`node:*` не попадает в браузерный бандл**, поэтому сборщики, которые не
выносят встроенные модули Node наружу — Webpack, esbuild, Rspack — больше не падают на
этапе разбора с `Can't resolve 'node:fs'`.

| Сборщик | Нужна настройка? | Ресурс wasm |
| --- | --- | --- |
| **Vite 5** | нет | автоматически попадает в вывод (`assets/*.wasm`) |
| **Webpack 5** | нет | автоматически выдаётся как asset |
| **esbuild** | нужно скопировать wasm вручную (ниже) | esbuild не обрабатывает файлы, на которые указывает `new URL(..., import.meta.url)` |
| **Node 18+** | нет | читает `dist/<algo>/<algo>.wasm` |

> Браузеру нужен **защищённый контекст** (`https://` или `localhost`), чтобы получить
> `crypto.getRandomValues`. Если его нет, библиотека **бросает ошибку** (fail-closed) и
> **не** откатывается к некриптографическому источнику.

#### esbuild: скопируйте wasm сами

esbuild не переносит файлы, на которые указывает `new URL('../<algo>/<algo>.wasm',
import.meta.url)`, в вывод (ни `--outfile`, ни `--outdir`). Выходному JS нужен
`<algo>/<algo>.wasm` в его **родительском** каталоге:

```bash
# вывод в dist/assets/ → во время работы разрешается ../<algo>/<algo>.wasm → dist/<algo>/<algo>.wasm
esbuild src/main.ts --bundle --platform=browser --format=esm --outdir=dist/assets
cp -r node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc} dist/
```

Копируйте только используемые алгоритмы (например, `cp -r node_modules/sm-crypto-wasm/dist/sm3 dist/`).

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

- Среды «строго потокового WASM» (**Cloudflare Workers / Vercel Edge**) не поддерживаются —
  их модель загрузки модулей несовместима с `WebAssembly.instantiate(ArrayBuffer)`.
- Загрузка «сырого» ESM напрямую через `<script type="module">` не поддерживается: стороне
  Node нужны `node:*`, поэтому один сборник без бандлера не может обслужить обе. Используйте
  сборщик из таблицы выше.

::: info Полный справочник
[Китайская страница](/guide/cross-runtime) содержит тот же материал и пример для Worker.
:::

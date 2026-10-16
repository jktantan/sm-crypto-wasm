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
| **Vite 5** | нет | попадает в вывод (`assets/*.wasm`) |
| **Webpack 5** | нет | выдаётся как asset |
| **Rspack 2** | нет | выдаётся как asset (имена с hash) |
| **Turbopack** (по умолчанию в Next.js 16) | нет | попадает в `static/media/*.wasm` |
| **esbuild** | одна строка плагина (ниже) | esbuild не обрабатывает файлы, на которые указывает `new URL(..., import.meta.url)` |
| **Node 18+** | нет | читает `dist/<algo>/<algo>.wasm` |

> Браузеру нужен **защищённый контекст** (`https://` или `localhost`), чтобы получить
> `crypto.getRandomValues`. Если его нет, библиотека **бросает ошибку** (fail-closed) и
> **не** откатывается к некриптографическому источнику.

#### esbuild: одна строка плагина

esbuild не переносит файлы, на которые указывает `new URL('../<algo>/<algo>.wasm',
import.meta.url)`, в вывод (ни `--outfile`, ни `--outdir`). Этот шаг закрывает небольшой
встроенный плагин:

```ts
import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'browser',
  format: 'esm',
  outdir: 'dist/assets',        // сюда попадает выходной JS
  plugins: [smCryptoWasm()],    // → wasm копируется в dist/<algo>/<algo>.wasm
});
```

Плагин кладёт wasm туда же, откуда его берёт рантайм (каталог `<algo>/` внутри
**родительского** каталога выходного JS). Указывайте `outdir` на подкаталог (например,
`dist/assets`), чтобы wasm попал в `dist/<algo>/`, а не на уровень выше выходного каталога.
Передайте `algorithms: ['sm3']`, чтобы копировать меньше.

Без плагина? Скопируйте `node_modules/sm-crypto-wasm/dist/{sm2,sm3,sm4,sm9,zuc}` в
**родительский** каталог выходного JS (`dist/` в примере выше).

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

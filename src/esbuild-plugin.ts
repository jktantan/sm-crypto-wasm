/**
 * esbuild 插件：把 `.wasm` 资源放到浏览器产物**运行时能解析到的位置**。
 *
 * ## 为什么需要它
 *
 * 浏览器版的加载器用 `fetch(new URL('../<algo>/<algo>.wasm', import.meta.url))` 取
 * wasm（这个写法 Vite 与 Webpack 5 都会自动归档资源并重写 URL）。**esbuild 不会** ——
 * 无论 `--outfile` 还是 `--outdir`，它都不搬 `new URL` 指向的文件（实测 0.28.2）。
 * 结果：构建能过，运行时 `fetch` 404。
 *
 * 本插件在 build 结束后把 `dist/<algo>/<algo>.wasm` 复制到该相对位置：
 * 运行时 URL 是相对**产物 JS 文件**的 `../<algo>/<algo>.wasm`，所以目标基目录是
 * **产物 JS 所在目录的上级**（由 esbuild 的 `outdir` / `outfile` 推导）。
 *
 * ## 用法
 *
 * ```ts
 * import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';
 *
 * await esbuild.build({
 *   entryPoints: ['src/main.ts'],
 *   bundle: true,
 *   platform: 'browser',
 *   format: 'esm',
 *   outdir: 'dist/assets',        // 产物 JS 落这里
 *                                 // output JS goes here
 *   plugins: [smCryptoWasm()],    // → wasm 复制到 dist/<algo>/<algo>.wasm
 *                                 // copies wasm to dist/<algo>/<algo>.wasm
 * });
 * ```
 *
 * 建议把 `outdir` 指到子目录（如 `dist/assets`），这样 wasm 落在 `dist/<algo>/` 而不是
 * 产物目录的上级。
 *
 * 只需用到部分算法时传 `algorithms` 少复制几个。
 *
 * esbuild plugin: place the `.wasm` assets **where the runtime can resolve them** in a
 * browser bundle.
 *
 * ## Why it is needed
 *
 * The browser loader fetches wasm with `fetch(new URL('../<algo>/<algo>.wasm',
 * import.meta.url))` (a form both Vite and Webpack 5 understand: they archive the asset
 * and rewrite the URL). **esbuild does not** — neither `--outfile` nor `--outdir` moves
 * the file that `new URL` points at (measured on 0.28.2). Result: the build succeeds and
 * `fetch` 404s at runtime.
 *
 * After the build finishes this plugin copies `dist/<algo>/<algo>.wasm` to that relative
 * location: the runtime URL is `../<algo>/<algo>.wasm` relative to **the emitted JS
 * file**, so the target base directory is **the parent of the directory holding the
 * emitted JS** (derived from esbuild's `outdir` / `outfile`).
 *
 * ## Usage
 *
 * ```ts
 * import { smCryptoWasm } from 'sm-crypto-wasm/esbuild-plugin';
 *
 * await esbuild.build({
 *   entryPoints: ['src/main.ts'],
 *   bundle: true,
 *   platform: 'browser',
 *   format: 'esm',
 *   outdir: 'dist/assets',        // the emitted JS lands here
 *   plugins: [smCryptoWasm()],    // → wasm is copied to dist/<algo>/<algo>.wasm
 * });
 * ```
 *
 * Pointing `outdir` at a subdirectory (e.g. `dist/assets`) is recommended so the wasm
 * lands in `dist/<algo>/` instead of the parent of the output directory.
 *
 * Pass `algorithms` when only some algorithms are used, to copy fewer files.
 */

import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** 支持的算法名（与加载器白名单一致）。
 *
 * Supported algorithm names (in sync with the loader allow-list).
 */
const WASM_ALGOS = ['sm2', 'sm3', 'sm4', 'sm9', 'zuc'] as const;
/** 白名单里的算法名类型（由 `WASM_ALGOS` 推导，选项与复制循环都受它约束）。
 *
 * The type of the names in the allow-list (derived from `WASM_ALGOS`; both the option
 * type and the copy loop are constrained by it).
 */
export type WasmAlgo = (typeof WASM_ALGOS)[number];

/** `smCryptoWasm()` 的选项。
 *
 * Options for `smCryptoWasm()`.
 */
export interface SmCryptoWasmPluginOptions {
  /** 只复制这些算法的 wasm（默认全部 5 个）。
   *
   * Only copy the wasm of these algorithms (all 5 by default).
   */
  algorithms?: readonly WasmAlgo[];
  /** wasm 目标基目录。默认由 esbuild 的 `outdir` / `outfile` 推导（见模块注释）。
   *
   * Base directory for the wasm output. Defaults to a value derived from esbuild's
   * `outdir` / `outfile` (see the module comment).
   */
  outDir?: string;
  /** wasm 源目录。默认本包的 `dist/`（插件自身所在目录）。
   *
   * Source directory of the wasm. Defaults to this package's `dist/` (the directory
   * the plugin itself lives in).
   */
  sourceDir?: string;
}

/**
 * esbuild 插件的**最小**结构。刻意不依赖 `esbuild` 的类型：这样本包不必把 esbuild
 * 列为依赖，也不会因 esbuild 主版本升级而影响类型。
 *
 * The **minimal** shape of an esbuild plugin. It deliberately does not depend on
 * `esbuild`'s types, so this package need not list esbuild as a dependency and a major
 * esbuild upgrade cannot affect its types.
 */
export interface SmCryptoWasmPlugin {
  name: string;
  setup(build: {
    initialOptions: { outdir?: string; outfile?: string };
    onEnd: (cb: (result: { errors: readonly unknown[] }) => void | Promise<void>) => void;
  }): void;
}

/** 本包 `dist/` 的位置（编译后插件自身就在 `dist/` 下）。
 *
 * Location of this package's `dist/` (once compiled, the plugin itself lives under
 * `dist/`).
 */
const THIS_DIST_DIR = dirname(fileURLToPath(import.meta.url));

/**
 * 推导 wasm 的目标基目录。
 *
 * 运行时相对**产物 JS 文件**解析 `../<algo>/<algo>.wasm`，所以目标是产物 JS 目录的上级。
 * esbuild 通常把入口产物放在 `outdir` 根（单入口时 `outbase` 就是入口所在目录）。
 *
 * Derive the base directory for the wasm output.
 *
 * At runtime `../<algo>/<algo>.wasm` is resolved relative to **the emitted JS file**, so
 * the target is the parent of the emitted JS directory. esbuild usually puts the entry
 * output at the root of `outdir` (with a single entry, `outbase` is the entry's own
 * directory).
 */
function resolveTargetBase(opts: { outdir?: string; outfile?: string }): string | undefined {
  if (opts.outdir) return resolve(opts.outdir, '..');
  if (opts.outfile) return resolve(dirname(opts.outfile), '..');
  return undefined;
}

/**
 * 创建 esbuild 插件：build 成功后复制 wasm 资源。
 *
 * @param options 见 {@link SmCryptoWasmPluginOptions}。
 * @returns 可直接放进 `plugins` 数组的插件对象。
 *
 * Create the esbuild plugin: copy the wasm assets after a successful build.
 *
 * @param options See {@link SmCryptoWasmPluginOptions}.
 * @returns A plugin object that can be placed directly in the `plugins` array.
 */
export function smCryptoWasm(options: SmCryptoWasmPluginOptions = {}): SmCryptoWasmPlugin {
  const algos = options.algorithms ?? WASM_ALGOS;
  const sourceDir = options.sourceDir ?? THIS_DIST_DIR;

  return {
    name: 'sm-crypto-wasm-assets',
    setup(build) {
      build.onEnd((result) => {
        // 构建失败时不产出资源，避免留下半套产物。
        //
        // Emit no assets when the build failed, so no half-written output is left behind.
        if (result.errors.length > 0) return;

        const targetBase = options.outDir ?? resolveTargetBase(build.initialOptions);
        // `write: false` 等场景：没有落盘位置
        //
        // Cases such as `write: false`: there is no location to write to.
        if (targetBase === undefined) return;

        for (const algo of algos) {
          const from = join(sourceDir, algo, `${algo}.wasm`);
          // 只装了部分算法时静默跳过。
          //
          // Silently skip algorithms that were not installed.
          if (!existsSync(from)) continue;
          const to = join(targetBase, algo, `${algo}.wasm`);
          mkdirSync(dirname(to), { recursive: true });
          copyFileSync(from, to);
        }
      });
    },
  };
}

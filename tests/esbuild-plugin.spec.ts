import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { smCryptoWasm } from '@/esbuild-plugin';

/**
 * esbuild 插件：把 wasm 复制到运行时 `new URL('../<algo>/<algo>.wasm', import.meta.url)`
 * 能解析到的位置 —— 即**产物 JS 所在目录的上级**。
 *
 * 用临时目录 + 假的 `initialOptions` 驱动，不真的调 esbuild。
 */

const ALGOS = ['sm2', 'sm3', 'sm4', 'sm9', 'zuc'] as const;

/** 触发插件的 `onEnd`（errors 默认空 = 构建成功）。 */
function runOnEnd(
  plugin: { setup: (b: unknown) => void },
  initialOptions: Record<string, unknown>,
  errors: unknown[] = [],
): void {
  let handler: ((r: { errors: readonly unknown[] }) => unknown) | undefined;
  plugin.setup({
    initialOptions,
    onEnd: (cb: (r: { errors: readonly unknown[] }) => unknown) => {
      handler = cb;
    },
  });
  handler?.({ errors });
}

describe('esbuild 插件：wasm 资源复制', () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sm-esb-plugin-'));
    // 铺一个假 dist/：dist/<algo>/<algo>.wasm
    for (const a of ALGOS) {
      mkdirSync(join(root, 'dist', a), { recursive: true });
      writeFileSync(join(root, 'dist', a, `${a}.wasm`), `wasm-${a}`);
    }
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  const srcDir = () => join(root, 'dist');

  it('按 outdir 复制到「上级目录/<algo>/」——与运行时 ../<algo>/ 对齐', () => {
    const plugin = smCryptoWasm({ sourceDir: srcDir() });
    runOnEnd(plugin, { outdir: join(root, 'out', 'assets') });

    for (const a of ALGOS) {
      const p = join(root, 'out', a, `${a}.wasm`);
      expect(existsSync(p), `${a} 应被复制到 ${p}`).toBe(true);
      expect(readFileSync(p, 'utf8')).toBe(`wasm-${a}`);
    }
  });

  it('outfile 形式同样推导到产物 JS 的上级', () => {
    const plugin = smCryptoWasm({ sourceDir: srcDir(), algorithms: ['sm3'] });
    runOnEnd(plugin, { outfile: join(root, 'out', 'assets', 'main.js') });

    expect(readFileSync(join(root, 'out', 'sm3', 'sm3.wasm'), 'utf8')).toBe('wasm-sm3');
  });

  it('algorithms 只复制指定的算法', () => {
    const plugin = smCryptoWasm({ sourceDir: srcDir(), algorithms: ['sm2', 'sm3'] });
    runOnEnd(plugin, { outdir: join(root, 'out') }); // targetBase = root

    expect(existsSync(join(root, 'sm2', 'sm2.wasm'))).toBe(true);
    expect(existsSync(join(root, 'sm3', 'sm3.wasm'))).toBe(true);
    expect(existsSync(join(root, 'sm9', 'sm9.wasm'))).toBe(false);
    expect(existsSync(join(root, 'zuc', 'zuc.wasm'))).toBe(false);
  });

  it('outDir 选项覆盖推导结果', () => {
    const plugin = smCryptoWasm({
      sourceDir: srcDir(),
      outDir: join(root, 'custom'),
      algorithms: ['zuc'],
    });
    runOnEnd(plugin, { outdir: join(root, 'out') });

    expect(existsSync(join(root, 'custom', 'zuc', 'zuc.wasm'))).toBe(true);
    // 由 outdir 推导出的位置（root/）不应被写入
    expect(existsSync(join(root, 'zuc', 'zuc.wasm'))).toBe(false);
  });

  it('构建失败（errors 非空）时不产出任何资源', () => {
    const plugin = smCryptoWasm({ sourceDir: srcDir() });
    runOnEnd(plugin, { outdir: join(root, 'out', 'assets') }, [{ text: 'boom' }]);

    expect(existsSync(join(root, 'out'))).toBe(false);
  });

  it('既没有 outdir 也没有 outfile 时静默跳过（如 write:false）', () => {
    const plugin = smCryptoWasm({ sourceDir: srcDir() });
    expect(() => runOnEnd(plugin, {})).not.toThrow();
  });
});

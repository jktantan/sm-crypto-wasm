import { fileURLToPath } from 'node:url';
import { defineConfig, type DefaultTheme } from 'vitepress';

/**
 * sm-crypto-wasm 文档站（VitePress）。
 *
 * 站点独立在 `website/`，与仓库里的 `docs/`（开发过程文档：spec / plan /
 * performance-ceiling）互不干扰。运行：
 *   pnpm docs:dev      # 本地预览（含热更新）
 *   pnpm docs:build    # 产物在 website/.vitepress/dist
 *   pnpm docs:preview  # 预览构建产物
 *
 * 三语：中文（root）/ English（/en/）/ Русский（/ru/）。
 */

const REPO = 'https://github.com/jktantan/sm-crypto-wasm';
/** GitHub Pages 的站点挂在仓库子路径下，base 必须与之一致。 */
const BASE = '/sm-crypto-wasm/';

/** 仓库根（本文件位于 `website/.vitepress/`）。 */
const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const distDir = `${repoRoot}dist/`;
const wasmLoaderShim = fileURLToPath(new URL('./theme/wasmLoader.ts', import.meta.url));
const nodeCryptoShim = fileURLToPath(new URL('./theme/shims/node-crypto.ts', import.meta.url));

/**
 * Vite 插件：把库内部的 `runtime/loadWasm.js` 换成本站的加载器。
 *
 * 为什么需要：库的浏览器分支用 `fetch(new URL(\`../${name}/${name}.wasm\`, import.meta.url))`
 * 定位 wasm —— 这个 URL 是运行时拼出来的，打包器无法静态分析，在 VitePress 的
 * 产物布局（chunk 落在 `assets/` 下）里会 404。换成本站的 shim 后，wasm 由
 * Vite 的 `?url` 静态导入（同一份 `dist/*.wasm`），URL 由构建期确定。
 *
 * 只对来自本项目 `dist/` 的导入生效，不影响任何其他模块。
 */
function wasmLoaderShimPlugin() {
  return {
    name: 'sm-crypto-wasm:wasm-loader-shim',
    enforce: 'pre' as const,
    resolveId(source: string, importer?: string) {
      if (!importer || !importer.startsWith(distDir)) return null;
      if (!/runtime[/\\]loadWasm\.js$/.test(source)) return null;
      return wasmLoaderShim;
    },
  };
}

const zhNav: DefaultTheme.NavItem[] = [
  { text: '指南', link: '/guide/', activeMatch: '^/guide/' },
  { text: '算法', link: '/algorithms/sm3', activeMatch: '^/algorithms/' },
  { text: '性能', link: '/performance' },
];

const zhSidebar: DefaultTheme.Sidebar = {
  '/': [
    {
      text: '指南',
      items: [
        { text: '简介', link: '/guide/' },
        { text: '安装与快速开始', link: '/guide/getting-started' },
        { text: '只用一个算法', link: '/guide/subpath-imports' },
        { text: '跨运行时', link: '/guide/cross-runtime' },
        { text: '错误处理', link: '/guide/error-handling' },
        { text: '安全说明', link: '/guide/security' },
        { text: '性能', link: '/performance' },
      ],
    },
    {
      text: '算法',
      items: [
        { text: 'SM3 · 摘要与 HMAC', link: '/algorithms/sm3' },
        { text: 'SM4 · 分组密码', link: '/algorithms/sm4' },
        { text: 'SM2 · 椭圆曲线公钥密码', link: '/algorithms/sm2' },
        { text: 'SM9 · 标识密码', link: '/algorithms/sm9' },
        { text: 'ZUC · 序列密码', link: '/algorithms/zuc' },
      ],
    },
  ],
};

const enNav: DefaultTheme.NavItem[] = [
  { text: 'Guide', link: '/en/guide/', activeMatch: '^/en/guide/' },
  { text: 'Algorithms', link: '/en/algorithms/sm3', activeMatch: '^/en/algorithms/' },
  { text: 'Performance', link: '/en/performance' },
];

const enSidebar: DefaultTheme.Sidebar = {
  '/en/': [
    {
      text: 'Guide',
      items: [
        { text: 'Introduction', link: '/en/guide/' },
        { text: 'Installation & Quick Start', link: '/en/guide/getting-started' },
        { text: 'Using a Single Algorithm', link: '/en/guide/subpath-imports' },
        { text: 'Cross-runtime', link: '/en/guide/cross-runtime' },
        { text: 'Error Handling', link: '/en/guide/error-handling' },
        { text: 'Security Notes', link: '/en/guide/security' },
        { text: 'Performance', link: '/en/performance' },
      ],
    },
    {
      text: 'Algorithms',
      items: [
        { text: 'SM3 · hash & HMAC', link: '/en/algorithms/sm3' },
        { text: 'SM4 · block cipher', link: '/en/algorithms/sm4' },
        { text: 'SM2 · elliptic curve', link: '/en/algorithms/sm2' },
        { text: 'SM9 · identity-based', link: '/en/algorithms/sm9' },
        { text: 'ZUC · stream cipher', link: '/en/algorithms/zuc' },
      ],
    },
  ],
};

const ruNav: DefaultTheme.NavItem[] = [
  { text: 'Руководство', link: '/ru/guide/', activeMatch: '^/ru/guide/' },
  { text: 'Алгоритмы', link: '/ru/algorithms/sm3', activeMatch: '^/ru/algorithms/' },
  { text: 'Производительность', link: '/ru/performance' },
];

const ruSidebar: DefaultTheme.Sidebar = {
  '/ru/': [
    {
      text: 'Руководство',
      items: [
        { text: 'Введение', link: '/ru/guide/' },
        { text: 'Установка и быстрый старт', link: '/ru/guide/getting-started' },
        { text: 'Один алгоритм', link: '/ru/guide/subpath-imports' },
        { text: 'Среды выполнения', link: '/ru/guide/cross-runtime' },
        { text: 'Обработка ошибок', link: '/ru/guide/error-handling' },
        { text: 'Безопасность', link: '/ru/guide/security' },
        { text: 'Производительность', link: '/ru/performance' },
      ],
    },
    {
      text: 'Алгоритмы',
      items: [
        { text: 'SM3 · хеш и HMAC', link: '/ru/algorithms/sm3' },
        { text: 'SM4 · блочный шифр', link: '/ru/algorithms/sm4' },
        { text: 'SM2 · эллиптические кривые', link: '/ru/algorithms/sm2' },
        { text: 'SM9 · идентификационная криптография', link: '/ru/algorithms/sm9' },
        { text: 'ZUC · поточный шифр', link: '/ru/algorithms/zuc' },
      ],
    },
  ],
};

export default defineConfig({
  base: BASE,
  lastUpdated: true,
  metaChunk: true,

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${BASE}favicon.svg` }],
    ['meta', { name: 'theme-color', content: '#0f766e' }],
  ],

  sitemap: { hostname: 'https://jktantan.github.io/sm-crypto-wasm/' },

  locales: {
    root: {
      label: '简体中文',
      lang: 'zh-CN',
      title: 'sm-crypto-wasm',
      description: '国密 SM2 / SM3 / SM4 / SM9 / ZUC 的 WASM 实现，Node 18+ 与现代浏览器均可使用。',
      themeConfig: {
        nav: zhNav,
        sidebar: zhSidebar,
        outline: { level: [2, 3], label: '本页目录' },
        lastUpdated: { text: '最后更新于' },
        docFooter: { prev: '上一篇', next: '下一篇' },
        returnToTopLabel: '回到顶部',
        sidebarMenuLabel: '目录',
        darkModeSwitchLabel: '主题',
        editLink: { pattern: `${REPO}/edit/main/website/:path`, text: '在 GitHub 上编辑此页' },
        footer: {
          message: '以 Apache-2.0 许可发布',
          copyright: 'Copyright © 2026 sm-crypto-wasm contributors',
        },
      },
    },
    en: {
      label: 'English',
      lang: 'en-US',
      link: '/en/',
      title: 'sm-crypto-wasm',
      description:
        'SM2 / SM3 / SM4 / SM9 / ZUC (China crypto) in WebAssembly. Node 18+ and modern browsers.',
      themeConfig: {
        nav: enNav,
        sidebar: enSidebar,
        outline: { level: [2, 3], label: 'On this page' },
        lastUpdated: { text: 'Last updated' },
        docFooter: { prev: 'Previous page', next: 'Next page' },
        returnToTopLabel: 'Return to top',
        sidebarMenuLabel: 'Menu',
        darkModeSwitchLabel: 'Appearance',
        editLink: { pattern: `${REPO}/edit/main/website/:path`, text: 'Edit this page on GitHub' },
        footer: {
          message: 'Released under the Apache-2.0 License',
          copyright: 'Copyright © 2026 sm-crypto-wasm contributors',
        },
      },
    },
    ru: {
      label: 'Русский',
      lang: 'ru-RU',
      link: '/ru/',
      title: 'sm-crypto-wasm',
      description:
        'SM2 / SM3 / SM4 / SM9 / ZUC (китайская криптография) на WebAssembly. Node 18+ и браузеры.',
      themeConfig: {
        nav: ruNav,
        sidebar: ruSidebar,
        outline: { level: [2, 3], label: 'На этой странице' },
        lastUpdated: { text: 'Обновлено' },
        docFooter: { prev: 'Предыдущая', next: 'Следующая' },
        returnToTopLabel: 'Наверх',
        sidebarMenuLabel: 'Меню',
        darkModeSwitchLabel: 'Тема',
        editLink: { pattern: `${REPO}/edit/main/website/:path`, text: 'Редактировать на GitHub' },
        footer: {
          message: 'Лицензия Apache-2.0',
          copyright: 'Copyright © 2026 sm-crypto-wasm contributors',
        },
      },
    },
  },

  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'sm-crypto-wasm',
    socialLinks: [{ icon: 'github', link: REPO }],
    search: { provider: 'local' },
  },

  vite: {
    plugins: [wasmLoaderShimPlugin()],
    resolve: {
      alias: [
        // dist/runtime/random.js 里有一句 `import { webcrypto } from 'node:crypto'`
        // 作为 Node 18 的兜底；浏览器里用不到，但需要一个能解析的模块接住它。
        { find: /^node:crypto$/, replacement: nodeCryptoShim },
        // Playground 里 `import { sm4 } from 'sm-crypto-wasm'` 直接指向构建产物，
        // 保证演示的就是 npm 包里的那份代码。
        { find: /^sm-crypto-wasm$/, replacement: `${distDir}index.js` },
        {
          find: /^sm-crypto-wasm\/(sm2|sm3|sm4|sm9|zuc)$/,
          replacement: `${distDir}$1/index.js`,
        },
      ],
    },
  },
});

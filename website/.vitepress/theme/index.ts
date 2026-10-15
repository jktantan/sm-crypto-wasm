import type { Theme } from 'vitepress';
import DefaultTheme from 'vitepress/theme';

import PlaygroundFrame from './components/PlaygroundFrame.vue';
import Sm2Playground from './components/Sm2Playground.vue';
import Sm3Playground from './components/Sm3Playground.vue';
import Sm4Playground from './components/Sm4Playground.vue';
import Sm9Playground from './components/Sm9Playground.vue';
import ZucPlayground from './components/ZucPlayground.vue';
import './styles/playground.css';

/**
 * 文档站主题：在 VitePress 默认主题上注册 Playground 系列组件。
 *
 * 这些组件直接 `import { sm4 } from 'sm-crypto-wasm'`（见 config.ts 的 alias），
 * 在浏览器里跑真实的 wasm，不是静态输出的假 demo。
 */
export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('PlaygroundFrame', PlaygroundFrame);
    app.component('Sm2Playground', Sm2Playground);
    app.component('Sm3Playground', Sm3Playground);
    app.component('Sm4Playground', Sm4Playground);
    app.component('Sm9Playground', Sm9Playground);
    app.component('ZucPlayground', ZucPlayground);
  },
} satisfies Theme;

<script setup lang="ts">
import { computed, ref } from 'vue';
import { usePgText } from './pg-i18n';

/** Playground 外壳：运行按钮、加载态、错误展示、耗时、可折叠的等效代码。 */
const props = defineProps<{
  /** 面板标题。 */
  title: string;
  /** 一句话说明这次演示在做什么。 */
  description?: string;
  /** 点击「运行」时执行的回调。抛出的异常会被捕获并原样显示。 */
  run: () => Promise<void> | void;
  /** 可选：等效的库调用代码，折叠展示。 */
  code?: string;
}>();

const pgText = usePgText();
/** 外壳自己的文案（按钮 / 折叠区标题）也走同一张三语文案表。 */
const T = computed(() => pgText.value.frame);

const busy = ref(false);
const elapsed = ref<number | null>(null);
const failure = ref<{ name: string; message: string } | null>(null);

async function onRun() {
  busy.value = true;
  failure.value = null;
  elapsed.value = null;
  const t0 = performance.now();
  try {
    await props.run();
    elapsed.value = performance.now() - t0;
  } catch (err) {
    // 错误也是演示的一部分：把库抛出的精确类型和消息摆出来。
    if (err instanceof Error) failure.value = { name: err.name, message: err.message };
    else failure.value = { name: typeof err, message: String(err) };
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="pg">
    <div class="pg__head">
      <h3>{{ title }}</h3>
      <span class="pg__tag">WASM · live</span>
    </div>
    <p v-if="description" class="pg__desc">{{ description }}</p>

    <div class="pg__body">
      <slot />
    </div>

    <div class="pg__bar">
      <button class="pg__run" type="button" :disabled="busy" @click="onRun">
        {{ busy ? T.running : T.run }}
      </button>
      <span v-if="elapsed !== null" class="pg__elapsed">{{ elapsed.toFixed(2) }} ms</span>
    </div>

    <div v-if="failure" class="pg__err">
      <b>{{ failure.name }}</b>
      <span>{{ failure.message }}</span>
    </div>

    <div class="pg__out">
      <slot name="result" />
    </div>

    <details v-if="code" class="pg__code">
      <summary>{{ T.src }}</summary>
      <pre><code>{{ code }}</code></pre>
    </details>
  </section>
</template>

<script setup lang="ts">
/** 表单字段的标签外壳。 */
defineProps<{ label: string; hint?: string }>();
</script>

<template>
  <label class="pgf">
    <span class="pgf__label">
      {{ label }}
      <em v-if="hint">{{ hint }}</em>
    </span>
    <slot />
  </label>
</template>

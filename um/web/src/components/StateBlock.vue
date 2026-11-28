<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    kind: 'loading' | 'empty' | 'error'
    title?: string
    message?: string
    code?: string
    retryable?: boolean
    retryLabel?: string
  }>(),
  {
    title: '',
    message: '',
    code: '',
    retryable: true,
    retryLabel: '重试',
  },
)

const emit = defineEmits<{ retry: [] }>()

const defaultTitle = computed(() => {
  switch (props.kind) {
    case 'loading':
      return '加载中…'
    case 'error':
      return '加载失败'
    default:
      return '暂无数据'
  }
})

const titleText = computed(() => props.title || defaultTitle.value)
</script>

<template>
  <div
    class="state-block"
    :class="`state-block--${kind}`"
    :role="kind === 'error' ? 'alert' : 'status'"
    :aria-live="kind === 'loading' ? 'polite' : 'assertive'"
  >
    <span v-if="kind === 'loading'" class="spinner" aria-hidden="true"></span>
    <span v-else class="state-symbol" aria-hidden="true">{{ kind === 'error' ? '!' : '·' }}</span>
    <div class="state-copy">
      <p class="state-title">{{ titleText }}</p>
      <p v-if="message" class="state-message">{{ message }}</p>
      <p v-if="code" class="state-code">错误代码：<span class="mono">{{ code }}</span></p>
    </div>
    <button
      v-if="kind === 'error' && retryable"
      type="button"
      class="btn btn-sm"
      @click="emit('retry')"
    >
      {{ retryLabel }}
    </button>
  </div>
</template>

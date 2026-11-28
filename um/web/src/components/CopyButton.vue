<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue'
import { copyText } from '@/utils/clipboard'

const props = withDefaults(
  defineProps<{
    value: string
    label?: string
    copiedLabel?: string
    quiet?: boolean
  }>(),
  {
    label: '复制',
    copiedLabel: '已复制',
    quiet: false,
  },
)

const copied = ref(false)
let resetTimer: ReturnType<typeof setTimeout> | null = null

async function onCopy(): Promise<void> {
  const ok = await copyText(props.value)
  copied.value = ok
  if (resetTimer !== null) clearTimeout(resetTimer)
  resetTimer = setTimeout(() => {
    copied.value = false
    resetTimer = null
  }, 2000)
}

onBeforeUnmount(() => {
  if (resetTimer !== null) clearTimeout(resetTimer)
})
</script>

<template>
  <button type="button" class="btn btn-sm" :class="quiet ? 'btn-quiet' : ''" @click="onCopy">
    {{ copied ? copiedLabel : label }}
  </button>
</template>

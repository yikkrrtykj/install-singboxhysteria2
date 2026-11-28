<script setup lang="ts">
import { ref } from 'vue'
import { copyText } from '@/utils/clipboard'

const props = withDefaults(
  defineProps<{
    codes: string[]
    remaining?: number | null
    title?: string
    /** Show a dismiss button when the parent wants "display once" semantics. */
    dismissible?: boolean
  }>(),
  {
    remaining: null,
    title: '恢复代码（仅显示一次）',
    dismissible: false,
  },
)

const emit = defineEmits<{ dismiss: [] }>()
const copiedAll = ref(false)
let resetTimer: ReturnType<typeof setTimeout> | null = null

async function copyAll(): Promise<void> {
  const ok = await copyText(props.codes.join('\n'))
  copiedAll.value = ok
  if (resetTimer !== null) clearTimeout(resetTimer)
  resetTimer = setTimeout(() => {
    copiedAll.value = false
    resetTimer = null
  }, 2000)
}
</script>

<template>
  <section class="recovery-codes" aria-labelledby="recovery-codes-title">
    <div class="recovery-codes__head">
      <h3 id="recovery-codes-title" class="recovery-codes__title">{{ title }}</h3>
      <div class="inline-actions">
        <button type="button" class="btn btn-sm" @click="copyAll">
          {{ copiedAll ? '已复制全部' : '复制全部' }}
        </button>
        <button
          v-if="dismissible"
          type="button"
          class="btn btn-sm btn-quiet"
          @click="emit('dismiss')"
        >
          我已保存，关闭
        </button>
      </div>
    </div>
    <p class="recovery-codes__warning" role="alert">
      这些恢复代码只显示这一次。请离线保存到安全位置；关闭后无法再次查看，只能重新生成。
    </p>
    <ol v-if="codes.length > 0" class="recovery-codes__grid">
      <li v-for="(code, index) in codes" :key="`${index}-${code}`" class="recovery-codes__item mono">
        {{ code }}
      </li>
    </ol>
    <p v-else class="muted small">服务端未返回恢复代码内容。</p>
    <p v-if="remaining !== null" class="muted small">
      服务端记录的剩余可用恢复代码：{{ remaining }} 个。
    </p>
  </section>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    open: boolean
    title: string
    message?: string
    confirmLabel?: string
    cancelLabel?: string
    danger?: boolean
    busy?: boolean
  }>(),
  {
    message: '',
    confirmLabel: '确认',
    cancelLabel: '取消',
    danger: false,
    busy: false,
  },
)

const emit = defineEmits<{ confirm: []; cancel: [] }>()
</script>

<template>
  <div v-if="open" class="modal-backdrop" @click.self="!busy && emit('cancel')">
    <div class="modal" role="dialog" aria-modal="true" :aria-label="title">
      <h2 class="modal-title">{{ title }}</h2>
      <p v-if="message" class="modal-message">{{ message }}</p>
      <div class="modal-actions">
        <button type="button" class="btn" :disabled="busy" @click="emit('cancel')">
          {{ cancelLabel }}
        </button>
        <button
          type="button"
          class="btn"
          :class="danger ? 'btn-danger' : 'btn-primary'"
          :disabled="busy"
          @click="emit('confirm')"
        >
          {{ busy ? '处理中…' : confirmLabel }}
        </button>
      </div>
    </div>
  </div>
</template>

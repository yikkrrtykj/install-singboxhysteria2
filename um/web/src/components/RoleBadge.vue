<script setup lang="ts">
import { computed } from 'vue'
import { roleLabel } from '@/api/types'

const props = defineProps<{ role: string | null | undefined }>()

const roleClass = computed(() => {
  switch (props.role) {
    case 'platform_admin':
      return 'badge--role-platform'
    case 'event_admin':
      return 'badge--role-event'
    case 'viewer':
      return 'badge--role-viewer'
    default:
      return 'badge--role-unknown'
  }
})
</script>

<template>
  <span class="badge" :class="roleClass">{{ roleLabel(role) }}</span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const homeTarget = computed(() => (auth.isAuthenticated ? '/' : '/login'))
const homeLabel = computed(() => (auth.isAuthenticated ? '返回总览' : '前往登录'))
</script>

<template>
  <div class="auth-page">
    <main class="auth-card">
      <p class="status-code" aria-hidden="true">404</p>
      <h1 class="auth-title">页面不存在</h1>
      <p class="muted">请求的路径不存在，可能已被移动或输入有误。</p>
      <div class="inline-actions">
        <RouterLink class="btn btn-primary" :to="homeTarget">{{ homeLabel }}</RouterLink>
      </div>
    </main>
  </div>
</template>

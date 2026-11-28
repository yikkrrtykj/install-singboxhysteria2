<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { roleLabel } from '@/api/types'

const auth = useAuthStore()
const router = useRouter()

const backTarget = computed(() => (auth.isAuthenticated ? '/' : '/login'))
const backLabel = computed(() => (auth.isAuthenticated ? '返回总览' : '前往登录'))

async function onLogout(): Promise<void> {
  await auth.logout()
  await router.replace({ name: 'login' })
}
</script>

<template>
  <div class="auth-page">
    <main class="auth-card">
      <p class="status-code" aria-hidden="true">403</p>
      <h1 class="auth-title">无权访问</h1>
      <p class="alert alert-warn" role="alert">
        当前账号{{ auth.isAuthenticated ? `（${auth.displayName} · ${roleLabel(auth.role)}）` : '' }}没有访问该页面所需的权限。
      </p>
      <p class="muted">
        页面访问控制只是交互提示；中心服务会对每个 API 请求独立校验角色与事件范围。若确需访问，请联系平台管理员调整权限。
      </p>

      <div class="inline-actions">
        <RouterLink class="btn btn-primary" :to="backTarget">{{ backLabel }}</RouterLink>
        <button v-if="auth.isAuthenticated" type="button" class="btn" @click="onLogout">退出登录</button>
      </div>
    </main>
  </div>
</template>

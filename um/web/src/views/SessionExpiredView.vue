<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()

const reason = computed(() => auth.expiredReason ?? '会话已过期或不再有效，请重新登录。')

async function goToLogin(): Promise<void> {
  auth.clearExpiredState()
  await router.replace({ name: 'login' })
}
</script>

<template>
  <div class="auth-page">
    <main class="auth-card">
      <header class="auth-brand">
        <span class="auth-brand__mark" aria-hidden="true">UM</span>
        <div>
          <strong>UM-C</strong>
          <span class="auth-brand__sub">统一监控 · 运维控制台</span>
        </div>
      </header>

      <h1 class="auth-title">会话已过期</h1>
      <p class="alert alert-warn" role="alert">{{ reason }}</p>
      <p class="muted">
        出于安全考虑，当前页面的内存状态已清空。服务端设置的会话 Cookie 可能已过期、被撤销，或 Cloudflare Access
        边缘会话需要重新认证。
      </p>

      <div class="stack">
        <button type="button" class="btn btn-primary btn-block" @click="goToLogin">重新登录</button>
      </div>

      <footer class="auth-foot muted small">
        如果反复出现该页面，请确认 Cloudflare Access 会话有效，或联系平台管理员。
      </footer>
    </main>
  </div>
</template>

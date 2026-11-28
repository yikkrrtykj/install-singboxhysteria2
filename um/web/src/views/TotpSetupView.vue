<script setup lang="ts">
import { useRouter } from 'vue-router'
import TotpEnrollmentPanel from '@/components/TotpEnrollmentPanel.vue'

const router = useRouter()

function onCompleted(): void {
  void router.replace({ name: 'dashboard' })
}
</script>

<template>
  <div class="auth-page">
    <main class="auth-card auth-card--wide">
      <header class="auth-brand">
        <span class="auth-brand__mark" aria-hidden="true">UM</span>
        <div>
          <strong>UM-C</strong>
          <span class="auth-brand__sub">统一监控 · 运维控制台</span>
        </div>
      </header>

      <h1 class="auth-title">绑定身份验证器</h1>
      <p class="muted">
        这是首次登录的安全要求。绑定完成后，后续登录需要输入身份验证器生成的 6 位验证码。密钥仅在本页面内存中短暂存在。
      </p>

      <TotpEnrollmentPanel mode="first-time" @completed="onCompleted" />
    </main>
  </div>
</template>

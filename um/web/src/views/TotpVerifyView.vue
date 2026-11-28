<script setup lang="ts">
import { ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'

const auth = useAuthStore()
const router = useRouter()
const { handle } = useApiErrorHandler()

const code = ref('')
const submitting = ref(false)
const error = ref<string | null>(null)

async function onSubmit(): Promise<void> {
  error.value = null
  const normalized = code.value.replace(/\D/g, '')
  if (normalized.length !== 6) {
    error.value = '请输入验证器上显示的 6 位数字验证码。'
    return
  }
  submitting.value = true
  try {
    const stage = await auth.verifyTotp(normalized)
    if (stage === 'authenticated') {
      await router.replace({ name: 'dashboard' })
    } else if (stage === 'totp_setup') {
      await router.replace({ name: 'totp-setup' })
    } else {
      error.value = '两步验证尚未完成，请重试或联系管理员。'
    }
  } catch (caught) {
    const message = handle(caught, '两步验证失败')
    if (message) error.value = message
  } finally {
    submitting.value = false
  }
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

      <h1 class="auth-title">两步验证</h1>
      <p class="muted">
        密码已通过。请输入身份验证器 App 中为
        <strong>{{ auth.displayName || '当前账号' }}</strong>
        生成的 6 位验证码以完成登录。
      </p>

      <form class="stack" novalidate @submit.prevent="onSubmit">
        <label class="field">
          <span class="field-label">6 位验证码</span>
          <input
            v-model="code"
            class="input input--code"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            maxlength="6"
            pattern="[0-9]*"
            placeholder="000000"
            :disabled="submitting"
            autofocus
          />
        </label>

        <p v-if="error" class="alert alert-error" role="alert">{{ error }}</p>

        <button type="submit" class="btn btn-primary btn-block" :disabled="submitting">
          {{ submitting ? '验证中…' : '验证并登录' }}
        </button>
      </form>

      <div class="auth-actions">
        <RouterLink to="/recovery">丢失验证器？使用恢复代码</RouterLink>
      </div>

      <footer class="auth-foot muted small">
        待验证会话由中心服务管理；关闭页面后再次访问仍会回到本步骤，直到完成验证或会话过期。
      </footer>
    </main>
  </div>
</template>

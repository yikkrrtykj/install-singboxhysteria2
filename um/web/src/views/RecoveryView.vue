<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { toApiError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'

const auth = useAuthStore()
const router = useRouter()
const { handle } = useApiErrorHandler()

const form = reactive({ username: '', password: '', recoveryCode: '' })
const submitting = ref(false)
const error = ref<string | null>(null)

onMounted(() => {
  if (!auth.initialized || !auth.hasCsrfToken()) {
    void auth.ensureContext()
  }
})

async function onSubmit(): Promise<void> {
  error.value = null
  const username = form.username.trim()
  const recoveryCode = form.recoveryCode.trim()
  if (username.length === 0 || form.password.length === 0 || recoveryCode.length === 0) {
    error.value = '请填写用户名、密码和恢复代码。'
    return
  }
  submitting.value = true
  try {
    const stage = await auth.submitRecovery(username, form.password, recoveryCode)
    if (stage === 'authenticated') {
      await router.replace({ name: 'dashboard' })
    } else if (stage === 'totp_setup') {
      await router.replace({ name: 'totp-setup' })
    } else if (stage === 'totp_pending') {
      await router.replace({ name: 'totp' })
    } else {
      error.value = '恢复登录尚未完成，请重试或联系平台管理员。'
    }
  } catch (caught) {
    const apiError = toApiError(caught, '恢复代码登录失败')
    if (apiError.code === 'login_csrf_failed') {
      await auth.bootstrap(true)
      error.value = '登录会话已刷新，请重新输入密码和恢复代码后重试。'
      return
    }
    const message = handle(apiError, '恢复代码登录失败')
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

      <h1 class="auth-title">恢复代码登录</h1>
      <p class="muted">
        仅在丢失身份验证器时使用。恢复代码一次性有效；使用成功后需要立即重新绑定身份验证器并保存新的恢复代码。
      </p>

      <form class="stack" novalidate @submit.prevent="onSubmit">
        <label class="field">
          <span class="field-label">用户名</span>
          <input
            v-model="form.username"
            class="input"
            type="text"
            name="username"
            autocomplete="username"
            autocapitalize="none"
            spellcheck="false"
            :disabled="submitting"
          />
        </label>

        <label class="field">
          <span class="field-label">密码</span>
          <input
            v-model="form.password"
            class="input"
            type="password"
            name="password"
            autocomplete="current-password"
            :disabled="submitting"
          />
        </label>

        <label class="field">
          <span class="field-label">恢复代码</span>
          <input
            v-model="form.recoveryCode"
            class="input mono"
            type="text"
            name="recovery-code"
            autocomplete="off"
            autocapitalize="none"
            spellcheck="false"
            placeholder="例如 XXXXX-XXXXX"
            :disabled="submitting"
          />
        </label>

        <p v-if="error" class="alert alert-error" role="alert">{{ error }}</p>

        <button type="submit" class="btn btn-primary btn-block" :disabled="submitting">
          {{ submitting ? '验证中…' : '使用恢复代码登录' }}
        </button>
      </form>

      <p class="auth-links">
        <RouterLink to="/login">返回账号密码登录</RouterLink>
      </p>

      <footer class="auth-foot muted small">
        恢复代码在服务端校验并一次性消费；不会写入浏览器存储。
      </footer>
    </main>
  </div>
</template>

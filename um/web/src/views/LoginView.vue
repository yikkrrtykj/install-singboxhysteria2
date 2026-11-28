<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { toApiError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'
import { safeRedirectTarget } from '@/router/redirect'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const { handle } = useApiErrorHandler()

const form = reactive({ username: '', password: '' })
const submitting = ref(false)
const retryingContext = ref(false)
const error = ref<string | null>(null)

const contextUnavailable = ref(route.query.reason === 'context_unavailable')
const notice = computed(() => {
  if (route.query.reason === 'password_changed') {
    return '密码已修改，所有会话已注销。请使用新密码重新登录并完成两步验证。'
  }
  if (route.query.reason === 'session_expired') {
    return '会话已过期，请重新登录。'
  }
  if (route.query.reason === 'logout_failed') {
    return '退出请求未能确认撤销服务端会话。请检查网络后重试，必要时通过“登录会话”撤销该设备。'
  }
  return null
})

onMounted(() => {
  if (!auth.initialized || !auth.hasCsrfToken()) {
    void auth.ensureContext()
  }
})

async function retryContext(): Promise<void> {
  retryingContext.value = true
  error.value = null
  try {
    const ok = await auth.ensureContext()
    contextUnavailable.value = !ok
  } finally {
    retryingContext.value = false
  }
}

async function onSubmit(): Promise<void> {
  error.value = null
  const username = form.username.trim()
  if (username.length === 0 || form.password.length === 0) {
    error.value = '请输入用户名和密码。'
    return
  }
  submitting.value = true
  try {
    const stage = await auth.login(username, form.password)
    const redirect = safeRedirectTarget(route.query.redirect)
    if (stage === 'authenticated') {
      await router.replace(redirect ?? { name: 'dashboard' })
    } else if (stage === 'totp_setup') {
      await router.replace({ name: 'totp-setup' })
    } else if (stage === 'totp_pending') {
      await router.replace({ name: 'totp' })
    } else {
      error.value = '无法确认登录状态，请重试。'
    }
  } catch (caught) {
    const apiError = toApiError(caught, '登录失败')
    if (apiError.code === 'login_csrf_failed') {
      // The preauth cookie/CSRF token expired. Refresh the preauth context and
      // let the user retry without losing the typed username.
      await auth.bootstrap(true)
      error.value = '登录会话已刷新，请重新输入密码后重试。'
      return
    }
    const message = handle(apiError, '登录失败')
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

      <h1 class="auth-title">登录</h1>
      <p class="muted">
        用户名和密码由中心服务校验。访问请求已通过 Cloudflare Access 在边缘认证；浏览器不保存任何会话令牌。
      </p>

      <p v-if="notice" class="alert alert-info" role="status">{{ notice }}</p>

      <div v-if="contextUnavailable" class="alert alert-warn" role="alert">
        <p>无法获取认证上下文。请检查 Cloudflare Access 会话或网络后重试。</p>
        <button type="button" class="btn btn-sm" :disabled="retryingContext" @click="retryContext">
          {{ retryingContext ? '检测中…' : '重试' }}
        </button>
      </div>
      <p v-else-if="auth.bootstrapError" class="alert alert-warn" role="alert">
        {{ auth.bootstrapError }}
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
            autofocus
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

        <p v-if="error" class="alert alert-error" role="alert">{{ error }}</p>

        <button type="submit" class="btn btn-primary btn-block" :disabled="submitting">
          {{ submitting ? '登录中…' : '登录' }}
        </button>
      </form>

      <p class="auth-links">
        <RouterLink to="/recovery">丢失验证器？使用恢复代码登录</RouterLink>
      </p>

      <footer class="auth-foot muted small">
        UM-C · 统一监控控制台 · 会话 Cookie 由服务端以 HttpOnly 设置
      </footer>
    </main>
  </div>
</template>

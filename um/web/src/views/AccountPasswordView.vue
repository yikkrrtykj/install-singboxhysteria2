<script setup lang="ts">
import { reactive, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'

const auth = useAuthStore()
const router = useRouter()
const { handle } = useApiErrorHandler()

const form = reactive({ currentPassword: '', newPassword: '', confirmPassword: '' })
const submitting = ref(false)
const error = ref<string | null>(null)
const success = ref<string | null>(null)

function validate(): string | null {
  if (form.currentPassword.length === 0) return '请输入当前密码。'
  if (form.newPassword.length < 12) return '新密码至少 12 个字符（中心服务按字节长度校验）。'
  if (form.newPassword !== form.confirmPassword) return '两次输入的新密码不一致。'
  if (form.newPassword === form.currentPassword) return '新密码不能与当前密码相同。'
  return null
}

async function onSubmit(): Promise<void> {
  error.value = null
  success.value = null
  const validationError = validate()
  if (validationError) {
    error.value = validationError
    return
  }
  submitting.value = true
  try {
    const result = await auth.changePassword(form.currentPassword, form.newPassword)
    if (result.reloginRequired) {
      // The center invalidates the session on password change; continue on the
      // login page with a explicit notice instead of showing a stale shell.
      await router.replace({ name: 'login', query: { reason: 'password_changed' } })
      return
    }
    success.value = '密码已更新。其他已登录会话可能仍有效，建议在“登录会话”中撤销不再使用的设备。'
    form.currentPassword = ''
    form.newPassword = ''
    form.confirmPassword = ''
  } catch (caught) {
    const message = handle(caught, '修改密码失败')
    if (message) error.value = message
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="page stack-lg">
    <div class="page-intro">
      <p class="muted">
        修改密码需要验证当前密码。密码通过同源 HTTPS 提交到中心服务，浏览器不保存密码或令牌。
      </p>
    </div>

    <section class="card card--narrow">
      <h2 class="card-title">修改密码</h2>

      <form class="stack" novalidate @submit.prevent="onSubmit">
        <label class="field">
          <span class="field-label">当前密码</span>
          <input
            v-model="form.currentPassword"
            class="input"
            type="password"
            autocomplete="current-password"
            :disabled="submitting"
          />
        </label>

        <label class="field">
          <span class="field-label">新密码</span>
          <input
            v-model="form.newPassword"
            class="input"
            type="password"
            autocomplete="new-password"
            :disabled="submitting"
          />
          <span class="field-hint">中心服务策略：12–1024 字节，需包含非空白字符；推荐使用密码管理器生成的随机密码。</span>
        </label>

        <label class="field">
          <span class="field-label">确认新密码</span>
          <input
            v-model="form.confirmPassword"
            class="input"
            type="password"
            autocomplete="new-password"
            :disabled="submitting"
          />
        </label>

        <p v-if="error" class="alert alert-error" role="alert">{{ error }}</p>
        <p v-if="success" class="alert alert-success" role="status">{{ success }}</p>

        <div class="inline-actions">
          <button type="submit" class="btn btn-primary" :disabled="submitting">
            {{ submitting ? '提交中…' : '更新密码' }}
          </button>
          <RouterLink class="btn btn-sm" to="/account/sessions">查看登录会话</RouterLink>
        </div>
      </form>
    </section>
  </div>
</template>

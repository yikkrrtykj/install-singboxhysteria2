<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'
import type { TotpSetupModel } from '@/api/types'
import QrCode from './QrCode.vue'
import CopyButton from './CopyButton.vue'
import RecoveryCodeList from './RecoveryCodeList.vue'
import StateBlock from './StateBlock.vue'

const props = withDefaults(
  defineProps<{
    /** first-time = forced enrolment after login; re-enroll = account security. */
    mode?: 'first-time' | 're-enroll'
  }>(),
  { mode: 'first-time' },
)

const emit = defineEmits<{ completed: [] }>()

const auth = useAuthStore()
const { handle } = useApiErrorHandler()

const starting = ref(false)
const passwordGate = ref(props.mode === 're-enroll')
const password = ref('')
const startError = ref<string | null>(null)
const setup = ref<TotpSetupModel | null>(null)
const code = ref('')
const confirming = ref(false)
const confirmError = ref<string | null>(null)
const confirmed = ref(false)
const recoveryCodes = ref<string[]>([])
const recoveryRemaining = ref<number | null>(null)
const generatingCodes = ref(false)
const codesError = ref<string | null>(null)

const showPasswordGate = computed(
  () => passwordGate.value && setup.value === null && !starting.value && !confirmed.value,
)

async function start(currentPassword?: string): Promise<void> {
  starting.value = true
  startError.value = null
  try {
    setup.value = await auth.beginTotpSetup(currentPassword)
    passwordGate.value = false
  } catch (error) {
    const message = handle(error, '无法开始 TOTP 绑定')
    if (message) startError.value = message
  } finally {
    starting.value = false
  }
}

function startWithPassword(): void {
  if (password.value.trim().length === 0) {
    startError.value = '请输入当前密码。'
    return
  }
  void start(password.value)
}

async function onConfirm(): Promise<void> {
  confirmError.value = null
  const normalized = code.value.replace(/\D/g, '')
  if (normalized.length !== 6) {
    confirmError.value = '请输入验证器上显示的 6 位数字验证码。'
    return
  }
  confirming.value = true
  try {
    const result = await auth.confirmTotpSetup(normalized)
    confirmed.value = true
    setup.value = null
    if (result.recoveryCodes.length > 0) {
      recoveryCodes.value = result.recoveryCodes
    }
  } catch (error) {
    const message = handle(error, '验证码校验失败')
    if (message) confirmError.value = message
  } finally {
    confirming.value = false
  }
}

async function onGenerateCodes(): Promise<void> {
  generatingCodes.value = true
  codesError.value = null
  try {
    const result = await auth.regenerateRecoveryCodes()
    recoveryCodes.value = result.codes
    recoveryRemaining.value = result.remaining
  } catch (error) {
    const message = handle(error, '生成恢复代码失败')
    if (message) codesError.value = message
  } finally {
    generatingCodes.value = false
  }
}

function finish(): void {
  emit('completed')
}

onMounted(() => {
  if (props.mode === 'first-time') void start()
})
</script>

<template>
  <div class="totp-panel">
    <section v-if="showPasswordGate" class="card card--quiet stack">
      <p class="muted">
        重新绑定身份验证器需要先验证当前密码。验证通过后会立即生成新密钥，旧验证器中的条目将在绑定完成后失效。
      </p>
      <p v-if="startError" class="alert alert-error" role="alert">{{ startError }}</p>
      <form class="stack" novalidate @submit.prevent="startWithPassword">
        <label class="field">
          <span class="field-label">当前密码</span>
          <input
            v-model="password"
            class="input"
            type="password"
            autocomplete="current-password"
            :disabled="starting"
          />
        </label>
        <div class="inline-actions">
          <button type="submit" class="btn btn-primary" :disabled="starting">
            {{ starting ? '验证中…' : '验证并重新绑定' }}
          </button>
        </div>
      </form>
    </section>

    <StateBlock
      v-else-if="starting"
      kind="loading"
      title="正在生成 TOTP 绑定信息…"
      message="密钥材料只保存在内存中；浏览器不会持久化该密钥。"
    />

    <StateBlock
      v-else-if="startError && !setup"
      kind="error"
      title="无法开始 TOTP 绑定"
      :message="startError"
      @retry="start()"
    />
    <p v-if="startError && !setup" class="muted small">
      如果页面曾刷新导致绑定二维码丢失，请重新登录以生成新的 TOTP 密钥；不要重复刷新绑定页面。
    </p>

    <section v-else-if="confirmed" class="stack">
      <p class="alert alert-success" role="status">
        {{ props.mode === 'first-time' ? 'TOTP 已绑定成功。' : 'TOTP 已重新绑定成功。' }}
      </p>
      <RecoveryCodeList
        v-if="recoveryCodes.length > 0"
        :codes="recoveryCodes"
        :remaining="recoveryRemaining"
        :title="'恢复代码（仅显示一次）'"
        dismissible
        @dismiss="finish"
      />
      <div v-else class="card card--quiet stack">
        <p class="muted">
          服务端本次没有返回恢复代码。建议立即生成一组恢复代码并离线保存，否则无法在丢失验证器时自助恢复。
        </p>
        <p v-if="codesError" class="alert alert-error" role="alert">{{ codesError }}</p>
        <div class="inline-actions">
          <button type="button" class="btn" :disabled="generatingCodes" @click="onGenerateCodes">
            {{ generatingCodes ? '生成中…' : '生成恢复代码' }}
          </button>
          <button type="button" class="btn btn-primary" @click="finish">完成</button>
        </div>
      </div>
      <div v-if="recoveryCodes.length > 0" class="inline-actions">
        <button type="button" class="btn btn-primary" @click="finish">完成</button>
      </div>
    </section>

    <div v-else-if="setup" class="totp-panel__body">
      <ol class="steps">
        <li>在身份验证器 App 中扫描二维码，或手动输入密钥。</li>
        <li>输入当前 6 位验证码完成绑定。</li>
        <li>保存随后只显示一次的恢复代码。</li>
      </ol>

      <div class="totp-panel__grid">
        <div class="totp-panel__qr">
          <QrCode :value="setup.otpauthUrl" />
          <p class="muted small">二维码由本地 `qrcode` 库渲染，不请求外部服务。</p>
        </div>

        <div class="totp-panel__manual">
          <div class="field">
            <span class="field-label">手动密钥（Base32）</span>
            <div class="input-row">
              <code class="secret mono">{{ setup.secret || '服务端未返回手动密钥，请使用 otpauth URI' }}</code>
              <CopyButton v-if="setup.secret" :value="setup.secret" label="复制密钥" quiet />
            </div>
          </div>

          <p v-if="setup.issuer || setup.accountName" class="muted small">
            发行方：{{ setup.issuer ?? 'UM-C' }} · 账户：{{ setup.accountName ?? auth.displayName }}
          </p>

          <details class="uri-details">
            <summary>查看 otpauth URI</summary>
            <code class="mono break-all">{{ setup.otpauthUrl }}</code>
          </details>

          <form class="stack" @submit.prevent="onConfirm">
            <label class="field">
              <span class="field-label">验证器当前 6 位验证码</span>
              <input
                v-model="code"
                class="input input--code"
                type="text"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                pattern="[0-9]*"
                placeholder="000000"
                :disabled="confirming"
              />
            </label>
            <p v-if="confirmError" class="alert alert-error" role="alert">{{ confirmError }}</p>
            <button type="submit" class="btn btn-primary" :disabled="confirming">
              {{ confirming ? '校验中…' : '完成绑定' }}
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'
import TotpEnrollmentPanel from '@/components/TotpEnrollmentPanel.vue'
import RecoveryCodeList from '@/components/RecoveryCodeList.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'

const auth = useAuthStore()
const { handle } = useApiErrorHandler()

const showEnrollment = ref(false)
const enrollmentCompleted = ref(false)
const enrollmentNotice = ref<string | null>(null)

const generating = ref(false)
const codesError = ref<string | null>(null)
const generatedCodes = ref<string[]>([])
const generatedRemaining = ref<number | null>(null)
const showRegenerateConfirm = ref(false)

function toggleEnrollment(): void {
  showEnrollment.value = !showEnrollment.value
  enrollmentNotice.value = null
}

function onEnrollmentCompleted(): void {
  showEnrollment.value = false
  enrollmentCompleted.value = true
  enrollmentNotice.value = '身份验证器已重新绑定。旧验证器生成的验证码已失效。'
}

async function confirmRegenerate(): Promise<void> {
  generating.value = true
  codesError.value = null
  try {
    const result = await auth.regenerateRecoveryCodes()
    generatedCodes.value = result.codes
    generatedRemaining.value = result.remaining
    if (result.codes.length === 0) {
      codesError.value = '服务端未返回恢复代码内容，请重试或联系平台管理员。'
    }
  } catch (error) {
    const message = handle(error, '重新生成恢复代码失败')
    if (message) codesError.value = message
  } finally {
    generating.value = false
    showRegenerateConfirm.value = false
  }
}

function dismissCodes(): void {
  generatedCodes.value = []
  generatedRemaining.value = null
}
</script>

<template>
  <div class="page stack-lg">
    <div class="page-intro">
      <p class="muted">
        管理当前账号的两步验证与恢复代码。密钥与恢复代码只在内存中短暂显示，不会写入浏览器存储。
      </p>
    </div>

    <section class="card">
      <div class="card-title-row">
        <h2 class="card-title">TOTP 身份验证器</h2>
        <span class="badge badge--ok">已启用</span>
      </div>
      <p class="muted">
        当前登录已通过 TOTP 验证。重新绑定会生成新的密钥，旧验证器 App 中的条目将在绑定完成后失效。
      </p>

      <p v-if="enrollmentNotice" class="alert alert-success" role="status">{{ enrollmentNotice }}</p>

      <div class="inline-actions">
        <button type="button" class="btn btn-sm" @click="toggleEnrollment">
          {{ showEnrollment ? '收起重新绑定' : '重新绑定 TOTP' }}
        </button>
        <RouterLink class="btn btn-sm" to="/account/sessions">登录会话</RouterLink>
        <RouterLink class="btn btn-sm" to="/account/password">修改密码</RouterLink>
      </div>

      <div v-if="showEnrollment" class="security-enrollment">
        <TotpEnrollmentPanel mode="re-enroll" @completed="onEnrollmentCompleted" />
      </div>
      <p v-else-if="enrollmentCompleted" class="muted small">如需再次更换验证器，请点击“重新绑定 TOTP”。</p>
    </section>

    <section class="card">
      <div class="card-title-row">
        <h2 class="card-title">恢复代码</h2>
        <span class="badge badge--muted">
          剩余：{{ auth.recoveryCodesRemaining ?? '未知' }}
        </span>
      </div>
      <p class="muted">
        恢复代码用于在丢失身份验证器时登录，每张代码只能使用一次。重新生成会立即使所有旧代码失效，并且新代码只显示一次。
      </p>
      <p v-if="codesError" class="alert alert-error" role="alert">{{ codesError }}</p>

      <RecoveryCodeList
        v-if="generatedCodes.length > 0"
        :codes="generatedCodes"
        :remaining="generatedRemaining"
        dismissible
        @dismiss="dismissCodes"
      />

      <div v-if="generatedCodes.length === 0" class="inline-actions">
        <button
          type="button"
          class="btn btn-sm"
          :disabled="generating"
          @click="showRegenerateConfirm = true"
        >
          {{ generating ? '生成中…' : '重新生成恢复代码' }}
        </button>
      </div>
    </section>

    <ConfirmDialog
      :open="showRegenerateConfirm"
      title="重新生成恢复代码"
      message="现有恢复代码将立即失效，新代码只在生成后显示一次。确定继续？"
      confirm-label="生成新恢复代码"
      danger
      :busy="generating"
      @confirm="confirmRegenerate"
      @cancel="showRegenerateConfirm = false"
    />
  </div>
</template>

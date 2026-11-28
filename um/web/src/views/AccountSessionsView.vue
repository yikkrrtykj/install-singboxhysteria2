<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'
import type { SessionModel } from '@/api/types'
import { formatTimestamp, shortId, shortUserAgent } from '@/utils/format'
import StateBlock from '@/components/StateBlock.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'

const auth = useAuthStore()
const router = useRouter()
const { handle } = useApiErrorHandler()

const sessions = ref<SessionModel[]>([])
const loading = ref(true)
const refreshing = ref(false)
const listError = ref<string | null>(null)
const actionError = ref<string | null>(null)
const revokingId = ref<string | null>(null)
const pendingRevoke = ref<SessionModel | null>(null)

async function loadSessions(initial = false): Promise<void> {
  if (initial) loading.value = true
  else refreshing.value = true
  listError.value = null
  try {
    sessions.value = await auth.fetchSessions()
  } catch (error) {
    const message = handle(error, '加载登录会话失败')
    if (message) listError.value = message
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

function requestRevoke(session: SessionModel): void {
  actionError.value = null
  pendingRevoke.value = session
}

async function confirmRevoke(): Promise<void> {
  const target = pendingRevoke.value
  if (!target) return
  revokingId.value = target.id
  actionError.value = null
  try {
    await auth.revokeSession(target.id)
    pendingRevoke.value = null
    if (target.current) {
      auth.markSessionExpired()
      await router.replace({ name: 'session-expired' })
      return
    }
    await loadSessions()
  } catch (error) {
    const message = handle(error, '撤销会话失败')
    if (message) actionError.value = message
  } finally {
    revokingId.value = null
    pendingRevoke.value = null
  }
}

onMounted(() => {
  void loadSessions(true)
})
</script>

<template>
  <div class="page stack-lg">
    <div class="page-intro">
      <p class="muted">
        这里列出服务端记录的当前账号登录会话。会话 Cookie 为 HttpOnly，浏览器无法读取；撤销操作会立即在服务端生效。
      </p>
    </div>

    <div class="toolbar">
      <button type="button" class="btn btn-sm" :disabled="refreshing || loading" @click="loadSessions()">
        {{ refreshing ? '刷新中…' : '刷新' }}
      </button>
      <span class="muted small">共 {{ sessions.length }} 个会话</span>
    </div>

    <p v-if="actionError" class="alert alert-error" role="alert">{{ actionError }}</p>

    <StateBlock v-if="loading" kind="loading" title="正在加载登录会话…" />
    <StateBlock
      v-else-if="listError"
      kind="error"
      title="登录会话加载失败"
      :message="listError"
      @retry="loadSessions(true)"
    />
    <StateBlock
      v-else-if="sessions.length === 0"
      kind="empty"
      title="没有可显示的会话"
      message="服务端未返回任何会话记录，或当前会话未被列出。"
    />

    <section v-else class="card card--flush">
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th scope="col">会话</th>
              <th scope="col">创建时间</th>
              <th scope="col">最近活动</th>
              <th scope="col">到期时间</th>
              <th scope="col">客户端 / IP</th>
              <th scope="col" class="text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="session in sessions" :key="session.id">
              <td>
                <div class="cell-stack">
                  <span class="mono small">{{ shortId(session.id) }}</span>
                  <span v-if="session.current" class="badge badge--ok">当前会话</span>
                  <span v-if="session.state" class="badge badge--muted">{{ session.state }}</span>
                </div>
              </td>
              <td class="nowrap">{{ formatTimestamp(session.createdAt) }}</td>
              <td class="nowrap">{{ formatTimestamp(session.lastSeenAt) }}</td>
              <td class="nowrap">{{ formatTimestamp(session.expiresAt) }}</td>
              <td>
                <div class="cell-stack">
                  <span>{{ shortUserAgent(session.userAgent) }}</span>
                  <span class="muted small mono">{{ session.ip ?? '—' }}</span>
                </div>
              </td>
              <td class="text-right">
                <button
                  type="button"
                  class="btn btn-sm btn-danger"
                  :disabled="revokingId === session.id"
                  @click="requestRevoke(session)"
                >
                  {{ revokingId === session.id ? '撤销中…' : '撤销' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <ConfirmDialog
      :open="pendingRevoke !== null"
      title="撤销登录会话"
      :message="
        pendingRevoke?.current
          ? '撤销当前会话将立即退出登录。确定继续？'
          : '撤销后该设备需要重新完成密码与两步验证。确定继续？'
      "
      confirm-label="撤销会话"
      danger
      :busy="revokingId !== null"
      @confirm="confirmRevoke"
      @cancel="pendingRevoke = null"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useApiErrorHandler } from '@/composables/useApiErrorHandler'
import * as usersApi from '@/api/users'
import { listAssignableEvents } from '@/api/b4'
import { ASSIGNABLE_ROLE_OPTIONS, roleLabel } from '@/api/types'
import type { EventScope, SessionModel, UserModel } from '@/api/types'
import { formatTimestamp, shortId, shortUserAgent } from '@/utils/format'
import StateBlock from '@/components/StateBlock.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import RoleBadge from '@/components/RoleBadge.vue'
import CopyButton from '@/components/CopyButton.vue'

interface PendingAction {
  title: string
  message: string
  confirmLabel: string
  danger: boolean
  run: () => Promise<void>
}

const auth = useAuthStore()
const { handle } = useApiErrorHandler()

const users = ref<UserModel[]>([])
const loading = ref(true)
const refreshing = ref(false)
const loadError = ref<string | null>(null)
const actionError = ref<string | null>(null)
const filter = ref('')

const filteredUsers = computed(() => {
  const query = filter.value.trim().toLowerCase()
  if (query.length === 0) return users.value
  return users.value.filter((user) => {
    return (
      user.username.toLowerCase().includes(query) ||
      user.role.toLowerCase().includes(query) ||
      user.eventIds.some((id) => id.toLowerCase().includes(query))
    )
  })
})

const scopeNames = computed(() => {
  const names = new Map<string, string>()
  for (const scope of assignmentOptions.value) names.set(scope.id, scope.name)
  for (const scope of auth.allowedEvents) {
    if (!names.has(scope.id)) names.set(scope.id, scope.name)
  }
  return names
})

function eventLabel(id: string): string {
  return scopeNames.value.get(id) ?? id
}

function eventSummary(user: UserModel): string {
  if (user.eventIds.length === 0) return '未分配'
  const visible = user.eventIds.slice(0, 3).map(eventLabel)
  const suffix = user.eventIds.length > 3 ? ` 等 ${user.eventIds.length} 个` : ''
  return `${visible.join('、')}${suffix}`
}

// ------------------------------------------------------- assignable events
// The center Web plane does not expose the assignable event catalogue through
// `/auth/context`; read it from the B4 management API (session bridge), with a
// fallback to whatever scopes the authenticated user view provides.
const assignableEvents = ref<EventScope[]>([])
const eventsLoading = ref(false)
const eventsError = ref<string | null>(null)

const assignmentOptions = computed<EventScope[]>(() =>
  assignableEvents.value.length > 0 ? assignableEvents.value : auth.allowedEvents,
)

async function loadEventOptions(): Promise<void> {
  eventsLoading.value = true
  eventsError.value = null
  try {
    const events = await listAssignableEvents()
    if (events.length > 0) {
      assignableEvents.value = events
    } else {
      assignableEvents.value = [...auth.allowedEvents]
    }
  } catch {
    assignableEvents.value = [...auth.allowedEvents]
    eventsError.value = '无法从 B4 读取事件目录，已回退到认证上下文中的事件范围。'
  } finally {
    eventsLoading.value = false
  }
}

async function loadUsers(initial = false): Promise<void> {
  if (initial) loading.value = true
  else refreshing.value = true
  loadError.value = null
  try {
    users.value = await usersApi.listUsers()
  } catch (error) {
    const message = handle(error, '加载用户列表失败')
    if (message) loadError.value = message
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

// ---------------------------------------------------------------- create user
const showCreate = ref(false)
const creating = ref(false)
const createError = ref<string | null>(null)
const createNotice = ref<{ username: string; oneTimePassword: string | null } | null>(null)

const createForm = reactive({ username: '', role: 'viewer', eventIds: [] as string[] })

function toggleCreate(): void {
  showCreate.value = !showCreate.value
  createError.value = null
}

function resetCreateForm(): void {
  createForm.username = ''
  createForm.role = 'viewer'
  createForm.eventIds = []
}

async function submitCreate(): Promise<void> {
  createError.value = null
  const username = createForm.username.trim()
  if (username.length < 3) {
    createError.value = '用户名至少 3 个字符（服务端规则为准）。'
    return
  }
  // The center store requires at least one event scope for non-platform-admin
  // accounts, and the Web API cannot create platform_admin.
  if (createForm.eventIds.length === 0) {
    createError.value = '事件管理员和只读账号至少需要分配一个事件范围。'
    return
  }
  creating.value = true
  try {
    const result = await usersApi.createUser({
      username,
      role: createForm.role,
      event_ids: [...createForm.eventIds],
    })
    createNotice.value = { username, oneTimePassword: result.oneTimePassword }
    resetCreateForm()
    showCreate.value = false
    await loadUsers()
  } catch (error) {
    const message = handle(error, '创建用户失败')
    if (message) createError.value = message
  } finally {
    creating.value = false
  }
}

// ------------------------------------------------------------- role / scopes
const editingUserId = ref<string | null>(null)
const savingRole = ref<string | null>(null)
const editForm = reactive({ role: 'viewer', eventIds: [] as string[] })

function startEdit(user: UserModel): void {
  actionError.value = null
  if (user.role === 'platform_admin') {
    actionError.value =
      '平台管理员账号由中心本地 Owner 策略管理，Web 控制台不能修改其角色或事件范围。'
    return
  }
  editingUserId.value = user.id
  editForm.role = user.role || 'viewer'
  editForm.eventIds = [...user.eventIds]
}

function cancelEdit(): void {
  editingUserId.value = null
}

async function saveRole(user: UserModel): Promise<void> {
  actionError.value = null
  if (editForm.eventIds.length === 0) {
    actionError.value = '事件管理员和只读账号至少需要分配一个事件范围。'
    return
  }
  savingRole.value = user.id
  try {
    const result = await usersApi.setUserRole(user.id, {
      role: editForm.role,
      event_ids: [...editForm.eventIds],
    })
    editingUserId.value = null
    actionNotice.value = {
      title: `已更新用户 ${user.username} 的角色：${roleLabel(result.user?.role ?? editForm.role)}。`,
      oneTimePassword: null,
    }
    await loadUsers()
  } catch (error) {
    const message = handle(error, '更新用户角色失败')
    if (message) actionError.value = message
  } finally {
    savingRole.value = null
  }
}

// --------------------------------------------------------------- user actions
const pendingAction = ref<PendingAction | null>(null)
const confirmBusy = ref(false)
const busyUserId = ref<string | null>(null)
const actionNotice = ref<{ title: string; oneTimePassword: string | null } | null>(null)

async function runPendingAction(): Promise<void> {
  const action = pendingAction.value
  if (!action) return
  confirmBusy.value = true
  try {
    await action.run()
  } finally {
    confirmBusy.value = false
    pendingAction.value = null
  }
}

function cancelPendingAction(): void {
  if (!confirmBusy.value) pendingAction.value = null
}

function askToggleEnabled(user: UserModel): void {
  const disabling = user.enabled
  pendingAction.value = {
    title: disabling ? '禁用用户' : '启用用户',
    message: disabling
      ? `禁用后 ${user.username} 将无法登录。服务端会按既定规则处理其现有会话。确定继续？`
      : `启用后 ${user.username} 可以重新登录。确定继续？`,
    confirmLabel: disabling ? '禁用' : '启用',
    danger: disabling,
    run: async () => {
      busyUserId.value = user.id
      actionError.value = null
      try {
        if (disabling) await usersApi.disableUser(user.id)
        else await usersApi.enableUser(user.id)
        actionNotice.value = {
          title: `已${disabling ? '禁用' : '启用'}用户 ${user.username}。`,
          oneTimePassword: null,
        }
        await loadUsers()
      } catch (error) {
        const message = handle(error, `${disabling ? '禁用' : '启用'}用户失败`)
        if (message) actionError.value = message
      } finally {
        busyUserId.value = null
      }
    },
  }
}

function askResetPassword(user: UserModel): void {
  pendingAction.value = {
    title: '重置密码',
    message: `将为 ${user.username} 生成一次性密码，旧密码立即失效。一次性密码只在响应中返回一次。确定继续？`,
    confirmLabel: '重置密码',
    danger: true,
    run: async () => {
      busyUserId.value = user.id
      actionError.value = null
      try {
        const result = await usersApi.resetUserPassword(user.id)
        actionNotice.value = {
          title: result.oneTimePassword
            ? `已为 ${user.username} 重置密码，请立即安全转交一次性密码。`
            : `已为 ${user.username} 重置密码；服务端未返回一次性密码，请通过既定受控渠道获取。`,
          oneTimePassword: result.oneTimePassword,
        }
        await loadUsers()
      } catch (error) {
        const message = handle(error, '重置密码失败')
        if (message) actionError.value = message
      } finally {
        busyUserId.value = null
      }
    },
  }
}

// ------------------------------------------------------------------- sessions
const sessionsFor = ref<string | null>(null)
const sessionsLoading = ref(false)
const sessionsError = ref<string | null>(null)
const sessionsByUser = reactive<Record<string, SessionModel[]>>({})
const busySessionId = ref<string | null>(null)

async function loadUserSessions(user: UserModel): Promise<void> {
  sessionsLoading.value = true
  sessionsError.value = null
  try {
    sessionsByUser[user.id] = await usersApi.listUserSessions(user.id)
  } catch (error) {
    const message = handle(error, '加载用户会话失败')
    if (message) sessionsError.value = message
  } finally {
    sessionsLoading.value = false
  }
}

async function toggleSessions(user: UserModel): Promise<void> {
  if (sessionsFor.value === user.id) {
    sessionsFor.value = null
    return
  }
  sessionsFor.value = user.id
  await loadUserSessions(user)
}

function askRevokeUserSession(user: UserModel, session: SessionModel): void {
  pendingAction.value = {
    title: '撤销用户会话',
    message: `撤销 ${user.username} 的会话 ${shortId(session.id)} 后，该设备需要重新完成密码与两步验证。确定继续？`,
    confirmLabel: '撤销会话',
    danger: true,
    run: async () => {
      busySessionId.value = session.id
      actionError.value = null
      try {
        await usersApi.revokeUserSession(user.id, session.id)
        actionNotice.value = {
          title: `已撤销 ${user.username} 的会话 ${shortId(session.id)}。`,
          oneTimePassword: null,
        }
        await loadUserSessions(user)
      } catch (error) {
        const message = handle(error, '撤销用户会话失败')
        if (message) actionError.value = message
      } finally {
        busySessionId.value = null
      }
    },
  }
}

onMounted(() => {
  void loadUsers(true)
  void loadEventOptions()
})
</script>

<template>
  <div class="page stack-lg">
    <div class="page-intro">
      <p class="muted">
        用户管理仅对平台管理员开放。页面入口隐藏只是交互提示，中心服务仍会对每个请求独立校验角色与事件范围。
      </p>
    </div>

    <p v-if="eventsError" class="alert alert-warn" role="status">
      {{ eventsError }}
      <button type="button" class="btn btn-sm" :disabled="eventsLoading" @click="loadEventOptions">
        {{ eventsLoading ? '读取中…' : '重试' }}
      </button>
    </p>

    <div class="toolbar">
      <label class="field field--inline">
        <span class="field-label">筛选</span>
        <input
          v-model="filter"
          class="input input--search"
          type="search"
          placeholder="用户名 / 角色 / 事件 ID"
          autocomplete="off"
        />
      </label>
      <div class="inline-actions">
        <button type="button" class="btn btn-sm" :disabled="refreshing || loading" @click="loadUsers()">
          {{ refreshing ? '刷新中…' : '刷新' }}
        </button>
        <button type="button" class="btn btn-sm btn-primary" @click="toggleCreate">
          {{ showCreate ? '收起新建' : '新建用户' }}
        </button>
      </div>
    </div>

    <div v-if="createNotice" class="alert alert-success" role="status">
      <p>用户 <strong class="mono">{{ createNotice.username }}</strong> 已创建。</p>
      <div v-if="createNotice.oneTimePassword" class="one-time-secret">
        <span class="field-label">一次性密码（只显示一次）</span>
        <div class="input-row">
          <code class="mono">{{ createNotice.oneTimePassword }}</code>
          <CopyButton :value="createNotice.oneTimePassword" />
        </div>
      </div>
      <button type="button" class="btn btn-sm btn-quiet" @click="createNotice = null">关闭</button>
    </div>

    <div v-if="actionNotice" class="alert alert-success" role="status">
      <p>{{ actionNotice.title }}</p>
      <div v-if="actionNotice.oneTimePassword" class="one-time-secret">
        <span class="field-label">一次性密码（只显示一次）</span>
        <div class="input-row">
          <code class="mono">{{ actionNotice.oneTimePassword }}</code>
          <CopyButton :value="actionNotice.oneTimePassword" />
        </div>
      </div>
      <button type="button" class="btn btn-sm btn-quiet" @click="actionNotice = null">关闭</button>
    </div>

    <section v-if="showCreate" class="card">
      <h2 class="card-title">新建用户</h2>
      <form class="stack" novalidate @submit.prevent="submitCreate">
        <div class="form-grid">
          <label class="field">
            <span class="field-label">用户名</span>
            <input
              v-model="createForm.username"
              class="input"
              type="text"
              autocomplete="off"
              autocapitalize="none"
              spellcheck="false"
              placeholder="例如 ops-alice"
              :disabled="creating"
            />
            <span class="field-hint">服务端规则：小写字母、数字、下划线、短横线或点，3–64 个字符。</span>
          </label>

          <label class="field">
            <span class="field-label">角色</span>
            <select v-model="createForm.role" class="input" :disabled="creating">
              <option v-for="option in ASSIGNABLE_ROLE_OPTIONS" :key="option.value" :value="option.value">
                {{ option.label }} — {{ option.description }}
              </option>
            </select>
            <span class="field-hint">
              Web 控制台只能创建事件管理员或只读账号；平台管理员由中心本地 Owner 策略创建。
            </span>
          </label>
        </div>

        <div class="field">
          <span class="field-label">事件范围</span>
          <p v-if="assignmentOptions.length === 0" class="muted small">
            事件目录为空（B4 <code class="mono">/api/v1/events</code> 未返回数据）。可以创建空事件范围的账号，或稍后重试。
          </p>
          <div v-else class="check-list">
            <label v-for="scope in assignmentOptions" :key="scope.id" class="check">
              <input v-model="createForm.eventIds" type="checkbox" :value="scope.id" :disabled="creating" />
              <span class="mono small">{{ scope.id }}</span>
              <span>{{ scope.name }}</span>
            </label>
          </div>
        </div>

        <p v-if="createError" class="alert alert-error" role="alert">{{ createError }}</p>

        <div class="inline-actions">
          <button type="submit" class="btn btn-primary" :disabled="creating">
            {{ creating ? '创建中…' : '创建用户' }}
          </button>
          <button type="button" class="btn" :disabled="creating" @click="toggleCreate">取消</button>
        </div>
      </form>
    </section>

    <p v-if="actionError" class="alert alert-error" role="alert">{{ actionError }}</p>

    <StateBlock v-if="loading" kind="loading" title="正在加载用户列表…" />
    <StateBlock
      v-else-if="loadError"
      kind="error"
      title="用户列表加载失败"
      :message="loadError"
      @retry="loadUsers(true)"
    />
    <StateBlock
      v-else-if="users.length === 0"
      kind="empty"
      title="暂无用户"
      message="使用“新建用户”创建第一个账号。"
    />
    <StateBlock
      v-else-if="filteredUsers.length === 0"
      kind="empty"
      title="没有匹配的用户"
      message="调整筛选条件后重试。"
    />

    <section v-else class="card card--flush">
      <div class="table-wrap">
        <table class="table table--users">
          <thead>
            <tr>
              <th scope="col">用户</th>
              <th scope="col">角色</th>
              <th scope="col">状态</th>
              <th scope="col">事件范围</th>
              <th scope="col">最近登录</th>
              <th scope="col" class="text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="user in filteredUsers" :key="user.id">
              <tr>
                <td>
                  <div class="cell-stack">
                    <span class="mono">{{ user.username }}</span>
                    <span class="muted small mono">{{ shortId(user.id) }}</span>
                  </div>
                </td>
                <td><RoleBadge :role="user.role" /></td>
                <td>
                  <span class="badge" :class="user.enabled ? 'badge--ok' : 'badge--danger'">
                    {{ user.enabled ? '启用' : '禁用' }}
                  </span>
                </td>
                <td>
                  <span v-if="user.eventIds.length === 0" class="muted small">未分配</span>
                  <span v-else class="muted small" :title="user.eventIds.map(eventLabel).join('、')">
                    {{ eventSummary(user) }}
                  </span>
                </td>
                <td class="nowrap muted small">{{ formatTimestamp(user.lastLoginAt) }}</td>
                <td class="text-right">
                  <div class="row-actions">
                    <button
                      type="button"
                      class="btn btn-sm"
                      :disabled="busyUserId === user.id"
                      @click="askToggleEnabled(user)"
                    >
                      {{ user.enabled ? '禁用' : '启用' }}
                    </button>
                    <button
                      type="button"
                      class="btn btn-sm"
                      :disabled="busyUserId === user.id"
                      @click="askResetPassword(user)"
                    >
                      重置密码
                    </button>
                    <button type="button" class="btn btn-sm" @click="startEdit(user)">角色/范围</button>
                    <button type="button" class="btn btn-sm" @click="toggleSessions(user)">
                      {{ sessionsFor === user.id ? '收起会话' : '会话' }}
                    </button>
                  </div>
                </td>
              </tr>

              <tr v-if="editingUserId === user.id" class="table-row--panel">
                <td colspan="6">
                  <div class="role-editor">
                    <label class="field">
                      <span class="field-label">角色</span>
                      <select v-model="editForm.role" class="input">
                        <option v-for="option in ASSIGNABLE_ROLE_OPTIONS" :key="option.value" :value="option.value">
                          {{ option.label }} — {{ option.description }}
                        </option>
                      </select>
                    </label>
                    <div class="field">
                      <span class="field-label">事件范围</span>
                      <p v-if="assignmentOptions.length === 0" class="muted small">
                        事件目录为空（B4 <code class="mono">/api/v1/events</code> 未返回数据）。可以保存空事件范围，或稍后重试。
                      </p>
                      <div v-else class="check-list">
                        <label
                          v-for="scope in assignmentOptions"
                          :key="scope.id"
                          class="check"
                        >
                          <input v-model="editForm.eventIds" type="checkbox" :value="scope.id" />
                          <span class="mono small">{{ scope.id }}</span>
                          <span>{{ scope.name }}</span>
                        </label>
                      </div>
                    </div>
                    <div class="inline-actions">
                      <button
                        type="button"
                        class="btn btn-primary btn-sm"
                        :disabled="savingRole === user.id"
                        @click="saveRole(user)"
                      >
                        {{ savingRole === user.id ? '保存中…' : '保存角色与范围' }}
                      </button>
                      <button type="button" class="btn btn-sm" :disabled="savingRole === user.id" @click="cancelEdit">
                        取消
                      </button>
                      <span class="muted small">保存后该用户的所有会话都会被撤销，需要重新登录。</span>
                    </div>
                  </div>
                </td>
              </tr>

              <tr v-if="sessionsFor === user.id" class="table-row--panel">
                <td colspan="6">
                  <div class="session-panel">
                    <div class="session-panel__head">
                      <h3 class="session-panel__title">{{ user.username }} 的登录会话</h3>
                      <button
                        type="button"
                        class="btn btn-sm"
                        :disabled="sessionsLoading"
                        @click="loadUserSessions(user)"
                      >
                        {{ sessionsLoading ? '加载中…' : '刷新' }}
                      </button>
                    </div>
                    <p v-if="sessionsError" class="alert alert-error" role="alert">{{ sessionsError }}</p>
                    <p
                      v-else-if="sessionsLoading && !sessionsByUser[user.id]"
                      class="muted small"
                    >
                      正在加载会话…
                    </p>
                    <p
                      v-else-if="!sessionsByUser[user.id] || sessionsByUser[user.id].length === 0"
                      class="muted small"
                    >
                      没有会话记录。
                    </p>
                    <ul v-else class="session-list">
                      <li
                        v-for="session in sessionsByUser[user.id]"
                        :key="session.id"
                        class="session-list__item"
                      >
                        <div class="cell-stack">
                          <span class="mono small">{{ shortId(session.id) }}</span>
                          <span class="muted small">
                            {{ formatTimestamp(session.createdAt) }} · {{ shortUserAgent(session.userAgent) }} ·
                            {{ session.ip ?? '—' }}
                          </span>
                        </div>
                        <button
                          type="button"
                          class="btn btn-sm btn-danger"
                          :disabled="busySessionId === session.id"
                          @click="askRevokeUserSession(user, session)"
                        >
                          {{ busySessionId === session.id ? '撤销中…' : '撤销' }}
                        </button>
                      </li>
                    </ul>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </section>

    <ConfirmDialog
      :open="pendingAction !== null"
      :title="pendingAction?.title ?? ''"
      :message="pendingAction?.message ?? ''"
      :confirm-label="pendingAction?.confirmLabel ?? '确认'"
      :danger="pendingAction?.danger ?? false"
      :busy="confirmBusy"
      @confirm="runPendingAction"
      @cancel="cancelPendingAction"
    />
  </div>
</template>

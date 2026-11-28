<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import RoleBadge from './RoleBadge.vue'

interface NavItem {
  name: string
  label: string
  to: string
}

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const loggingOut = ref(false)
const logoutError = ref<string | null>(null)

const pageTitle = computed(() => {
  const title = route.meta.title
  return typeof title === 'string' ? title : '总览'
})

const navItems = computed<NavItem[]>(() => {
  const items: NavItem[] = [
    { name: 'dashboard', label: '总览', to: '/' },
    { name: 'account-sessions', label: '登录会话', to: '/account/sessions' },
    { name: 'account-security', label: '账户安全', to: '/account/security' },
    { name: 'account-password', label: '修改密码', to: '/account/password' },
  ]
  if (auth.isPlatformAdmin) {
    items.push({ name: 'admin-users', label: '用户管理', to: '/admin/users' })
  }
  return items
})

async function onLogout(): Promise<void> {
  loggingOut.value = true
  logoutError.value = null
  try {
    await auth.logout()
    await router.replace({ name: 'login' })
  } catch {
    logoutError.value = '退出登录失败，请重试。'
  } finally {
    loggingOut.value = false
  }
}
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <RouterLink class="brand" to="/">
        <span class="brand__mark" aria-hidden="true">UM</span>
        <span class="brand__text">
          <strong>UM-C</strong>
          <small>统一监控 · 运维控制台</small>
        </span>
      </RouterLink>

      <nav class="nav" aria-label="主导航">
        <RouterLink
          v-for="item in navItems"
          :key="item.name"
          :to="item.to"
          class="nav-link"
          :class="{ 'is-active': route.name === item.name }"
        >
          {{ item.label }}
        </RouterLink>
      </nav>

      <div class="sidebar__foot">
        <span class="edge-note">Cloudflare Access · 边缘认证</span>
        <span class="edge-note edge-note--muted">会话令牌不进入浏览器存储</span>
      </div>
    </aside>

    <div class="app-main">
      <header class="topbar">
        <h1 class="topbar__title">{{ pageTitle }}</h1>
        <div class="topbar__user">
          <div class="user-chip">
            <span class="user-chip__name">{{ auth.displayName || '未知用户' }}</span>
            <RoleBadge :role="auth.role" />
          </div>
          <button type="button" class="btn btn-sm" :disabled="loggingOut" @click="onLogout">
            {{ loggingOut ? '退出中…' : '退出登录' }}
          </button>
        </div>
      </header>

      <p v-if="logoutError" class="alert alert-error topbar__alert" role="alert">
        {{ logoutError }}
      </p>

      <main class="content">
        <RouterView />
      </main>

      <footer class="app-footer">
        UM-C · 统一监控控制台 · 事件范围 {{ auth.allowedEvents.length }} 个
      </footer>
    </div>
  </div>
</template>

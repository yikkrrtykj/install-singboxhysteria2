<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import RoleBadge from '@/components/RoleBadge.vue'

const auth = useAuthStore()

const quickLinks = computed(() => {
  const links = [
    {
      to: '/account/sessions',
      title: '登录会话',
      description: '查看当前账号的登录会话，撤销可疑设备。',
    },
    {
      to: '/account/security',
      title: '账户安全',
      description: '重新绑定 TOTP、重新生成恢复代码。',
    },
    {
      to: '/account/password',
      title: '修改密码',
      description: '更新当前账号密码。',
    },
  ]
  if (auth.isPlatformAdmin) {
    links.push({
      to: '/admin/users',
      title: '用户管理',
      description: '创建用户、启用/禁用、分配角色与事件范围。',
    })
  }
  return links
})
</script>

<template>
  <div class="page stack-lg">
    <div class="page-intro">
      <p class="muted">
        欢迎，<strong>{{ auth.displayName || '操作员' }}</strong>。本控制台提供 UM-C 认证、会话与用户管理基础设施；统一监控面板属于
        UM-D 范围，尚未实现。
      </p>
    </div>

    <section class="grid grid--2">
      <article class="card">
        <h2 class="card-title">当前账号</h2>
        <dl class="facts">
          <div class="facts__row">
            <dt>用户名</dt>
            <dd class="mono">{{ auth.displayName || '—' }}</dd>
          </div>
          <div class="facts__row">
            <dt>角色</dt>
            <dd><RoleBadge :role="auth.role" /></dd>
          </div>
          <div class="facts__row">
            <dt>账号 ID</dt>
            <dd class="mono">{{ auth.user?.id || '—' }}</dd>
          </div>
          <div class="facts__row">
            <dt>事件范围</dt>
            <dd>{{ auth.hasEventScopes ? `${auth.allowedEvents.length} 个` : '未分配' }}</dd>
          </div>
        </dl>
        <div class="inline-actions">
          <RouterLink class="btn btn-sm" to="/account/security">账户安全</RouterLink>
          <RouterLink class="btn btn-sm" to="/account/sessions">登录会话</RouterLink>
        </div>
      </article>

      <article class="card">
        <div class="card-title-row">
          <h2 class="card-title">系统健康</h2>
          <span class="badge badge--muted">占位</span>
        </div>
        <p class="muted">
          UM-C 不实现监控面板、指标图表或告警视图。统一监控与系统健康看板属于 UM-D 范围，本里程碑只保留占位。
        </p>
        <p class="muted small">
          B4 管理 API（<code class="mono">/api/v1/*</code>）的只读与变更客户端能力已在请求层预留；本页不会请求健康或监控数据。
        </p>
      </article>
    </section>

    <section class="card">
      <h2 class="card-title">事件范围</h2>
      <p v-if="!auth.hasEventScopes" class="muted">
        当前账号未被分配任何事件范围。平台管理员可以在“用户管理”中调整。
      </p>
      <ul v-else class="chip-list">
        <li v-for="scope in auth.allowedEvents" :key="scope.id" class="chip">
          <span class="mono small">{{ scope.id }}</span>
          <span>{{ scope.name }}</span>
        </li>
      </ul>
    </section>

    <section class="grid grid--2">
      <article v-for="link in quickLinks" :key="link.to" class="card card--link">
        <h2 class="card-title">{{ link.title }}</h2>
        <p class="muted">{{ link.description }}</p>
        <RouterLink class="btn btn-sm" :to="link.to">打开</RouterLink>
      </article>
    </section>
  </div>
</template>

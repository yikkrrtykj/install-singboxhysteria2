import type { RouteRecordRaw } from 'vue-router'
import LoginView from '@/views/LoginView.vue'
import TotpVerifyView from '@/views/TotpVerifyView.vue'
import TotpSetupView from '@/views/TotpSetupView.vue'
import RecoveryView from '@/views/RecoveryView.vue'
import SessionExpiredView from '@/views/SessionExpiredView.vue'
import ForbiddenView from '@/views/ForbiddenView.vue'
import NotFoundView from '@/views/NotFoundView.vue'
import AppShell from '@/components/AppShell.vue'
import DashboardView from '@/views/DashboardView.vue'
import AccountSessionsView from '@/views/AccountSessionsView.vue'
import AccountSecurityView from '@/views/AccountSecurityView.vue'
import AccountPasswordView from '@/views/AccountPasswordView.vue'
import AdminUsersView from '@/views/AdminUsersView.vue'

declare module 'vue-router' {
  interface RouteMeta {
    /** Public pages do not require an authenticated session. */
    public?: boolean
    /** Redirect authenticated users away (login page). */
    guestOnly?: boolean
    /** Requires an authenticated session (checked against /auth/context). */
    requiresAuth?: boolean
    /** Requires the platform_admin role (backend still enforces RBAC). */
    requiresPlatformAdmin?: boolean
    title?: string
  }
}

export const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { public: true, guestOnly: true, title: '登录' },
  },
  {
    path: '/totp',
    name: 'totp',
    component: TotpVerifyView,
    meta: { public: true, title: '两步验证' },
  },
  {
    path: '/setup-totp',
    name: 'totp-setup',
    component: TotpSetupView,
    meta: { public: true, title: '绑定身份验证器' },
  },
  {
    path: '/recovery',
    name: 'recovery',
    component: RecoveryView,
    meta: { public: true, title: '恢复代码登录' },
  },
  {
    path: '/expired',
    name: 'session-expired',
    component: SessionExpiredView,
    meta: { public: true, title: '会话已过期' },
  },
  {
    path: '/403',
    name: 'forbidden',
    component: ForbiddenView,
    meta: { public: true, title: '无权访问' },
  },
  {
    path: '/',
    component: AppShell,
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'dashboard',
        component: DashboardView,
        meta: { title: '总览' },
      },
      {
        path: 'account/sessions',
        name: 'account-sessions',
        component: AccountSessionsView,
        meta: { title: '登录会话' },
      },
      {
        path: 'account/security',
        name: 'account-security',
        component: AccountSecurityView,
        meta: { title: '账户安全' },
      },
      {
        path: 'account/password',
        name: 'account-password',
        component: AccountPasswordView,
        meta: { title: '修改密码' },
      },
      {
        path: 'admin/users',
        name: 'admin-users',
        component: AdminUsersView,
        meta: { title: '用户管理', requiresPlatformAdmin: true },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: NotFoundView,
    meta: { public: true, title: '页面不存在' },
  },
]

/**
 * Route guard driven by `GET /auth/context`.
 *
 * This is a UX gate, not a security boundary: the backend independently
 * resolves the session, role and event scopes for every request. Hiding a
 * button or route never replaces server-side authorization.
 */

import type { NavigationGuardWithThis, Router } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const ALLOWED_WHILE_PENDING = new Set(['totp', 'recovery', 'session-expired', 'forbidden', 'not-found'])
const ALLOWED_WHILE_SETUP = new Set(['totp-setup', 'recovery', 'session-expired', 'forbidden', 'not-found'])

function routeName(name: unknown): string {
  return typeof name === 'string' ? name : ''
}

const authGuard: NavigationGuardWithThis<undefined> = async (to) => {
  const auth = useAuthStore()

  if (!auth.initialized) {
    await auth.bootstrap()
  }

  // /auth/context unavailable (network/edge outage): let public pages render
  // with their own error state, but never assume a protected page is allowed.
  if (!auth.initialized) {
    if (to.meta.requiresAuth || to.meta.requiresPlatformAdmin) {
      return {
        name: 'login',
        query: {
          reason: 'context_unavailable',
          ...(to.fullPath !== '/' ? { redirect: to.fullPath } : {}),
        },
      }
    }
    return true
  }

  if (auth.expired && to.meta.requiresAuth) {
    return { name: 'session-expired' }
  }

  switch (auth.stage) {
    case 'authenticated': {
      if (to.meta.requiresPlatformAdmin && !auth.isPlatformAdmin) {
        return { name: 'forbidden' }
      }
      if (to.meta.guestOnly) {
        return { name: 'dashboard' }
      }
      if (to.name === 'totp' || to.name === 'totp-setup') {
        return { name: 'dashboard' }
      }
      return true
    }
    case 'totp_pending': {
      return ALLOWED_WHILE_PENDING.has(routeName(to.name)) ? true : { name: 'totp' }
    }
    case 'totp_setup': {
      return ALLOWED_WHILE_SETUP.has(routeName(to.name)) ? true : { name: 'totp-setup' }
    }
    default: {
      if (to.meta.requiresAuth || to.meta.requiresPlatformAdmin) {
        return {
          name: 'login',
          query: to.fullPath !== '/' ? { redirect: to.fullPath } : {},
        }
      }
      if (to.name === 'totp' || to.name === 'totp-setup') {
        return { name: 'login' }
      }
      return true
    }
  }
}

export function installAuthGuard(router: Router): void {
  router.beforeEach(authGuard)
}

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import * as authApi from '@/api/auth'
import { ApiError } from '@/api/http'
import type { UserModel } from '@/api/types'
import { useAuthStore } from '@/stores/auth'
import { installAuthGuard } from './guard'
import { safeRedirectTarget } from './redirect'
import { routes } from './routes'

vi.mock('@/api/auth', () => ({
  getAuthContext: vi.fn(),
  login: vi.fn(),
  verifyTotp: vi.fn(),
  submitRecovery: vi.fn(),
  logout: vi.fn(),
  fetchSessions: vi.fn(),
  revokeSession: vi.fn(),
  changePassword: vi.fn(),
  setupTotp: vi.fn(),
  confirmTotpSetup: vi.fn(),
  regenerateRecoveryCodes: vi.fn(),
}))

const mocked = vi.mocked(authApi)

function makeRouter(): Router {
  const router = createRouter({ history: createMemoryHistory(), routes })
  installAuthGuard(router)
  return router
}

function userWithRole(role: string): UserModel {
  return {
    id: 'u-1',
    username: 'alice',
    role,
    enabled: true,
    eventIds: ['ev-1'],
    totpEnrolled: true,
    createdAt: null,
    lastLoginAt: null,
  }
}

function anonymousState(): ReturnType<typeof useAuthStore> {
  const auth = useAuthStore()
  auth.initialized = true
  auth.authenticated = false
  auth.totpPending = false
  auth.totpSetupRequired = false
  auth.expired = false
  auth.expiredReason = null
  auth.user = null
  return auth
}

function authenticatedState(role = 'viewer'): ReturnType<typeof useAuthStore> {
  const auth = anonymousState()
  auth.authenticated = true
  auth.user = userWithRole(role)
  return auth
}

async function navigate(path: string): Promise<{ name: unknown; query: Record<string, string>; path: string }> {
  const router = makeRouter()
  await router.push(path)
  const current = router.currentRoute.value
  return {
    name: current.name,
    query: current.query as Record<string, string>,
    path: current.path,
  }
}

beforeEach(() => {
  setActivePinia(createPinia())
  vi.clearAllMocks()
})

describe('route guard: anonymous visitors', () => {
  it('redirects protected routes to login with the intended path', async () => {
    anonymousState()
    const result = await navigate('/account/sessions')
    expect(result.name).toBe('login')
    expect(result.query.redirect).toBe('/account/sessions')
  })

  it('does not add a redirect query for the root dashboard', async () => {
    anonymousState()
    const result = await navigate('/')
    expect(result.name).toBe('login')
    expect(result.query.redirect).toBeUndefined()
  })

  it('allows public recovery / 403 / 404 pages', async () => {
    anonymousState()
    expect((await navigate('/recovery')).name).toBe('recovery')
    expect((await navigate('/403')).name).toBe('forbidden')
    expect((await navigate('/definitely-missing')).name).toBe('not-found')
  })

  it('does not allow totp or setup pages without a pending preauth session', async () => {
    anonymousState()
    expect((await navigate('/totp')).name).toBe('login')
    expect((await navigate('/setup-totp')).name).toBe('login')
  })
})

describe('route guard: pending second factor', () => {
  it('forces the TOTP challenge page for any other route', async () => {
    const auth = anonymousState()
    auth.totpPending = true
    expect((await navigate('/')).name).toBe('totp')
    expect((await navigate('/login')).name).toBe('totp')
  })

  it('allows the TOTP page, recovery and expired pages', async () => {
    const auth = anonymousState()
    auth.totpPending = true
    expect((await navigate('/totp')).name).toBe('totp')
    expect((await navigate('/recovery')).name).toBe('recovery')
    expect((await navigate('/expired')).name).toBe('session-expired')
  })

  it('forces first-time TOTP setup for the setup stage', async () => {
    const auth = anonymousState()
    auth.totpSetupRequired = true
    expect((await navigate('/')).name).toBe('totp-setup')
    expect((await navigate('/account/security')).name).toBe('totp-setup')
    expect((await navigate('/setup-totp')).name).toBe('totp-setup')
  })
})

describe('route guard: authenticated users', () => {
  it('redirects the login page to the dashboard', async () => {
    authenticatedState('viewer')
    expect((await navigate('/login')).name).toBe('dashboard')
  })

  it('allows account pages for every authenticated role', async () => {
    authenticatedState('viewer')
    expect((await navigate('/')).name).toBe('dashboard')
    expect((await navigate('/account/sessions')).name).toBe('account-sessions')
    expect((await navigate('/account/security')).name).toBe('account-security')
    expect((await navigate('/account/password')).name).toBe('account-password')
  })

  it('blocks non-platform-admins from the user administration route', async () => {
    authenticatedState('event_admin')
    expect((await navigate('/admin/users')).name).toBe('forbidden')
  })

  it('allows platform admins into user administration', async () => {
    authenticatedState('platform_admin')
    expect((await navigate('/admin/users')).name).toBe('admin-users')
  })

  it('keeps the 404 page for authenticated users', async () => {
    authenticatedState('viewer')
    expect((await navigate('/missing')).name).toBe('not-found')
  })
})

describe('route guard: expired session and context outage', () => {
  it('routes an expired authenticated user to the expired page', async () => {
    const auth = anonymousState()
    auth.expired = true
    expect((await navigate('/')).name).toBe('session-expired')
  })

  it('falls back to login when /auth/context is unavailable', async () => {
    mocked.getAuthContext.mockRejectedValue(new ApiError(0, 'network_error', 'offline', true))
    const result = await navigate('/admin/users')
    expect(result.name).toBe('login')
    expect(result.query.reason).toBe('context_unavailable')
    expect(result.query.redirect).toBe('/admin/users')
  })
})

describe('safeRedirectTarget', () => {
  it('accepts internal absolute paths only', () => {
    expect(safeRedirectTarget('/account/sessions')).toBe('/account/sessions')
    expect(safeRedirectTarget('//evil.example')).toBeNull()
    expect(safeRedirectTarget('/\\evil.example')).toBeNull()
    expect(safeRedirectTarget('https://evil.example')).toBeNull()
    expect(safeRedirectTarget('account/sessions')).toBeNull()
    expect(safeRedirectTarget(undefined)).toBeNull()
  })
})

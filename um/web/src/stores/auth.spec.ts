import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import * as authApi from '@/api/auth'
import { ApiError, getCsrfToken, setCsrfToken } from '@/api/http'
import type { AuthSnapshot, TotpSetupModel, UserModel } from '@/api/types'
import { useAuthStore } from './auth'

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

function snapshot(overrides: Partial<AuthSnapshot> = {}): AuthSnapshot {
  return {
    stage: 'anonymous',
    authenticated: false,
    totpSetupRequired: false,
    totpPending: false,
    user: null,
    allowedEvents: [],
    csrfToken: 'preauth-csrf',
    recoveryCodesRemaining: null,
    recoveryCodes: [],
    totpSetup: null,
    raw: {},
    ...overrides,
  }
}

const platformAdmin: UserModel = {
  id: 'u-1',
  username: 'alice',
  role: 'platform_admin',
  enabled: true,
  eventIds: ['ev-1'],
  totpEnrolled: true,
  createdAt: null,
  lastLoginAt: null,
}

const authenticatedSnapshot = (): AuthSnapshot =>
  snapshot({
    stage: 'authenticated',
    authenticated: true,
    user: platformAdmin,
    allowedEvents: [{ id: 'ev-1', name: '生产事件' }],
    csrfToken: 'active-csrf',
  })

beforeEach(() => {
  setActivePinia(createPinia())
  vi.clearAllMocks()
  setCsrfToken(null)
})

describe('auth store bootstrap', () => {
  it('hydrates anonymous preauth state from /auth/context', async () => {
    mocked.getAuthContext.mockResolvedValue(snapshot({ csrfToken: 'preauth-1' }))
    const store = useAuthStore()

    await expect(store.bootstrap()).resolves.toBe(true)

    expect(store.initialized).toBe(true)
    expect(store.stage).toBe('anonymous')
    expect(store.user).toBeNull()
    expect(getCsrfToken()).toBe('preauth-1')
    expect(store.hasCsrfToken()).toBe(true)
  })

  it('hydrates an authenticated platform admin with role helpers and event scopes', async () => {
    mocked.getAuthContext.mockResolvedValue(authenticatedSnapshot())
    const store = useAuthStore()

    await expect(store.bootstrap()).resolves.toBe(true)

    expect(store.stage).toBe('authenticated')
    expect(store.isAuthenticated).toBe(true)
    expect(store.isPlatformAdmin).toBe(true)
    expect(store.displayName).toBe('alice')
    expect(store.hasEventScopes).toBe(true)
    expect(store.allowedEvents).toEqual([{ id: 'ev-1', name: '生产事件' }])
  })

  it('records a bootstrap failure without assuming authentication', async () => {
    mocked.getAuthContext.mockRejectedValue(new ApiError(0, 'network_error', 'offline', true))
    const store = useAuthStore()

    await expect(store.bootstrap()).resolves.toBe(false)

    expect(store.initialized).toBe(false)
    expect(store.stage).toBe('anonymous')
    expect(store.bootstrapError).toContain('网络')
  })

  it('ensureContext refetches when no in-memory CSRF token is present', async () => {
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: null }))
      .mockResolvedValueOnce(snapshot({ csrfToken: 'fresh-preauth' }))
    const store = useAuthStore()

    await store.bootstrap()
    expect(getCsrfToken()).toBeNull()

    await expect(store.ensureContext()).resolves.toBe(true)
    expect(getCsrfToken()).toBe('fresh-preauth')
    expect(mocked.getAuthContext).toHaveBeenCalledTimes(2)
  })
})

describe('auth store login and second factor', () => {
  it('enters the TOTP pending stage after a password login', async () => {
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: 'preauth-1' }))
      .mockResolvedValueOnce(snapshot({ stage: 'totp_pending', totpPending: true, csrfToken: 'pending-csrf' }))
    mocked.login.mockResolvedValue(
      snapshot({ stage: 'totp_pending', totpPending: true, csrfToken: 'pending-csrf' }),
    )
    const store = useAuthStore()

    await expect(store.login('alice', 'secret')).resolves.toBe('totp_pending')

    expect(store.stage).toBe('totp_pending')
    expect(getCsrfToken()).toBe('pending-csrf')
    expect(mocked.login).toHaveBeenCalledWith('alice', 'secret')
  })

  it('enters the TOTP setup stage for first-time enrollment', async () => {
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: 'preauth-1' }))
      .mockResolvedValueOnce(
        snapshot({ stage: 'totp_setup', totpSetupRequired: true, csrfToken: 'setup-csrf' }),
      )
    mocked.login.mockResolvedValue(
      snapshot({ stage: 'totp_setup', totpSetupRequired: true, csrfToken: 'setup-csrf' }),
    )
    const store = useAuthStore()

    await expect(store.login('alice', 'secret')).resolves.toBe('totp_setup')
    expect(store.totpSetupRequired).toBe(true)
    expect(store.stage).toBe('totp_setup')
  })

  it('reaches the authenticated stage after TOTP verification', async () => {
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: 'preauth-1' }))
      .mockResolvedValueOnce(authenticatedSnapshot())
    mocked.verifyTotp.mockResolvedValue(authenticatedSnapshot())
    const store = useAuthStore()

    await store.bootstrap()
    await expect(store.verifyTotp('123456')).resolves.toBe('authenticated')

    expect(store.isAuthenticated).toBe(true)
    expect(store.user?.username).toBe('alice')
    expect(store.expired).toBe(false)
    expect(mocked.verifyTotp).toHaveBeenCalledWith('123456')
  })

  it('surfaces invalid credentials without expiring the session', async () => {
    mocked.getAuthContext.mockResolvedValue(snapshot({ csrfToken: 'preauth-1' }))
    mocked.login.mockRejectedValue(new ApiError(401, 'invalid_credentials', 'bad', false))
    const store = useAuthStore()

    await expect(store.login('alice', 'wrong')).rejects.toBeInstanceOf(ApiError)

    expect(store.stage).toBe('anonymous')
    expect(store.expired).toBe(false)
    expect(store.user).toBeNull()
  })

  it('completes recovery-code login', async () => {
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: 'preauth-1' }))
      .mockResolvedValueOnce(authenticatedSnapshot())
    mocked.submitRecovery.mockResolvedValue(authenticatedSnapshot())
    const store = useAuthStore()

    await store.bootstrap()
    await expect(store.submitRecovery('alice', 'secret', 'CODE-1')).resolves.toBe('authenticated')
    expect(mocked.submitRecovery).toHaveBeenCalledWith('alice', 'secret', 'CODE-1')
    expect(store.isAuthenticated).toBe(true)
  })
})

describe('auth store account security actions', () => {
  it('clears user, TOTP and CSRF state on logout', async () => {
    mocked.getAuthContext.mockResolvedValue(authenticatedSnapshot())
    mocked.logout.mockResolvedValue(null)
    const store = useAuthStore()
    await store.bootstrap()

    await store.logout()

    expect(store.stage).toBe('anonymous')
    expect(store.user).toBeNull()
    expect(store.allowedEvents).toEqual([])
    expect(getCsrfToken()).toBeNull()
    expect(store.expired).toBe(false)
    expect(mocked.logout).toHaveBeenCalledTimes(1)
  })

  it('keeps the new CSRF token returned by TOTP setup', async () => {
    mocked.setupTotp.mockResolvedValue({
      secret: 'JBSWY3DPEHPK3PXP',
      otpauthUrl: 'otpauth://totp/UM-C:alice?secret=JBSWY3DPEHPK3PXP',
      issuer: 'UM-C',
      accountName: 'alice',
      csrfToken: 'setup-csrf-2',
      raw: {},
    } satisfies TotpSetupModel)
    const store = useAuthStore()

    const setup = await store.beginTotpSetup()

    expect(setup.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(store.totpSetup?.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(getCsrfToken()).toBe('setup-csrf-2')
  })

  it('passes the current password to re-enrolment', async () => {
    mocked.setupTotp.mockResolvedValue({
      secret: 'RE-ENROLL',
      otpauthUrl: 'otpauth://totp/UM-C:alice?secret=RE-ENROLL',
      issuer: 'UM-C',
      accountName: 'alice',
      csrfToken: null,
      raw: {},
    } satisfies TotpSetupModel)
    const store = useAuthStore()

    await store.beginTotpSetup('current-password')

    expect(mocked.setupTotp).toHaveBeenCalledWith(
      expect.objectContaining({ issuer: 'UM-C' }),
      'current-password',
    )
  })

  it('keeps setup material returned directly by the center login response', async () => {
    const material: TotpSetupModel = {
      secret: 'LOGIN-SETUP-SECRET',
      otpauthUrl: 'otpauth://totp/UM-C:alice?secret=LOGIN-SETUP-SECRET',
      issuer: 'UM Center',
      accountName: 'alice',
      csrfToken: null,
      raw: {},
    }
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: 'preauth-1' }))
      .mockResolvedValue(
        snapshot({
          stage: 'totp_setup',
          totpSetupRequired: true,
          user: { ...platformAdmin, totpEnrolled: false },
          csrfToken: 'setup-csrf',
        }),
      )
    mocked.login.mockResolvedValue(
      snapshot({
        stage: 'totp_setup',
        totpSetupRequired: true,
        totpSetup: material,
        csrfToken: 'setup-csrf',
      }),
    )
    const store = useAuthStore()

    await expect(store.login('alice', 'secret')).resolves.toBe('totp_setup')
    expect(store.totpSetup?.secret).toBe('LOGIN-SETUP-SECRET')
  })

  it('prefers recovery setup material over the ambiguous context stage', async () => {
    const material: TotpSetupModel = {
      secret: 'RECOVERY-SETUP-SECRET',
      otpauthUrl: 'otpauth://totp/UM-C:alice?secret=RECOVERY-SETUP-SECRET',
      issuer: 'UM Center',
      accountName: 'alice',
      csrfToken: null,
      raw: {},
    }
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: 'preauth-1' }))
      .mockResolvedValue(
        snapshot({
          stage: 'totp_pending',
          totpPending: true,
          user: { ...platformAdmin, totpEnrolled: true },
          csrfToken: 'setup-csrf',
        }),
      )
    mocked.submitRecovery.mockResolvedValue(
      snapshot({
        stage: 'totp_setup',
        totpSetupRequired: true,
        totpSetup: material,
        csrfToken: 'setup-csrf',
      }),
    )
    const store = useAuthStore()

    await store.bootstrap()
    await expect(store.submitRecovery('alice', 'secret', 'CODE-1')).resolves.toBe('totp_setup')
    expect(store.totpSetup?.secret).toBe('RECOVERY-SETUP-SECRET')
  })

  it('returns one-time recovery codes from TOTP confirmation', async () => {
    mocked.getAuthContext.mockResolvedValue(authenticatedSnapshot())
    mocked.confirmTotpSetup.mockResolvedValue(
      snapshot({
        stage: 'authenticated',
        authenticated: true,
        recoveryCodes: ['AAAA-BBBB', 'CCCC-DDDD'],
        recoveryCodesRemaining: 8,
        csrfToken: 'after-confirm',
      }),
    )
    const store = useAuthStore()

    const result = await store.confirmTotpSetup('123456')

    expect(result.recoveryCodes).toEqual(['AAAA-BBBB', 'CCCC-DDDD'])
    expect(store.recoveryCodesRemaining).toBe(8)
    // /auth/context is authoritative for the current CSRF token.
    expect(getCsrfToken()).toBe('active-csrf')
    expect(store.totpSetup).toBeNull()
  })

  it('retains the confirmation CSRF token when the context refresh omits it', async () => {
    mocked.getAuthContext.mockResolvedValue(snapshot({ csrfToken: null }))
    mocked.confirmTotpSetup.mockResolvedValue(
      snapshot({ stage: 'authenticated', authenticated: true, recoveryCodes: [], csrfToken: 'confirm-csrf' }),
    )
    const store = useAuthStore()

    await store.confirmTotpSetup('123456')

    expect(getCsrfToken()).toBe('confirm-csrf')
  })

  it('updates the remaining recovery-code count after regeneration', async () => {
    mocked.regenerateRecoveryCodes.mockResolvedValue({ codes: ['NEW-1'], remaining: 10 })
    const store = useAuthStore()

    const result = await store.regenerateRecoveryCodes()

    expect(result.codes).toEqual(['NEW-1'])
    expect(store.recoveryCodesRemaining).toBe(10)
  })

  it('changes the password and refreshes the context', async () => {
    mocked.getAuthContext.mockResolvedValue(authenticatedSnapshot())
    mocked.changePassword.mockResolvedValue({ reloginRequired: false })
    const store = useAuthStore()
    await store.bootstrap()

    await store.changePassword('old-password', 'new-password-123')

    expect(mocked.changePassword).toHaveBeenCalledWith('old-password', 'new-password-123')
    expect(mocked.getAuthContext).toHaveBeenCalledTimes(2)
  })

  it('clears the session when the center requires re-login after a password change', async () => {
    mocked.getAuthContext.mockResolvedValue(authenticatedSnapshot())
    mocked.changePassword.mockResolvedValue({ reloginRequired: true })
    const store = useAuthStore()
    await store.bootstrap()

    const result = await store.changePassword('old-password', 'new-password-123')

    expect(result.reloginRequired).toBe(true)
    expect(store.stage).toBe('anonymous')
    expect(store.user).toBeNull()
    expect(store.initialized).toBe(true)
    expect(store.expired).toBe(false)
    expect(getCsrfToken()).toBeNull()
  })
})

describe('auth store expired state', () => {
  it('clears sensitive memory state and records the expired reason', async () => {
    mocked.getAuthContext.mockResolvedValue(authenticatedSnapshot())
    const store = useAuthStore()
    await store.bootstrap()

    store.markSessionExpired(new ApiError(401, 'session_expired', 'expired', false))

    expect(store.stage).toBe('anonymous')
    expect(store.expired).toBe(true)
    expect(store.expiredReason).toContain('会话已过期')
    expect(store.user).toBeNull()
    expect(getCsrfToken()).toBeNull()
    expect(store.hasCsrfToken()).toBe(false)
  })
})

describe('storage hygiene', () => {
  it('never writes auth state to localStorage or sessionStorage', async () => {
    const localSet = vi.spyOn(window.localStorage, 'setItem')
    const sessionSet = vi.spyOn(window.sessionStorage, 'setItem')
    mocked.getAuthContext
      .mockResolvedValueOnce(snapshot({ csrfToken: 'preauth-1' }))
      .mockResolvedValueOnce(authenticatedSnapshot())
    mocked.login.mockResolvedValue(authenticatedSnapshot())
    const store = useAuthStore()

    await store.login('alice', 'secret')

    expect(localSet).not.toHaveBeenCalled()
    expect(sessionSet).not.toHaveBeenCalled()
    expect(getCsrfToken()).toBe('active-csrf')
  })
})

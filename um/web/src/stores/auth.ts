/**
 * In-memory authentication state for UM-C.
 *
 * No token, CSRF value, user object or recovery code is ever persisted to
 * `localStorage`/`sessionStorage`; a page refresh rehydrates through
 * `GET /auth/context` using the server-set HttpOnly cookie.
 */

import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import * as authApi from '@/api/auth'
import { getCsrfToken, resetCsrfToken, setCsrfToken, toApiError } from '@/api/http'
import type {
  AuthSnapshot,
  AuthStage,
  EventScope,
  PasswordChangeResult,
  RecoveryCodesResult,
  SessionModel,
  TotpSetupModel,
  UserModel,
} from '@/api/types'
import { describeApiError } from '@/utils/errors'

export const useAuthStore = defineStore('auth', () => {
  const initialized = ref(false)
  const bootstrapping = ref(false)
  const bootstrapError = ref<string | null>(null)

  const authenticated = ref(false)
  const totpSetupRequired = ref(false)
  const totpPending = ref(false)
  const user = ref<UserModel | null>(null)
  const allowedEvents = ref<EventScope[]>([])
  const recoveryCodesRemaining = ref<number | null>(null)

  const expired = ref(false)
  const expiredReason = ref<string | null>(null)

  /** Current TOTP enrolment material. Kept in memory only; never persisted. */
  const totpSetup = ref<TotpSetupModel | null>(null)

  let bootstrapPromise: Promise<boolean> | null = null

  const stage = computed<AuthStage>(() => {
    if (authenticated.value) return 'authenticated'
    if (totpSetupRequired.value) return 'totp_setup'
    if (totpPending.value) return 'totp_pending'
    return 'anonymous'
  })
  const isAuthenticated = computed(() => authenticated.value)
  const role = computed(() => user.value?.role ?? '')
  const isPlatformAdmin = computed(() => role.value === 'platform_admin')
  const displayName = computed(() => user.value?.username ?? '')
  const hasEventScopes = computed(() => allowedEvents.value.length > 0)

  function applySnapshot(snapshot: AuthSnapshot): void {
    authenticated.value = snapshot.authenticated
    totpSetupRequired.value = snapshot.totpSetupRequired
    totpPending.value = snapshot.totpPending
    user.value = snapshot.user
    allowedEvents.value = snapshot.allowedEvents
    recoveryCodesRemaining.value = snapshot.recoveryCodesRemaining
    if (snapshot.csrfToken) setCsrfToken(snapshot.csrfToken)
    if (snapshot.totpSetup) totpSetup.value = snapshot.totpSetup
    if (snapshot.authenticated) {
      expired.value = false
      expiredReason.value = null
      if (stage.value === 'authenticated') totpSetup.value = null
    }
  }

  function resetClientState(): void {
    authenticated.value = false
    totpSetupRequired.value = false
    totpPending.value = false
    user.value = null
    allowedEvents.value = []
    recoveryCodesRemaining.value = null
    totpSetup.value = null
    resetCsrfToken()
  }

  async function tryRefreshContext(): Promise<boolean> {
    try {
      const snapshot = await authApi.getAuthContext()
      applySnapshot(snapshot)
      return true
    } catch {
      return false
    }
  }

  async function bootstrap(force = false): Promise<boolean> {
    if (initialized.value && !force) return true
    if (bootstrapPromise) return bootstrapPromise

    bootstrapPromise = (async () => {
      bootstrapping.value = true
      bootstrapError.value = null
      try {
        const snapshot = await authApi.getAuthContext()
        applySnapshot(snapshot)
        initialized.value = true
        return true
      } catch (error) {
        bootstrapError.value = describeApiError(error, '无法获取认证上下文')
        return initialized.value
      } finally {
        bootstrapping.value = false
      }
    })()

    try {
      return await bootstrapPromise
    } finally {
      bootstrapPromise = null
    }
  }

  /** Ensure `/auth/context` ran and a preauth CSRF token is in memory. */
  async function ensureContext(): Promise<boolean> {
    if (!initialized.value) return bootstrap()
    if (getCsrfToken() === null) return bootstrap(true)
    return true
  }

  /**
   * Prefer the authoritative `/auth/context`, fall back to the mutation
   * response if the context refresh is temporarily unavailable.
   */
  async function reconcileWithContext(fallback: AuthSnapshot): Promise<AuthStage> {
    if (fallback.csrfToken) setCsrfToken(fallback.csrfToken)
    if (fallback.totpSetup) totpSetup.value = fallback.totpSetup
    const refreshed = await tryRefreshContext()
    // `/auth/context` does not expose "pending vs setup" for the center Web
    // plane; explicit setup material in the mutation response is authoritative.
    if (fallback.totpSetup && stage.value !== 'authenticated') {
      totpSetupRequired.value = true
      totpPending.value = false
    }
    if (!refreshed) {
      applySnapshot(fallback)
      initialized.value = true
    }
    return stage.value
  }

  async function login(username: string, password: string): Promise<AuthStage> {
    await ensureContext()
    const snapshot = await authApi.login(username, password)
    return reconcileWithContext(snapshot)
  }

  async function verifyTotp(code: string): Promise<AuthStage> {
    const snapshot = await authApi.verifyTotp(code)
    return reconcileWithContext(snapshot)
  }

  async function submitRecovery(
    username: string,
    password: string,
    recoveryCode: string,
  ): Promise<AuthStage> {
    await ensureContext()
    const snapshot = await authApi.submitRecovery(username, password, recoveryCode)
    return reconcileWithContext(snapshot)
  }

  async function logout(): Promise<boolean> {
    let serverLogoutOK = true
    try {
      await authApi.logout()
    } catch {
      // Local memory is cleared for safety, but the caller must show that the
      // server session may still be valid when revocation failed.
      serverLogoutOK = false
    }
    resetClientState()
    initialized.value = true
    bootstrapError.value = null
    expired.value = false
    expiredReason.value = null
    return serverLogoutOK
  }

  async function changePassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<PasswordChangeResult> {
    const result = await authApi.changePassword(currentPassword, newPassword)
    if (result.reloginRequired) {
      // The center invalidates all cookies after a password change.
      resetClientState()
      initialized.value = true
      bootstrapError.value = null
      expired.value = false
      expiredReason.value = null
      return result
    }
    await tryRefreshContext()
    return result
  }

  async function beginTotpSetup(password?: string): Promise<TotpSetupModel> {
    if (totpSetup.value) return totpSetup.value
    const setup = await authApi.setupTotp(
      { issuer: 'UM-C', accountName: user.value?.username },
      password,
    )
    totpSetup.value = setup
    if (setup.csrfToken) setCsrfToken(setup.csrfToken)
    return setup
  }

  async function confirmTotpSetup(
    code: string,
  ): Promise<{ stage: AuthStage; recoveryCodes: string[] }> {
    const snapshot = await authApi.confirmTotpSetup(code)
    if (snapshot.csrfToken) setCsrfToken(snapshot.csrfToken)
    // Keep the last known-good auth state if this refresh is momentarily
    // unavailable; the next request re-validates through `/auth/context`.
    const refreshed = await tryRefreshContext()
    if (!refreshed && snapshot.authenticated) applySnapshot(snapshot)
    if (snapshot.recoveryCodes.length > 0) {
      recoveryCodesRemaining.value = snapshot.recoveryCodesRemaining ?? recoveryCodesRemaining.value
    }
    totpSetup.value = null
    return { stage: stage.value, recoveryCodes: snapshot.recoveryCodes }
  }

  async function regenerateRecoveryCodes(): Promise<RecoveryCodesResult> {
    const result = await authApi.regenerateRecoveryCodes()
    if (result.remaining !== null) recoveryCodesRemaining.value = result.remaining
    return result
  }

  async function fetchSessions(): Promise<SessionModel[]> {
    return authApi.fetchSessions()
  }

  async function revokeSession(sessionId: string): Promise<void> {
    await authApi.revokeSession(sessionId)
  }

  function markSessionExpired(error?: unknown): void {
    const apiError = error === undefined ? null : toApiError(error)
    resetClientState()
    initialized.value = true
    bootstrapping.value = false
    bootstrapError.value = null
    expired.value = true
    expiredReason.value = apiError
      ? describeApiError(apiError, '会话已过期，请重新登录。')
      : '会话已过期，请重新登录。'
  }

  function clearExpiredState(): void {
    expired.value = false
    expiredReason.value = null
  }

  /** Exposed for tests/diagnostics: current in-memory CSRF presence. */
  function hasCsrfToken(): boolean {
    return getCsrfToken() !== null
  }

  return {
    // state
    initialized,
    bootstrapping,
    bootstrapError,
    authenticated,
    totpSetupRequired,
    totpPending,
    user,
    allowedEvents,
    recoveryCodesRemaining,
    expired,
    expiredReason,
    totpSetup,
    // getters
    stage,
    isAuthenticated,
    role,
    isPlatformAdmin,
    displayName,
    hasEventScopes,
    // actions
    bootstrap,
    ensureContext,
    login,
    verifyTotp,
    submitRecovery,
    logout,
    changePassword,
    beginTotpSetup,
    confirmTotpSetup,
    regenerateRecoveryCodes,
    fetchSessions,
    revokeSession,
    markSessionExpired,
    clearExpiredState,
    hasCsrfToken,
  }
})

/** Type helper for consumers that hold the store instance. */
export type AuthStore = ReturnType<typeof useAuthStore>

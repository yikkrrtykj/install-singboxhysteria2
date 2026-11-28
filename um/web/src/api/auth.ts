/**
 * UM-C authentication endpoints.
 *
 * Cloudflare Access runs at the edge; these calls only use same-origin cookies
 * and the in-memory CSRF token (attached automatically by `http.ts`).
 *
 * The center Web plane (um/internal/web) is the concrete backend in this
 * repository. Where an endpoint differs from the earlier contract draft, this
 * module prefers the implemented endpoint and keeps a narrowly-scoped fallback
 * for the drafted variant (`/auth/totp/confirm`, `/auth/totp/setup`).
 */

import { ApiError, getJson, postJson } from './http'
import {
  normalizeAuthPayload,
  normalizePasswordChangeResult,
  normalizeRecoveryCodes,
  normalizeSessionList,
  normalizeTotpSetup,
  type TotpSetupFallback,
} from './normalize'
import type {
  AuthSnapshot,
  PasswordChangeResult,
  RecoveryCodesResult,
  SessionModel,
  TotpSetupModel,
} from './types'

function isMissingEndpoint(error: unknown): boolean {
  if (!(error instanceof ApiError)) return false
  return error.status === 404 || error.status === 405
}

export function getAuthContext(): Promise<AuthSnapshot> {
  // `allowAnonymous` because "not logged in yet" is a normal answer here.
  return getJson<unknown>('/auth/context', { allowAnonymous: true }).then(normalizeAuthPayload)
}

export function login(username: string, password: string): Promise<AuthSnapshot> {
  return postJson<unknown>(
    '/auth/login',
    { username, password },
    { allowAnonymous: true },
  ).then(normalizeAuthPayload)
}

export function verifyTotp(code: string): Promise<AuthSnapshot> {
  return postJson<unknown>('/auth/totp', { code }, { allowAnonymous: true }).then(normalizeAuthPayload)
}

/**
 * Complete first-time TOTP enrolment (or a re-enrolment started by
 * `setupTotp`). The implemented center confirms via `POST /auth/totp`; the
 * drafted contract used `POST /auth/totp/confirm`, so a 404/405 falls back.
 */
export async function confirmTotpSetup(code: string): Promise<AuthSnapshot> {
  try {
    const payload = await postJson<unknown>('/auth/totp/confirm', { code })
    return normalizeAuthPayload(payload)
  } catch (error) {
    if (!isMissingEndpoint(error)) throw error
    const payload = await postJson<unknown>('/auth/totp', { code })
    return normalizeAuthPayload(payload)
  }
}

export function submitRecovery(
  username: string,
  password: string,
  recoveryCode: string,
): Promise<AuthSnapshot> {
  return postJson<unknown>(
    '/auth/recovery',
    { username, password, recovery_code: recoveryCode },
    { allowAnonymous: true },
  ).then(normalizeAuthPayload)
}

export function logout(): Promise<unknown> {
  return postJson<unknown>('/auth/logout', undefined, { allowAnonymous: true })
}

export function fetchSessions(): Promise<SessionModel[]> {
  return getJson<unknown>('/auth/sessions').then(normalizeSessionList)
}

export function revokeSession(sessionId: string): Promise<unknown> {
  return postJson<unknown>(`/auth/sessions/${encodeURIComponent(sessionId)}/revoke`)
}

export function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<PasswordChangeResult> {
  return postJson<unknown>('/auth/password', {
    current_password: currentPassword,
    new_password: newPassword,
  }).then(normalizePasswordChangeResult)
}

/**
 * Start TOTP enrolment.
 *
 * - The implemented center returns first-time enrolment material directly from
 *   `/auth/login` and `/auth/recovery`, so callers normally pass the held
 *   material to the UI instead of calling this.
 * - Re-enrolment uses `POST /auth/totp/update` and requires the current
 *   password. The drafted `/auth/totp/setup` endpoint is tried as a fallback so
 *   both backend variants work.
 */
export async function setupTotp(
  fallback: TotpSetupFallback = {},
  password?: string,
): Promise<TotpSetupModel> {
  const currentPassword = password?.trim() ?? ''

  if (currentPassword.length > 0) {
    try {
      const payload = await postJson<unknown>('/auth/totp/update', {
        password: currentPassword,
      })
      return normalizeTotpSetup(payload, fallback)
    } catch (error) {
      if (!isMissingEndpoint(error)) throw error
      // Drafted backend variant: /auth/totp/setup has no body.
    }
  }

  try {
    const payload = await postJson<unknown>('/auth/totp/setup')
    return normalizeTotpSetup(payload, fallback)
  } catch (error) {
    if (!isMissingEndpoint(error)) throw error
    if (currentPassword.length === 0) {
      throw new ApiError(
        400,
        'password_required',
        '重新绑定身份验证器需要提供当前密码。',
        false,
      )
    }
    throw error
  }
}

export function regenerateRecoveryCodes(): Promise<RecoveryCodesResult> {
  return postJson<unknown>('/auth/recovery-codes').then(normalizeRecoveryCodes)
}

/**
 * Defensive payload normalizers.
 *
 * The UM-C backend contract is described in `um/web/README.md`. These helpers
 * accept the documented shapes plus benign aliases (snake_case/camelCase,
 * direct JSON or B4 `{v:1,data:...}` envelopes) so a contract detail change
 * does not crash the console. Unknown fields are ignored, never rendered raw.
 */

import { ApiError } from './http'
import type {
  AuthSnapshot,
  AuthStage,
  EventScope,
  MutationResult,
  PasswordChangeResult,
  RecoveryCodesResult,
  SessionModel,
  Timestamp,
  TotpSetupModel,
  UserModel,
} from './types'

const DEFAULT_TOTP_ISSUER = 'UM-C'

export function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

export function pickString(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) return value.trim()
  }
  return null
}

export function pickBoolean(...values: unknown[]): boolean | null {
  for (const value of values) {
    if (typeof value === 'boolean') return value
  }
  return null
}

export function pickNumber(...values: unknown[]): number | null {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string' && value.trim().length > 0 && Number.isFinite(Number(value))) {
      return Number(value)
    }
  }
  return null
}

export function pickTimestamp(...values: unknown[]): Timestamp {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string' && value.trim().length > 0) return value
  }
  return null
}

function asArray(value: unknown): unknown[] | null {
  return Array.isArray(value) ? value : null
}

export function normalizeEventScopes(value: unknown): EventScope[] {
  const scopes: EventScope[] = []
  const seen = new Set<string>()
  const push = (rawId: unknown, rawName: unknown): void => {
    const id = pickString(rawId, rawName)
    if (!id || seen.has(id)) return
    seen.add(id)
    scopes.push({ id, name: pickString(rawName, rawId) ?? id })
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === 'string') {
        push(item, item)
        continue
      }
      const record = asRecord(item)
      if (!record) continue
      push(
        pickString(record.id, record.event_id, record.eventId, record.slug),
        pickString(record.name, record.label, record.title),
      )
    }
    return scopes
  }

  const record = asRecord(value)
  if (record) {
    for (const [key, entry] of Object.entries(record)) {
      if (typeof entry === 'string') push(key, entry)
      else {
        const entryRecord = asRecord(entry)
        if (entryRecord) push(pickString(entryRecord.id, key), pickString(entryRecord.name, entryRecord.label, key))
      }
    }
  }
  return scopes
}

export function normalizeEventIds(value: unknown): string[] {
  return normalizeEventScopes(value).map((scope) => scope.id)
}

export function normalizeUser(raw: unknown): UserModel | null {
  const record = asRecord(raw)
  if (!record) return null

  const username = pickString(record.username, record.name, record.login)
  const id = pickString(record.id, record.user_id, record.userId, record.uid, username)
  if (!username && !id) return null

  const enabled = pickBoolean(record.enabled) ?? (pickBoolean(record.disabled) === true ? false : true)

  return {
    id: id ?? '',
    username: username ?? id ?? '',
    role: pickString(record.role) ?? '',
    enabled,
    eventIds: normalizeEventIds(
      record.event_ids ?? record.eventIds ?? record.allowed_events ?? record.allowedEvents ?? record.events,
    ),
    totpEnrolled: pickBoolean(record.totp_enrolled, record.totpEnrolled, record.totp_enabled),
    createdAt: pickTimestamp(record.created_at, record.createdAt),
    lastLoginAt: pickTimestamp(record.last_login_at, record.lastLoginAt, record.last_seen_at),
  }
}

function inferStateHint(record: Record<string, unknown>): string | null {
  const hint = pickString(record.status, record.state, record.stage, record.session_state)
  return hint ? hint.toLowerCase().replace(/\s+/g, '_') : null
}

function optionalTotpSetup(record: Record<string, unknown>): TotpSetupModel | null {
  const nested = asRecord(record.data)
  const hasMaterial =
    pickString(
      record.secret,
      record.base32,
      record.totp_secret,
      record.totpSecret,
      record.otpauth_url,
      record.otpauth_uri,
      record.otpauthUrl,
      record.provisioning_uri,
      record.provisioningUri,
      record.uri,
      nested?.secret,
      nested?.otpauth_url,
      nested?.otpauth_uri,
    ) !== null
  if (!hasMaterial) return null
  try {
    return normalizeTotpSetup(record, {
      issuer: 'UM-C',
      accountName: normalizeUser(record.user)?.username,
    })
  } catch {
    return null
  }
}

export function normalizeAuthPayload(payload: unknown): AuthSnapshot {
  const record = asRecord(payload) ?? {}
  const userRecord = asRecord(record.user ?? record.current_user ?? record.currentUser ?? record.account)
  const user = normalizeUser(userRecord)
  const stateHint = inferStateHint(record)

  const authenticated =
    pickBoolean(record.authenticated) ??
    (stateHint === 'authenticated' || stateHint === 'active' || stateHint === 'logged_in')

  const setupHint =
    stateHint === 'totp_setup' ||
    stateHint === 'totp_setup_required' ||
    stateHint === 'setup_required'
  const pendingHint =
    stateHint === 'totp_pending' ||
    stateHint === 'totp_required' ||
    stateHint === 'pending_totp' ||
    stateHint === 'totp_verification_required'

  let totpSetupRequired =
    pickBoolean(record.totp_setup_required, record.totpSetupRequired, record.setup_required) ?? setupHint
  let totpPending =
    pickBoolean(
      record.totp_required,
      record.totpRequired,
      record.pending_totp,
      record.totpPending,
      record.totp_pending,
    ) ?? pendingHint

  // The center Web plane's `/auth/context` does not expose a stage field; it
  // returns the authenticated=false user view for pending/setup sessions. The
  // user's TOTP enrolment flag disambiguates the common cases. A session created
  // by recovery-code login is a setup session even though the user was enrolled
  // before; responses for that flow carry explicit setup material/hints.
  if (!totpSetupRequired && !totpPending && !authenticated && user) {
    if (user.totpEnrolled === false) totpSetupRequired = true
    else if (user.totpEnrolled === true) totpPending = true
  }
  if (totpSetupRequired) totpPending = false

  const allowedEvents = normalizeEventScopes(
    record.allowed_events ??
      record.allowedEvents ??
      record.event_scopes ??
      record.eventScopes ??
      userRecord?.allowed_events ??
      userRecord?.event_ids,
  )
  const recoveryCodes = normalizeRecoveryCodes(
    record.recovery_codes ?? record.recoveryCodes,
  ).codes
  const recoveryCodesRemaining = pickNumber(
    record.recovery_codes_remaining,
    record.recoveryCodesRemaining,
    userRecord?.recovery_codes_remaining,
    userRecord?.recoveryCodesRemaining,
  )

  const stage: AuthStage = authenticated
    ? 'authenticated'
    : totpSetupRequired
      ? 'totp_setup'
      : totpPending
        ? 'totp_pending'
        : 'anonymous'

  return {
    stage,
    authenticated: stage === 'authenticated',
    totpSetupRequired: stage === 'totp_setup',
    totpPending: stage === 'totp_pending',
    user,
    allowedEvents,
    csrfToken: pickString(record.csrf_token, record.csrfToken, record.csrf),
    recoveryCodesRemaining,
    recoveryCodes,
    totpSetup: optionalTotpSetup(record),
    raw: record,
  }
}

export function normalizeSession(raw: unknown): SessionModel | null {
  const record = asRecord(raw)
  if (!record) return null
  const id = pickString(record.id, record.session_id, record.id_hash, record.session_hash)
  if (!id) return null
  return {
    id,
    current: pickBoolean(record.current, record.is_current, record.current_session) ?? false,
    state: pickString(record.state, record.status),
    createdAt: pickTimestamp(record.created_at, record.createdAt),
    lastSeenAt: pickTimestamp(record.last_seen_at, record.lastSeenAt),
    expiresAt: pickTimestamp(record.expires_at, record.expiresAt, record.absolute_expires_at),
    ip: pickString(record.ip, record.client_ip, record.remote_ip),
    userAgent: pickString(record.user_agent, record.userAgent),
  }
}

function unwrapList(payload: unknown, keys: readonly string[]): unknown[] {
  if (Array.isArray(payload)) return payload
  const record = asRecord(payload)
  if (!record) return []
  for (const key of keys) {
    const value = record[key]
    if (Array.isArray(value)) return value
  }
  for (const key of ['data', 'result', 'payload', 'items']) {
    if (key in record && record[key] !== undefined) {
      const nested = unwrapList(record[key], keys)
      if (nested.length > 0) return nested
    }
  }
  return []
}

export function normalizeSessionList(payload: unknown): SessionModel[] {
  return unwrapList(payload, ['sessions', 'login_sessions'])
    .map(normalizeSession)
    .filter((session): session is SessionModel => session !== null)
}

export function normalizeUserList(payload: unknown): UserModel[] {
  return unwrapList(payload, ['users', 'accounts'])
    .map(normalizeUser)
    .filter((user): user is UserModel => user !== null)
}

export function normalizeRecoveryCodes(payload: unknown): RecoveryCodesResult {
  const direct = asArray(payload)
  const record = asRecord(payload)
  const nested = asRecord(record?.data)
  const codeList =
    direct ??
    asArray(record?.recovery_codes) ??
    asArray(record?.codes) ??
    asArray(nested?.recovery_codes) ??
    asArray(nested?.codes) ??
    []

  const codes = codeList
    .map((item) => {
      if (typeof item === 'string') return item.trim()
      const record = asRecord(item)
      return pickString(record?.code, record?.value)
    })
    .filter((code): code is string => code !== null && code.length > 0)

  return {
    codes,
    remaining: pickNumber(
      record?.remaining,
      record?.recovery_codes_remaining,
      record?.recoveryCodesRemaining,
      nested?.remaining,
      nested?.recovery_codes_remaining,
    ),
  }
}

export interface OtpauthUriOptions {
  secret: string
  issuer: string
  account: string
  algorithm?: string
  digits?: number
  period?: number
}

export function buildOtpauthUri(options: OtpauthUriOptions): string {
  const issuer = options.issuer.trim() || DEFAULT_TOTP_ISSUER
  const account = options.account.trim() || 'operator'
  const label = `${issuer}:${account}`
  const params = new URLSearchParams({
    secret: options.secret.trim(),
    issuer,
    algorithm: options.algorithm ?? 'SHA1',
    digits: String(options.digits ?? 6),
    period: String(options.period ?? 30),
  })
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`
}

function extractSecretFromOtpauth(url: string | null): string | null {
  if (!url) return null
  try {
    const parsed = new URL(url)
    return pickString(parsed.searchParams.get('secret'))
  } catch {
    return null
  }
}

export interface TotpSetupFallback {
  issuer?: string
  accountName?: string
}

export function normalizeTotpSetup(payload: unknown, fallback: TotpSetupFallback = {}): TotpSetupModel {
  const record = asRecord(payload) ?? {}
  const nested = asRecord(record.data)
  const secret =
    pickString(
      record.secret,
      record.base32,
      record.totp_secret,
      record.totpSecret,
      nested?.secret,
      nested?.base32,
    ) ?? extractSecretFromOtpauth(
      pickString(
        record.otpauth_url,
        record.otpauth_uri,
        record.otpauthUrl,
        record.provisioning_uri,
        record.provisioningUri,
        record.uri,
        nested?.otpauth_url,
        nested?.otpauth_uri,
      ),
    )
  const otpauthRaw = pickString(
    record.otpauth_url,
    record.otpauth_uri,
    record.otpauthUrl,
    record.provisioning_uri,
    record.provisioningUri,
    record.uri,
    nested?.otpauth_url,
    nested?.otpauth_uri,
  )
  const issuer = pickString(record.issuer, nested?.issuer) ?? fallback.issuer ?? null
  const accountName =
    pickString(
      record.account,
      record.account_name,
      record.accountName,
      record.username,
      nested?.account,
      nested?.account_name,
    ) ??
    fallback.accountName ??
    null

  const otpauthUrl =
    otpauthRaw ??
    (secret
      ? buildOtpauthUri({
          secret,
          issuer: issuer ?? DEFAULT_TOTP_ISSUER,
          account: accountName ?? 'operator',
        })
      : '')

  if (!secret && !otpauthUrl) {
    throw new ApiError(
      502,
      'invalid_totp_setup',
      '服务端未返回 TOTP 密钥或 otpauth URI，无法完成绑定。',
      false,
      payload,
    )
  }

  return {
    secret: secret ?? '',
    otpauthUrl,
    issuer,
    accountName,
    csrfToken: pickString(record.csrf_token, record.csrfToken),
    raw: record,
  }
}

const ONE_TIME_PASSWORD_KEYS = [
  'password',
  'temporary_password',
  'temp_password',
  'initial_password',
  'one_time_password',
  'new_password',
  'generated_password',
] as const

export function normalizeMutationResult(payload: unknown): MutationResult {
  const record = asRecord(payload) ?? {}
  const data = asRecord(record.data)
  const nestedUser = asRecord(record.user) ?? asRecord(data?.user)

  const user =
    normalizeUser(nestedUser) ??
    normalizeUser(record.data) ??
    (pickString(record.username) ? normalizeUser(record) : null)

  let oneTimePassword: string | null = null
  for (const candidate of [record, data, nestedUser]) {
    if (!candidate) continue
    for (const key of ONE_TIME_PASSWORD_KEYS) {
      const value = pickString(candidate[key])
      if (value) {
        oneTimePassword = value
        break
      }
    }
    if (oneTimePassword) break
  }

  return { user, oneTimePassword }
}

/**
 * B4 `GET /api/v1/events` returns `{events:[{event_id, display_name, ...}]}`
 * inside the standard `{v:1,data}` envelope. Used by the user administration
 * page to offer real event scopes for assignment.
 */
export function normalizeEventList(payload: unknown): EventScope[] {
  const seen = new Set<string>()
  const scopes: EventScope[] = []
  for (const item of unwrapList(payload, ['events', 'items'])) {
    if (typeof item === 'string') {
      if (!seen.has(item)) {
        seen.add(item)
        scopes.push({ id: item, name: item })
      }
      continue
    }
    const record = asRecord(item)
    if (!record) continue
    const id = pickString(record.event_id, record.eventId, record.id, record.name)
    if (!id || seen.has(id)) continue
    seen.add(id)
    scopes.push({
      id,
      name: pickString(record.display_name, record.displayName, record.name, record.label, id) ?? id,
    })
  }
  return scopes
}

/** Password changes on the center Web plane terminate the browser session. */
export function normalizePasswordChangeResult(payload: unknown): PasswordChangeResult {
  const record = asRecord(payload) ?? {}
  const nested = asRecord(record.data)
  const reloginRequired =
    pickBoolean(
      record.relogin_required,
      record.reloginRequired,
      nested?.relogin_required,
      nested?.reloginRequired,
    ) ?? false
  return { reloginRequired }
}

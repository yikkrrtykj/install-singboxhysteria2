/**
 * Domain types shared by the UM-C API layer, stores and views.
 *
 * These types describe the *normalized* frontend view of the auth/web/B4
 * contracts. Raw payload shapes are accepted defensively by
 * `src/api/normalize.ts` so that harmless backend variations (snake_case vs
 * camelCase, direct JSON vs B4 envelopes) do not break the console.
 */

export type Timestamp = number | string | null

export type AuthStage = 'anonymous' | 'totp_pending' | 'totp_setup' | 'authenticated'

export interface EventScope {
  id: string
  name: string
}

export interface UserModel {
  id: string
  username: string
  role: string
  enabled: boolean
  eventIds: string[]
  totpEnrolled: boolean | null
  createdAt: Timestamp
  lastLoginAt: Timestamp
}

export interface AuthSnapshot {
  stage: AuthStage
  authenticated: boolean
  totpSetupRequired: boolean
  totpPending: boolean
  user: UserModel | null
  allowedEvents: EventScope[]
  csrfToken: string | null
  recoveryCodesRemaining: number | null
  /** Recovery codes that a login/confirm response may return exactly once. */
  recoveryCodes: string[]
  /**
   * TOTP enrolment material returned directly by the backend (the center Web
   * plane returns it from `POST /auth/login` and `POST /auth/recovery`). It is
   * kept in memory only and shown once on the enrolment page.
   */
  totpSetup: TotpSetupModel | null
  raw: Record<string, unknown>
}

export interface SessionModel {
  id: string
  current: boolean
  state: string | null
  createdAt: Timestamp
  lastSeenAt: Timestamp
  expiresAt: Timestamp
  ip: string | null
  userAgent: string | null
}

export interface TotpSetupModel {
  secret: string
  otpauthUrl: string
  issuer: string | null
  accountName: string | null
  csrfToken: string | null
  raw: Record<string, unknown>
}

export interface RecoveryCodesResult {
  codes: string[]
  remaining: number | null
}

export interface MutationResult {
  user: UserModel | null
  /** Password/temporary password that the server returns only once, if any. */
  oneTimePassword: string | null
}

export interface CreateUserInput {
  username: string
  role: string
  event_ids: string[]
}

export interface RoleUpdateInput {
  role: string
  event_ids: string[]
}

export interface PasswordChangeResult {
  /** Center Web plane invalidates all cookies after a password change. */
  reloginRequired: boolean
}

export const ROLES = ['platform_admin', 'event_admin', 'viewer'] as const
export type KnownRole = (typeof ROLES)[number]

export interface RoleOption {
  value: string
  label: string
  description: string
}

export const ROLE_OPTIONS: readonly RoleOption[] = [
  {
    value: 'platform_admin',
    label: '平台管理员',
    description: '用户管理、全部事件与全局配置',
  },
  {
    value: 'event_admin',
    label: '事件管理员',
    description: '被分配事件范围内的管理与变更操作',
  },
  {
    value: 'viewer',
    label: '只读',
    description: '只读查看被分配事件范围的数据',
  },
]

/**
 * Roles the Web console may assign. The center Web API intentionally refuses
 * platform_admin creation/escalation ("Owner policy"); platform_admin accounts
 * are created only by the local, OS-protected center bootstrap path.
 */
export const ASSIGNABLE_ROLE_OPTIONS: readonly RoleOption[] = ROLE_OPTIONS.filter(
  (option) => option.value !== 'platform_admin',
)

export function roleLabel(role: string | null | undefined): string {
  const found = ROLE_OPTIONS.find((option) => option.value === role)
  return found ? found.label : role ? role : '未知角色'
}

export function isKnownRole(role: string | null | undefined): role is KnownRole {
  return typeof role === 'string' && (ROLES as readonly string[]).includes(role)
}

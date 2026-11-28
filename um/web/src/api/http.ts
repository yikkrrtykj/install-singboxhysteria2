/**
 * In-memory HTTP client for the UM-C console.
 *
 * Security rules enforced here:
 * - Cloudflare Access is validated at the edge. The browser never fabricates,
 *   reads or stores an Access JWT, and no bearer token is attached to requests.
 * - Session cookies are HttpOnly and server-set. This module never reads or
 *   writes cookies, `localStorage` or `sessionStorage`.
 * - The CSRF token only lives in a module-scope variable (memory). It is
 *   attached as `X-CSRF-Token` to unsafe methods (POST/PUT/PATCH/DELETE).
 * - 401/419/expired responses notify the registered auth-failure handler so the
 *   app can clear memory state and route to the session-expired page.
 */

const CSRF_HEADER = 'X-CSRF-Token'

const CREDENTIAL_ERROR_CODES = new Set([
  'invalid_credentials',
  'bad_credentials',
  'invalid_password',
  'invalid_totp',
  'invalid_code',
  'invalid_recovery_code',
])

const EXPIRED_ERROR_CODES = new Set([
  'session_expired',
  'preauth_expired',
  'expired',
  'unauthenticated',
  'unauthorized',
  'session_invalid',
  'session_not_found',
  'access_redirect',
])

const DEFAULT_TIMEOUT_MS = 30_000

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export interface RequestOptions {
  method?: HttpMethod
  body?: unknown
  headers?: Record<string, string>
  timeoutMs?: number
  signal?: AbortSignal
  /**
   * Do not trigger the global session-expired handler on 401/expired responses.
   * Used by login/recovery/TOTP challenge forms so a bad credential can be
   * rendered inline instead of logging the pending session out.
   */
  allowAnonymous?: boolean
}

export interface ApiErrorInfo {
  code?: string
  message?: string
  retryable?: boolean
  requestId?: string
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly retryable: boolean
  readonly details: unknown
  readonly requestId: string | null

  constructor(
    status: number,
    code: string,
    message: string,
    retryable = false,
    details: unknown = null,
    requestId: string | null = null,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryable = retryable
    this.details = details
    this.requestId = requestId
  }
}

let csrfToken: string | null = null
let authFailureHandler: ((error: ApiError) => void) | null = null

export function setCsrfToken(token: string | null | undefined): void {
  const next = typeof token === 'string' ? token.trim() : ''
  csrfToken = next.length > 0 ? next : null
}

export function getCsrfToken(): string | null {
  return csrfToken
}

export function resetCsrfToken(): void {
  csrfToken = null
}

export function setAuthFailureHandler(handler: ((error: ApiError) => void) | null): void {
  authFailureHandler = handler
}

export function isExpiredError(error: ApiError): boolean {
  if (CREDENTIAL_ERROR_CODES.has(error.code)) return false
  if (error.status === 401 || error.status === 419) return true
  return EXPIRED_ERROR_CODES.has(error.code)
}

export function isForbiddenError(error: ApiError): boolean {
  return (
    error.status === 403 ||
    error.code === 'forbidden' ||
    error.code === 'permission_denied' ||
    error.code === 'insufficient_role'
  )
}

export function toApiError(error: unknown, fallbackMessage = '请求失败'): ApiError {
  if (error instanceof ApiError) return error
  if (isAbortError(error)) {
    return new ApiError(0, 'timeout', '请求超时，请稍后重试。', true)
  }
  return new ApiError(0, 'unknown_error', fallbackMessage, false, null, null)
}

function isAbortError(error: unknown): boolean {
  if (typeof DOMException !== 'undefined' && error instanceof DOMException) {
    return error.name === 'AbortError'
  }
  return error instanceof Error && error.name === 'AbortError'
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function pickString(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) return value.trim()
  }
  return null
}

function pickBoolean(...values: unknown[]): boolean | null {
  for (const value of values) {
    if (typeof value === 'boolean') return value
  }
  return null
}

function parseJsonBody(text: string): unknown {
  const trimmed = text.trim()
  if (trimmed.length === 0) return null
  try {
    return JSON.parse(trimmed) as unknown
  } catch {
    return null
  }
}

export function extractApiErrorInfo(payload: unknown): ApiErrorInfo {
  const root = asRecord(payload)
  if (!root) return {}
  const nested = asRecord(root.error)
  const info: ApiErrorInfo = {
    code: pickString(nested?.code, root.code) ?? undefined,
    message: pickString(nested?.message, root.message) ?? undefined,
    retryable: pickBoolean(nested?.retryable, root.retryable) ?? undefined,
    requestId: pickString(root.request_id, root.requestId) ?? undefined,
  }
  if (typeof root.error === 'string') info.message = root.error
  return info
}

function defaultStatusMessage(status: number): string {
  switch (status) {
    case 400:
      return '请求参数无效。'
    case 401:
      return '会话已过期或尚未认证，请重新登录。'
    case 403:
      return '当前账号无权执行该操作。'
    case 404:
      return '请求的资源不存在。'
    case 409:
      return '操作冲突，请刷新后重试。'
    case 410:
      return '请求的资源已失效。'
    case 413:
      return '请求体过大。'
    case 419:
      return 'CSRF 校验失败，请刷新页面后重试。'
    case 429:
      return '请求过于频繁，请稍后重试。'
    case 500:
      return '服务端内部错误。'
    case 502:
    case 503:
    case 504:
      return '服务暂时不可用，请稍后重试。'
    default:
      return `请求失败（HTTP ${status}）。`
  }
}

/**
 * Perform a JSON request and return the raw parsed payload.
 * Authentication endpoints use this directly; B4 endpoints use `b4Request`.
 */
export async function requestJson<T = unknown>(path: string, options: RequestOptions = {}): Promise<T> {
  const method: HttpMethod = options.method ?? 'GET'
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...options.headers,
  }

  let body: string | undefined
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body)
  }

  // Attach to every request when available: the center Web plane requires the
  // header on both mutations and some protected GETs (e.g. `/web/api/*`), while
  // GET requests that do not need it simply ignore the extra header.
  if (csrfToken !== null) {
    headers[CSRF_HEADER] = csrfToken
  }

  const controller = new AbortController()
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const timer = timeoutMs > 0 ? setTimeout(() => controller.abort(), timeoutMs) : null
  const externalSignal = options.signal
  const onExternalAbort = (): void => controller.abort()
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort()
    else externalSignal.addEventListener('abort', onExternalAbort)
  }

  let response: Response
  try {
    response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers,
      body,
      cache: 'no-store',
      redirect: 'manual',
      signal: controller.signal,
    })
  } catch (error) {
    if (controller.signal.aborted) {
      throw new ApiError(0, 'timeout', '请求超时，请稍后重试。', true)
    }
    throw new ApiError(
      0,
      'network_error',
      '网络连接失败，请检查网络或 Cloudflare Access 会话。',
      true,
      error,
    )
  } finally {
    if (timer !== null) clearTimeout(timer)
    externalSignal?.removeEventListener('abort', onExternalAbort)
  }

  // The edge (Cloudflare Access) redirects unauthenticated browsers to its
  // login page. Such a redirect is an expired edge session, not a JSON answer.
  if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
    const redirectError = new ApiError(
      401,
      'access_redirect',
      'Cloudflare Access 会话已失效，请重新登录。',
      false,
      null,
    )
    if (!options.allowAnonymous) authFailureHandler?.(redirectError)
    throw redirectError
  }

  let text = ''
  try {
    text = await response.text()
  } catch {
    text = ''
  }
  const payload = parseJsonBody(text)

  if (!response.ok) {
    const info = extractApiErrorInfo(payload)
    const error = new ApiError(
      response.status,
      info.code ?? `http_${response.status}`,
      info.message ?? defaultStatusMessage(response.status),
      info.retryable ?? (response.status >= 500 || response.status === 429),
      payload,
      info.requestId ?? null,
    )
    if (!options.allowAnonymous && isExpiredError(error)) {
      authFailureHandler?.(error)
    }
    throw error
  }

  return payload as T
}

export function getJson<T = unknown>(path: string, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<T> {
  return requestJson<T>(path, { ...options, method: 'GET' })
}

export function postJson<T = unknown>(
  path: string,
  body?: unknown,
  options: Omit<RequestOptions, 'method' | 'body'> = {},
): Promise<T> {
  return requestJson<T>(path, { ...options, method: 'POST', body })
}

export function isB4Envelope(payload: unknown): payload is { v: 1; data: unknown } {
  const record = asRecord(payload)
  return record !== null && record.v === 1 && 'data' in record
}

export function unwrapB4<T>(payload: unknown): T {
  if (!isB4Envelope(payload)) {
    throw new ApiError(
      502,
      'invalid_b4_response',
      'B4 响应格式无效（缺少 v=1/data），请检查中心服务版本。',
      true,
      payload,
    )
  }
  return payload.data as T
}

/** Read from the B4 management API (`/api/v1/*`); returns the unwrapped data. */
export async function b4Request<T = unknown>(
  path: string,
  options: Omit<RequestOptions, 'method' | 'body'> & { method?: HttpMethod; body?: unknown } = {},
): Promise<T> {
  const normalized = path.startsWith('/') ? path : `/${path}`
  const payload = await requestJson<unknown>(`/api/v1${normalized}`, options)
  return unwrapB4<T>(payload)
}

export async function b4Get<T = unknown>(
  path: string,
  options: Omit<RequestOptions, 'method' | 'body'> = {},
): Promise<T> {
  return b4Request<T>(path, { ...options, method: 'GET' })
}

export async function b4Mutate<T = unknown>(
  path: string,
  body?: unknown,
  options: Omit<RequestOptions, 'method' | 'body'> = {},
): Promise<T> {
  return b4Request<T>(path, { ...options, method: 'POST', body })
}

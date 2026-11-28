import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ApiError,
  b4Request,
  getCsrfToken,
  isExpiredError,
  requestJson,
  setAuthFailureHandler,
  setCsrfToken,
  toApiError,
  unwrapB4,
} from './http'

type FetchMock = ReturnType<typeof vi.fn>

function fakeResponse(status: number, body: unknown, type = 'basic'): Response {
  const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body)
  return {
    status,
    ok: status >= 200 && status < 300,
    type,
    text: async () => text,
  } as unknown as Response
}

function firstInit(fetchMock: FetchMock): {
  headers: Record<string, string>
  body?: string
  method?: string
  credentials?: RequestCredentials
} {
  const init = fetchMock.mock.calls[0]?.[1] as {
    headers: Record<string, string>
    body?: string
    method?: string
    credentials?: RequestCredentials
  }
  expect(init).toBeTruthy()
  return init
}

let fetchMock: FetchMock

beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  setCsrfToken(null)
  setAuthFailureHandler(null)
})

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrfToken(null)
  setAuthFailureHandler(null)
})

describe('requestJson', () => {
  it('sends GET with same-origin credentials and no CSRF or bearer headers', async () => {
    fetchMock.mockResolvedValue(fakeResponse(200, { authenticated: false }))
    const payload = await requestJson<{ authenticated: boolean }>('/auth/context')

    expect(payload.authenticated).toBe(false)
    expect(fetchMock.mock.calls[0][0]).toBe('/auth/context')
    const init = firstInit(fetchMock)
    expect(init.method).toBe('GET')
    expect(init.credentials).toBe('same-origin')
    expect(init.headers['X-CSRF-Token']).toBeUndefined()
    expect(init.headers.Authorization).toBeUndefined()
    expect(init.body).toBeUndefined()
  })

  it('attaches only the in-memory CSRF token to unsafe methods', async () => {
    setCsrfToken('csrf-from-context')
    fetchMock.mockResolvedValue(fakeResponse(200, { ok: true }))

    await requestJson('/auth/login', {
      method: 'POST',
      body: { username: 'alice', password: 'secret' },
    })

    const init = firstInit(fetchMock)
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('same-origin')
    expect(init.headers['X-CSRF-Token']).toBe('csrf-from-context')
    expect(init.headers['Content-Type']).toBe('application/json')
    expect(init.headers.Authorization).toBeUndefined()
    expect(init.body).toBe(JSON.stringify({ username: 'alice', password: 'secret' }))
  })

  it('also attaches the CSRF header to protected GETs when the token exists', async () => {
    setCsrfToken('csrf-from-context')
    fetchMock.mockResolvedValue(fakeResponse(200, { users: [] }))

    await requestJson('/web/api/users')

    const init = firstInit(fetchMock)
    expect(init.method).toBe('GET')
    expect(init.headers['X-CSRF-Token']).toBe('csrf-from-context')
  })

  it('returns null for an empty 204 response', async () => {
    fetchMock.mockResolvedValue(fakeResponse(204, undefined))
    await expect(requestJson('/auth/logout', { method: 'POST' })).resolves.toBeNull()
  })

  it('calls the auth-failure handler for 401 session expiry', async () => {
    const handler = vi.fn()
    setAuthFailureHandler(handler)
    fetchMock.mockResolvedValue(
      fakeResponse(401, { error: { code: 'session_expired', message: 'expired', retryable: false } }),
    )

    await expect(requestJson('/auth/sessions')).rejects.toMatchObject({
      status: 401,
      code: 'session_expired',
      retryable: false,
    })
    expect(handler).toHaveBeenCalledTimes(1)
    expect(handler.mock.calls[0][0]).toBeInstanceOf(ApiError)
  })

  it('does not expire the session for allowAnonymous credential failures', async () => {
    const handler = vi.fn()
    setAuthFailureHandler(handler)
    fetchMock.mockResolvedValue(
      fakeResponse(401, {
        error: { code: 'invalid_credentials', message: 'bad credentials', retryable: false },
      }),
    )

    await expect(
      requestJson('/auth/login', { method: 'POST', body: {}, allowAnonymous: true }),
    ).rejects.toMatchObject({ code: 'invalid_credentials' })
    expect(handler).not.toHaveBeenCalled()
  })

  it('does not treat invalid TOTP as an expired session', async () => {
    const handler = vi.fn()
    setAuthFailureHandler(handler)
    fetchMock.mockResolvedValue(
      fakeResponse(401, { error: { code: 'invalid_totp', message: 'bad code', retryable: false } }),
    )

    await expect(
      requestJson('/auth/totp', { method: 'POST', body: { code: '000000' } }),
    ).rejects.toMatchObject({ code: 'invalid_totp' })
    expect(handler).not.toHaveBeenCalled()
  })

  it('throws forbidden errors without expiring the session', async () => {
    const handler = vi.fn()
    setAuthFailureHandler(handler)
    fetchMock.mockResolvedValue(
      fakeResponse(403, { error: { code: 'forbidden', message: 'no', retryable: false } }),
    )

    await expect(requestJson('/web/api/users')).rejects.toMatchObject({
      status: 403,
      code: 'forbidden',
    })
    expect(handler).not.toHaveBeenCalled()
  })

  it('maps network failures to a retryable ApiError', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    await expect(requestJson('/auth/context')).rejects.toMatchObject({
      status: 0,
      code: 'network_error',
      retryable: true,
    })
  })

  it('treats a Cloudflare Access edge redirect as an expired session', async () => {
    const handler = vi.fn()
    setAuthFailureHandler(handler)
    fetchMock.mockResolvedValue(fakeResponse(0, undefined, 'opaqueredirect'))

    await expect(requestJson('/auth/sessions')).rejects.toMatchObject({
      status: 401,
      code: 'access_redirect',
    })
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('uses an HTTP fallback code when the error body is not JSON', async () => {
    fetchMock.mockResolvedValue(fakeResponse(503, 'upstream unavailable'))

    await expect(requestJson('/auth/context')).rejects.toMatchObject({
      status: 503,
      code: 'http_503',
      retryable: true,
    })
  })
})

describe('B4 envelope handling', () => {
  it('unwraps {v:1,data} and targets /api/v1', async () => {
    fetchMock.mockResolvedValue(fakeResponse(200, { v: 1, data: { status: 'ok' } }))

    const data = await b4Request<{ status: string }>('/health')

    expect(data.status).toBe('ok')
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/health')
  })

  it('rejects a payload without the B4 envelope', async () => {
    fetchMock.mockResolvedValue(fakeResponse(200, { data: {} }))
    await expect(b4Request('/health')).rejects.toMatchObject({ code: 'invalid_b4_response' })
  })

  it('attaches CSRF to B4 mutations', async () => {
    setCsrfToken('csrf-b4')
    fetchMock.mockResolvedValue(fakeResponse(200, { v: 1, data: { ok: true } }))

    await b4Request('/events/ev-1', { method: 'POST', body: { name: 'x' } })

    const init = firstInit(fetchMock)
    expect(init.method).toBe('POST')
    expect(init.headers['X-CSRF-Token']).toBe('csrf-b4')
  })

  it('unwrapB4 reports a helpful error for malformed payloads', () => {
    expect(() => unwrapB4({ v: 2, data: {} })).toThrowError(/B4/)
  })
})

describe('helpers', () => {
  it('distinguishes credential errors from session expiry', () => {
    expect(isExpiredError(new ApiError(401, 'session_expired', 'x'))).toBe(true)
    expect(isExpiredError(new ApiError(419, 'csrf_invalid', 'x'))).toBe(true)
    expect(isExpiredError(new ApiError(401, 'invalid_credentials', 'x'))).toBe(false)
    expect(isExpiredError(new ApiError(403, 'forbidden', 'x'))).toBe(false)
  })

  it('toApiError preserves ApiError instances and wraps unknown errors', () => {
    const original = new ApiError(500, 'http_500', 'boom', true)
    expect(toApiError(original)).toBe(original)
    const wrapped = toApiError(new Error('unexpected'), 'fallback text')
    expect(wrapped.code).toBe('unknown_error')
    expect(wrapped.message).toBe('fallback text')
  })

  it('never writes to localStorage or sessionStorage', async () => {
    const localSet = vi.spyOn(Storage.prototype, 'setItem')
    const sessionSet = vi.spyOn(Storage.prototype, 'setItem')
    setCsrfToken('csrf')
    fetchMock.mockResolvedValue(fakeResponse(200, { v: 1, data: {} }))

    await b4Request('/health')

    expect(localSet).not.toHaveBeenCalled()
    expect(sessionSet).not.toHaveBeenCalled()
    expect(getCsrfToken()).toBe('csrf')
  })
})

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './http'
import {
  changePassword,
  confirmTotpSetup,
  getAuthContext,
  login,
  setupTotp,
} from './auth'

vi.mock('./http', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./http')>()
  return {
    ...actual,
    getJson: vi.fn(),
    postJson: vi.fn(),
  }
})

import { getJson, postJson } from './http'

const get = vi.mocked(getJson)
const post = vi.mocked(postJson)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('auth API contract adapter', () => {
  it('sends the documented login body and normalizes the pending stage', async () => {
    post.mockResolvedValue({ totp_required: true, csrf_token: 'pending-csrf' })

    const snapshot = await login('alice', 'secret')

    expect(post).toHaveBeenCalledWith(
      '/auth/login',
      { username: 'alice', password: 'secret' },
      { allowAnonymous: true },
    )
    expect(snapshot.stage).toBe('totp_pending')
    expect(snapshot.csrfToken).toBe('pending-csrf')
  })

  it('hydrates the anonymous preauth context', async () => {
    get.mockResolvedValue({ authenticated: false, totp_required: false, csrf_token: 'preauth' })

    const snapshot = await getAuthContext()

    expect(get).toHaveBeenCalledWith('/auth/context', { allowAnonymous: true })
    expect(snapshot.stage).toBe('anonymous')
    expect(snapshot.csrfToken).toBe('preauth')
  })

  it('confirms TOTP enrolment through /auth/totp/confirm', async () => {
    post.mockResolvedValue({
      authenticated: true,
      csrf_token: 'active',
      user: { user_id: 'u-1', username: 'alice', role: 'viewer', totp_enrolled: true },
    })

    const snapshot = await confirmTotpSetup('123456')

    expect(post).toHaveBeenCalledWith('/auth/totp/confirm', { code: '123456' })
    expect(snapshot.stage).toBe('authenticated')
  })

  it('falls back to /auth/totp for backends without the confirm endpoint', async () => {
    post
      .mockRejectedValueOnce(new ApiError(404, 'endpoint_not_found', 'missing endpoint'))
      .mockResolvedValueOnce({
        authenticated: true,
        user: { user_id: 'u-1', username: 'alice', role: 'viewer', totp_enrolled: true },
      })

    const snapshot = await confirmTotpSetup('123456')

    expect(post).toHaveBeenNthCalledWith(2, '/auth/totp', { code: '123456' })
    expect(snapshot.authenticated).toBe(true)
  })

  it('re-enrols TOTP through /auth/totp/update with the current password', async () => {
    post.mockResolvedValue({
      totp_setup_required: true,
      csrf_token: 'setup-csrf',
      secret: 'NEW-SECRET',
      otpauth_uri: 'otpauth://totp/UM%20Center:alice?secret=NEW-SECRET&issuer=UM+Center',
    })

    const setup = await setupTotp({}, 'current-password')

    expect(post).toHaveBeenCalledWith('/auth/totp/update', { password: 'current-password' })
    expect(setup.secret).toBe('NEW-SECRET')
    expect(setup.csrfToken).toBe('setup-csrf')
  })

  it('falls back to /auth/totp/setup when the update endpoint is missing', async () => {
    post
      .mockRejectedValueOnce(new ApiError(404, 'endpoint_not_found', 'missing'))
      .mockResolvedValueOnce({ secret: 'DRAFTED-SECRET' })

    const setup = await setupTotp({}, 'current-password')

    expect(post).toHaveBeenNthCalledWith(2, '/auth/totp/setup')
    expect(setup.secret).toBe('DRAFTED-SECRET')
  })

  it('starts first-time enrolment through /auth/totp/setup (drafted contract)', async () => {
    post.mockResolvedValue({ secret: 'FIRST-SECRET' })

    await setupTotp({})

    expect(post).toHaveBeenCalledWith('/auth/totp/setup')
  })

  it('requires a password when the implemented update endpoint is present but no password was supplied', async () => {
    post.mockRejectedValue(new ApiError(404, 'endpoint_not_found', 'missing'))

    await expect(setupTotp({})).rejects.toMatchObject({ code: 'password_required' })
  })

  it('normalizes the relogin_required password-change response', async () => {
    post.mockResolvedValue({ relogin_required: true })

    const result = await changePassword('old-password', 'new-password-123')

    expect(post).toHaveBeenCalledWith('/auth/password', {
      current_password: 'old-password',
      new_password: 'new-password-123',
    })
    expect(result.reloginRequired).toBe(true)
  })
})

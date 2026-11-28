import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './http'
import { createUser, listUsers, revokeUserSession } from './users'

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

describe('user administration API adapter', () => {
  it('normalizes the center users list', async () => {
    get.mockResolvedValue({
      users: [
        {
          user_id: 'u-1',
          username: 'alice',
          role: 'event_admin',
          enabled: true,
          event_ids: ['ev-1'],
          totp_enrolled: true,
          last_login_at: 1_700_000_000,
        },
      ],
    })

    const users = await listUsers()

    expect(get).toHaveBeenCalledWith('/web/api/users')
    expect(users[0]?.id).toBe('u-1')
    expect(users[0]?.eventIds).toEqual(['ev-1'])
    expect(users[0]?.lastLoginAt).toBe(1_700_000_000)
  })

  it('creates a user with the exact center body and returns the initial password once', async () => {
    post.mockResolvedValue({
      user: { user_id: 'u-2', username: 'bob', role: 'viewer', event_ids: ['ev-1'] },
      initial_password: 'Init-Password-1',
    })

    const result = await createUser({ username: 'bob', role: 'viewer', event_ids: ['ev-1'] })

    expect(post).toHaveBeenCalledWith('/web/api/users', {
      username: 'bob',
      role: 'viewer',
      event_ids: ['ev-1'],
    })
    expect(result.user?.username).toBe('bob')
    expect(result.oneTimePassword).toBe('Init-Password-1')
  })

  it('revokes sessions through the implemented nested user route', async () => {
    post.mockResolvedValue({ revoked: true })

    await revokeUserSession('u-1', 'session-1')

    expect(post).toHaveBeenCalledWith('/web/api/users/u-1/sessions/session-1/revoke')
  })

  it('falls back to the drafted flat session route only for a missing endpoint', async () => {
    post
      .mockRejectedValueOnce(new ApiError(404, 'endpoint_not_found', 'missing'))
      .mockResolvedValueOnce({ revoked: true })

    await revokeUserSession('u-1', 'session-1')

    expect(post).toHaveBeenNthCalledWith(2, '/web/api/sessions/session-1/revoke')
  })

  it('does not fall back when the session itself is not found', async () => {
    post.mockRejectedValue(new ApiError(404, 'not_found', 'session not found'))

    await expect(revokeUserSession('u-1', 'session-1')).rejects.toMatchObject({
      code: 'not_found',
    })
    expect(post).toHaveBeenCalledTimes(1)
  })
})

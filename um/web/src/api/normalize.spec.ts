import { describe, expect, it } from 'vitest'
import {
  buildOtpauthUri,
  normalizeAuthPayload,
  normalizeEventList,
  normalizeMutationResult,
  normalizePasswordChangeResult,
  normalizeRecoveryCodes,
  normalizeSessionList,
  normalizeTotpSetup,
  normalizeUserList,
} from './normalize'

describe('normalizeAuthPayload', () => {
  it('normalizes an authenticated /auth/context payload', () => {
    const snapshot = normalizeAuthPayload({
      authenticated: true,
      totp_setup_required: false,
      user: {
        id: 'u-1',
        username: 'alice',
        role: 'platform_admin',
        enabled: true,
        event_ids: ['ev-1'],
      },
      csrf_token: 'csrf-123',
      allowed_events: [
        { id: 'ev-1', name: '生产事件' },
        'ev-2',
      ],
    })

    expect(snapshot.stage).toBe('authenticated')
    expect(snapshot.authenticated).toBe(true)
    expect(snapshot.user?.username).toBe('alice')
    expect(snapshot.user?.eventIds).toEqual(['ev-1'])
    expect(snapshot.allowedEvents).toEqual([
      { id: 'ev-1', name: '生产事件' },
      { id: 'ev-2', name: 'ev-2' },
    ])
    expect(snapshot.csrfToken).toBe('csrf-123')
  })

  it('infers the TOTP setup stage', () => {
    const snapshot = normalizeAuthPayload({ authenticated: false, totp_setup_required: true, csrf_token: 'p' })
    expect(snapshot.stage).toBe('totp_setup')
    expect(snapshot.totpSetupRequired).toBe(true)
  })

  it('infers the pending TOTP stage from login-style responses', () => {
    expect(normalizeAuthPayload({ totp_required: true, csrf_token: 'p' }).stage).toBe('totp_pending')
    expect(normalizeAuthPayload({ session_state: 'totp_pending', csrf_token: 'p' }).stage).toBe('totp_pending')
    expect(normalizeAuthPayload({ status: 'totp_required', csrf_token: 'p' }).stage).toBe('totp_pending')
  })

  it('defaults to anonymous for an unauthenticated preauth context', () => {
    const snapshot = normalizeAuthPayload({ authenticated: false, csrf_token: 'preauth' })
    expect(snapshot.stage).toBe('anonymous')
    expect(snapshot.csrfToken).toBe('preauth')
    expect(snapshot.user).toBeNull()
  })

  it('accepts camelCase aliases', () => {
    const snapshot = normalizeAuthPayload({
      authenticated: true,
      totpSetupRequired: false,
      csrfToken: 'camel',
      allowedEvents: [{ event_id: 'ev-9', label: '九号事件' }],
      user: { userId: 'u-9', username: 'bob', role: 'viewer' },
    })
    expect(snapshot.csrfToken).toBe('camel')
    expect(snapshot.allowedEvents[0]).toEqual({ id: 'ev-9', name: '九号事件' })
    expect(snapshot.user?.id).toBe('u-9')
  })

  it('infers pending/setup from the center context user view (no stage field)', () => {
    const anonymous = { authenticated: false, csrf_token: 'preauth' }
    const pending = normalizeAuthPayload({
      ...anonymous,
      user: { user_id: 'u-1', username: 'alice', role: 'viewer', totp_enrolled: true },
    })
    expect(pending.stage).toBe('totp_pending')

    const setup = normalizeAuthPayload({
      ...anonymous,
      user: { user_id: 'u-1', username: 'alice', role: 'viewer', totp_enrolled: false },
    })
    expect(setup.stage).toBe('totp_setup')
  })

  it('extracts enrolment material and recovery codes returned by login', () => {
    const snapshot = normalizeAuthPayload({
      authenticated: false,
      totp_setup_required: true,
      csrf_token: 'setup-csrf',
      secret: 'LOGIN-SECRET',
      otpauth_uri: 'otpauth://totp/UM%20Center:alice?secret=LOGIN-SECRET&issuer=UM+Center',
      user: { user_id: 'u-1', username: 'alice', role: 'platform_admin', totp_enrolled: false },
    })
    expect(snapshot.stage).toBe('totp_setup')
    expect(snapshot.totpSetup?.secret).toBe('LOGIN-SECRET')
    expect(snapshot.user?.totpEnrolled).toBe(false)
  })

  it('extracts one-time recovery codes from a TOTP confirm response', () => {
    const snapshot = normalizeAuthPayload({
      authenticated: true,
      user: { user_id: 'u-1', username: 'alice', role: 'platform_admin', totp_enrolled: true },
      csrf_token: 'after-confirm',
      recovery_codes: ['AAAA-BBBB', 'CCCC-DDDD'],
    })
    expect(snapshot.stage).toBe('authenticated')
    expect(snapshot.recoveryCodes).toEqual(['AAAA-BBBB', 'CCCC-DDDD'])
  })
})

describe('normalizeSessionList', () => {
  it('accepts a direct array, a sessions object and a B4-like envelope', () => {
    expect(normalizeSessionList([{ id: 's-1', current: true }])).toHaveLength(1)
    expect(normalizeSessionList({ sessions: [{ session_id: 's-2' }] })[0]?.id).toBe('s-2')
    expect(normalizeSessionList({ v: 1, data: { sessions: [{ id: 's-3' }] } })[0]?.id).toBe('s-3')
  })

  it('drops entries without an identifier', () => {
    expect(normalizeSessionList([{ created_at: 1 }, { id: 's-4' }])).toHaveLength(1)
  })
})

describe('normalizeUserList', () => {
  it('normalizes snake_case users and defaults enabled to true', () => {
    const users = normalizeUserList({
      users: [
        { user_id: 'u-1', username: 'alice', role: 'platform_admin', event_ids: ['ev-1'] },
        { id: 'u-2', username: 'bob', role: 'viewer', disabled: true },
      ],
    })
    expect(users).toHaveLength(2)
    expect(users[0]?.enabled).toBe(true)
    expect(users[0]?.eventIds).toEqual(['ev-1'])
    expect(users[1]?.enabled).toBe(false)
  })
})

describe('normalizeTotpSetup', () => {
  it('builds an otpauth URI when only a manual secret is returned', () => {
    const setup = normalizeTotpSetup({ secret: 'JBSWY3DPEHPK3PXP', issuer: 'UM-C', account_name: 'alice' })
    expect(setup.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(setup.otpauthUrl).toContain('otpauth://totp/')
    expect(setup.otpauthUrl).toContain('secret=JBSWY3DPEHPK3PXP')
    expect(setup.otpauthUrl).toContain('issuer=UM-C')
  })

  it('extracts the secret from an otpauth URI', () => {
    const setup = normalizeTotpSetup({
      otpauth_url: 'otpauth://totp/UM-C:alice?secret=ABC234&issuer=UM-C',
    })
    expect(setup.secret).toBe('ABC234')
  })

  it('throws a clear error when no TOTP material is returned', () => {
    expect(() => normalizeTotpSetup({})).toThrowError(/TOTP/)
  })

  it('buildOtpauthUri escapes labels but keeps otpauth parameters', () => {
    const uri = buildOtpauthUri({ secret: 'ABC', issuer: 'UM-C', account: 'ops/alice' })
    expect(uri.startsWith('otpauth://totp/UM-C%3Aops%2Falice?')).toBe(true)
    expect(uri).toContain('digits=6')
  })
})

describe('normalizeRecoveryCodes', () => {
  it('accepts direct arrays and wrapped payloads', () => {
    expect(normalizeRecoveryCodes(['AAAA-BBBB', 'CCCC-DDDD']).codes).toHaveLength(2)
    const wrapped = normalizeRecoveryCodes({
      recovery_codes: ['EEEE-FFFF'],
      recovery_codes_remaining: 9,
    })
    expect(wrapped.codes).toEqual(['EEEE-FFFF'])
    expect(wrapped.remaining).toBe(9)
  })
})

describe('normalizeMutationResult', () => {
  it('extracts a one-time password from reset/creation responses', () => {
    const result = normalizeMutationResult({
      user: { id: 'u-1', username: 'alice' },
      temporary_password: 'Tmp-Secret-1',
    })
    expect(result.user?.username).toBe('alice')
    expect(result.oneTimePassword).toBe('Tmp-Secret-1')
  })

  it('looks inside a data envelope', () => {
    const result = normalizeMutationResult({
      data: { user: { id: 'u-2', username: 'bob' }, initial_password: 'Init-2' },
    })
    expect(result.user?.username).toBe('bob')
    expect(result.oneTimePassword).toBe('Init-2')
  })
})

describe('normalizeEventList (B4 /api/v1/events)', () => {
  it('normalizes EventView entries inside the B4 envelope', () => {
    const events = normalizeEventList({
      v: 1,
      data: {
        events: [
          { event_id: 'ev-1', display_name: '生产事件', state: 'active', created_at: 1 },
          { event_id: 'ev-2', display_name: '测试事件', state: 'active', created_at: 1 },
        ],
        total: 2,
      },
    })
    expect(events).toEqual([
      { id: 'ev-1', name: '生产事件' },
      { id: 'ev-2', name: '测试事件' },
    ])
  })

  it('accepts a plain array payload', () => {
    expect(normalizeEventList([{ event_id: 'ev-3', display_name: '三号' }])).toEqual([
      { id: 'ev-3', name: '三号' },
    ])
  })
})

describe('normalizePasswordChangeResult', () => {
  it('detects the center relogin_required flag', () => {
    expect(normalizePasswordChangeResult({ relogin_required: true }).reloginRequired).toBe(true)
    expect(normalizePasswordChangeResult({}).reloginRequired).toBe(false)
    expect(normalizePasswordChangeResult({ data: { reloginRequired: true } }).reloginRequired).toBe(
      true,
    )
  })
})

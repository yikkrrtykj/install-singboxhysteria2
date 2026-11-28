/**
 * UM-C real-browser authentication closure lab.
 *
 * Runs the real built Vue bundle against the real center Web handler, real
 * SQLite store and real B4 management bridge over real HTTPS. Cloudflare
 * Access/TLS is synthetic (isolated `um/cmd/um-c-e2e` harness only) and the lab
 * clock is controlled through the harness `/__lab/*` surface; neither proves a
 * real Cloudflare edge deployment, which remains a production HOLD.
 *
 * This file must stay the only `*.spec.ts` under `tests/e2e`: the lab clock is
 * global to the harness process, so parallel spec files would interfere. The
 * tests intentionally share one serial worker because provisioning (user
 * creation + forced TOTP enrolment) is expensive and later tests exercise
 * permission changes against the same accounts.
 */

import { expect, test, type Browser, type Page } from '@playwright/test'
import {
  BASE_URL,
  E2E_ADMIN_PASSWORD,
  E2E_ADMIN_USER,
  advanceLabClock,
  b4Call,
  b4Data,
  b4EventIds,
  browserFetch,
  closeLabSession,
  completeFirstTimeTotpSetup,
  completeTotpLogin,
  csrfToken,
  distinctStaleCode,
  eventDisplayName,
  expectApiError,
  expectDashboard,
  expectInvalidTotp,
  expectLoginRejected,
  installAccessRoute,
  labState,
  localB4Call,
  logoutUi,
  newLabSession,
  nextTotpCode,
  passwordLogin,
  roleBadgeText,
  screenshot,
  webUsersCall,
} from './lab'
import type { LabSession, LabState } from './lab'

test.describe.configure({ mode: 'serial' })

type AccountKey = 'event_admin_a' | 'event_admin_b' | 'viewer_a' | 'viewer_b'

interface Account {
  username: string
  password: string
  role: 'event_admin' | 'viewer'
  eventId: string
  secret: string
  recoveryCodes: string[]
}

interface LabRunState {
  state: LabState | null
  ownerSecret: string
  ownerRecoveryCodes: string[]
  accounts: Partial<Record<AccountKey, Account>>
}

const lab: LabRunState = { state: null, ownerSecret: '', ownerRecoveryCodes: [], accounts: {} }

function requireState(): LabState {
  if (!lab.state) throw new Error('lab fixtures are not initialized yet')
  return lab.state
}

function requireAccount(key: AccountKey): Account {
  const account = lab.accounts[key]
  if (!account) throw new Error(`account ${key} has not been provisioned yet`)
  return account
}

function expectEventIds(actual: string[], expected: string[]): void {
  expect([...actual].sort()).toEqual([...expected].sort())
}

function userMainRow(page: Page, username: string) {
  // The main user row contains a span whose exact text is the username; the
  // per-user session/role panels only embed it inside longer headings.
  return page.locator('tr').filter({ has: page.getByText(username, { exact: true }) })
}

async function navTo(page: Page, label: string): Promise<void> {
  // Dashboard cards can duplicate a nav label (a nav link plus a quick-link
  // button); always drive the sidebar navigation deterministically.
  await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: label }).click()
}

async function openUserAdmin(page: Page): Promise<void> {
  await navTo(page, '用户管理')
  await expect(page).toHaveURL(/\/admin\/users$/)
  await expect(page.getByRole('table')).toBeVisible({ timeout: 20_000 })
}

async function loginAccount(
  browser: Browser,
  key: AccountKey,
): Promise<{ session: LabSession; account: Account; page: Page }> {
  const account = requireAccount(key)
  const session = await newLabSession(browser)
  expect(await passwordLogin(session.page, account.username, account.password)).toBe('totp')
  await completeTotpLogin(session.page, account.secret)
  return { session, account, page: session.page }
}

async function loginAdmin(browser: Browser): Promise<LabSession> {
  const state = requireState()
  const session = await newLabSession(browser)
  expect(
    await passwordLogin(session.page, state.platform_admin.username, state.platform_admin.password),
  ).toBe('totp')
  await completeTotpLogin(session.page, lab.ownerSecret)
  return session
}

async function createUserThroughUi(
  page: Page,
  username: string,
  role: 'event_admin' | 'viewer',
  eventId: string,
): Promise<string> {
  const createInput = page.locator('input[placeholder="例如 ops-alice"]')
  if ((await createInput.count()) === 0) {
    await page.getByRole('button', { name: '新建用户' }).click()
  }
  await expect(createInput).toBeVisible({ timeout: 20_000 })
  const form = page.locator('form').filter({ has: createInput })
  await form.locator('input[placeholder="例如 ops-alice"]').fill(username)
  await form.locator('select').selectOption(role)
  const checkbox = form.locator('label.check', { hasText: eventId }).locator('input[type="checkbox"]')
  await expect(checkbox).toBeVisible({ timeout: 20_000 })
  await checkbox.check()
  await form.getByRole('button', { name: '创建用户' }).click()

  const notice = page.locator('.alert-success').filter({ hasText: '已创建' }).first()
  await expect(notice).toBeVisible({ timeout: 20_000 })
  const password = (await notice.locator('.one-time-secret code.mono').innerText()).trim()
  expect(password.length).toBeGreaterThan(8)
  await notice.getByRole('button', { name: '关闭' }).click()
  await expect(userMainRow(page, username)).toBeVisible({ timeout: 20_000 })
  return password
}

// ---------------------------------------------------------------------------
// Existing single-role closure (kept as the baseline regression test)
// ---------------------------------------------------------------------------

test.describe('UM-C real browser authentication closure', () => {
  test('login, forced TOTP setup, session, RBAC pages, logout and TOTP login', async ({ page }) => {
    await installAccessRoute(page)
    expect(await passwordLogin(page, E2E_ADMIN_USER, E2E_ADMIN_PASSWORD)).toBe('setup')
    const enrollment = await completeFirstTimeTotpSetup(page)
    expect(enrollment.secret.length).toBeGreaterThan(10)
    await screenshot(page, 'um-c-browser-dashboard')

    // B4 management API through the Web session bridge + platform-admin page.
    await page.getByRole('link', { name: '用户管理' }).click()
    await expect(page).toHaveURL(/\/admin\/users$/)
    await expect(page.getByRole('table').getByText('e2e-admin')).toBeVisible({ timeout: 15_000 })
    await screenshot(page, 'um-c-browser-users')

    // Logout is a CSRF-protected mutation and clears the server session.
    await logoutUi(page)

    // Second login needs only TOTP (password + session rotate).
    expect(await passwordLogin(page, E2E_ADMIN_USER, E2E_ADMIN_PASSWORD)).toBe('totp')
    await completeTotpLogin(page, enrollment.secret)
    await expectDashboard(page)
  })
})

// ---------------------------------------------------------------------------
// H8 multi-role / permission-change / account-recovery lab
// ---------------------------------------------------------------------------

test.describe('UM-C H8 multi-role real browser lab', () => {
  test('H8 provisioning: platform admin creates scoped event_admin and viewer accounts via the user admin UI', async ({
    browser,
  }) => {
    test.setTimeout(180_000)
    const session = await newLabSession(browser)
    const page = session.page
    const state = await labState(page)
    lab.state = state
    expect(state.events.a.id).not.toBe(state.events.b.id)
    expect(state.platform_admin.username).not.toBe(E2E_ADMIN_USER)

    // First login of the seeded platform_admin: forced TOTP enrolment.
    expect(
      await passwordLogin(page, state.platform_admin.username, state.platform_admin.password),
    ).toBe('setup')
    const enrollment = await completeFirstTimeTotpSetup(page)
    lab.ownerSecret = enrollment.secret
    lab.ownerRecoveryCodes = enrollment.recoveryCodes
    await expect(page.locator('.user-chip')).toContainText('平台管理员')
    await screenshot(page, 'um-c-h8-admin-dashboard')

    await openUserAdmin(page)
    await expect(page.getByRole('table').getByText(E2E_ADMIN_USER)).toBeVisible({ timeout: 20_000 })

    const definitions: Array<{
      key: AccountKey
      username: string
      role: 'event_admin' | 'viewer'
      eventId: string
    }> = [
      {
        key: 'event_admin_a',
        username: 'e2e-event-admin-a',
        role: 'event_admin',
        eventId: state.events.a.id,
      },
      {
        key: 'event_admin_b',
        username: 'e2e-event-admin-b',
        role: 'event_admin',
        eventId: state.events.b.id,
      },
      { key: 'viewer_a', username: 'e2e-viewer-a', role: 'viewer', eventId: state.events.a.id },
      { key: 'viewer_b', username: 'e2e-viewer-b', role: 'viewer', eventId: state.events.b.id },
    ]
    for (const definition of definitions) {
      const password = await createUserThroughUi(
        page,
        definition.username,
        definition.role,
        definition.eventId,
      )
      lab.accounts[definition.key] = {
        username: definition.username,
        password,
        role: definition.role,
        eventId: definition.eventId,
        secret: '',
        recoveryCodes: [],
      }
      const row = userMainRow(page, definition.username)
      await expect(row).toContainText(roleBadgeText(definition.role))
      await expect(row).toContainText(eventDisplayName(state, definition.eventId))
      // A scope/user created through the UI must not leak the other event name.
      const otherEventId =
        definition.eventId === state.events.a.id ? state.events.b.id : state.events.a.id
      const otherEventName = eventDisplayName(state, otherEventId)
      console.log(
        `[H8] UI created ${definition.username} role=${definition.role} event=${definition.eventId} otherScopeHidden=${!(await row.innerText()).includes(otherEventName)}`,
      )
      expect(await row.innerText()).not.toContain(otherEventName)
    }
    await screenshot(page, 'um-c-h8-admin-users-created')

    // platform_admin accounts are Owner-managed: the Web UI refuses role edits.
    await userMainRow(page, state.platform_admin.username)
      .getByRole('button', { name: '角色/范围' })
      .click()
    await expect(page.locator('.alert-error').first()).toContainText('平台管理员账号由中心本地 Owner 策略管理')

    await closeLabSession(session)
  })

  test('H8 enrolment: each role completes forced first-login TOTP setup and then a normal TOTP login', async ({
    browser,
  }) => {
    test.setTimeout(240_000)
    const order: AccountKey[] = ['event_admin_a', 'event_admin_b', 'viewer_a', 'viewer_b']
    for (const key of order) {
      const account = requireAccount(key)
      const session = await newLabSession(browser)
      const page = session.page

      expect(await passwordLogin(page, account.username, account.password)).toBe('setup')
      const enrollment = await completeFirstTimeTotpSetup(page)
      account.secret = enrollment.secret
      account.recoveryCodes = enrollment.recoveryCodes
      expect(account.recoveryCodes.length).toBeGreaterThan(5)
      await expect(page.locator('.user-chip')).toContainText(account.username)
      await expect(page.locator('.user-chip')).toContainText(roleBadgeText(account.role))
      await expect(page.locator('.chip-list')).toContainText(account.eventId)
      await expect(page.locator('.app-footer')).toContainText('事件范围 1 个')
      await screenshot(page, `um-c-h8-role-${key}-dashboard`)
      console.log(`[H8] forced TOTP setup completed role=${account.role} user=${account.username}`)
      await logoutUi(page)

      // Normal TOTP login (no forced setup on return).
      expect(await passwordLogin(page, account.username, account.password)).toBe('totp')
      await completeTotpLogin(page, account.secret)
      await expect(page.locator('.user-chip')).toContainText(roleBadgeText(account.role))
      console.log(`[H8] normal TOTP login ok role=${account.role} user=${account.username}`)
      await logoutUi(page)
      await closeLabSession(session)
    }
  })

  test('H8 RBAC: authorized event visibility, unauthorized invisibility, viewer read-only and event_admin without global admin', async ({
    browser,
  }) => {
    test.setTimeout(240_000)
    const state = requireState()

    // --- event_admin A: scoped reads/one mutation, no global administration.
    const eventAdminA = await loginAccount(browser, 'event_admin_a')
    {
      const { page, account } = eventAdminA
      await expect(page.getByRole('link', { name: '用户管理' })).toHaveCount(0)
      await expect(page.locator('.chip-list')).toContainText(account.eventId)
      await expect(page.locator('.chip-list')).not.toContainText(state.events.b.id)
      await screenshot(page, 'um-c-h8-event-admin-a-dashboard')

      const csrf = await csrfToken(page)
      expectEventIds(b4EventIds(await b4Call(page, 'GET', '/events')), [account.eventId])
      expect((await b4Call(page, 'GET', `/events/${account.eventId}`)).status).toBe(200)
      expectApiError(await b4Call(page, 'GET', `/events/${state.events.b.id}`), 404, 'not_found')
      expectApiError(
        await b4Call(page, 'POST', '/events', {
          csrf,
          body: { event_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', display_name: 'E2E Denied Event' },
        }),
        403,
        'forbidden',
      )
      expectApiError(
        await b4Call(page, 'PATCH', `/events/${account.eventId}`, {
          csrf,
          body: { display_name: 'E2E Denied Rename' },
        }),
        403,
        'forbidden',
      )
      expectApiError(await b4Call(page, 'POST', '/retention/run', { csrf }), 403, 'forbidden')
      expectApiError(await webUsersCall(page, 'GET', '/users'), 403, 'forbidden')
      const created = await b4Call(page, 'POST', `/events/${account.eventId}/tokens`, {
        csrf,
        body: { node_class: 'linux_vps', ttl_seconds: 120 },
      })
      expect(created.status, JSON.stringify(created.body)).toBe(201)
      expect(b4Data(created).event_id).toBe(account.eventId)
      expectApiError(
        await b4Call(page, 'POST', `/events/${state.events.b.id}/tokens`, {
          csrf,
          body: { node_class: 'linux_vps', ttl_seconds: 120 },
        }),
        404,
        'not_found',
      )

      await page.goto(`${BASE_URL}/admin/users`)
      await expect(page).toHaveURL(/\/403$/, { timeout: 20_000 })
      await expect(page.getByRole('heading', { name: '无权访问' })).toBeVisible()
      await screenshot(page, 'um-c-h8-event-admin-forbidden')
    }
    await closeLabSession(eventAdminA.session)

    // --- viewer A: in-scope reads only, no mutation, no user administration.
    const viewerA = await loginAccount(browser, 'viewer_a')
    {
      const { page, account } = viewerA
      await expect(page.locator('.user-chip')).toContainText('只读')
      await expect(page.locator('.chip-list')).toContainText(account.eventId)
      await expect(page.locator('.chip-list')).not.toContainText(state.events.b.id)
      await screenshot(page, 'um-c-h8-viewer-a-dashboard')
      expectEventIds(b4EventIds(await b4Call(page, 'GET', '/events')), [account.eventId])
      expectApiError(await b4Call(page, 'GET', `/events/${state.events.b.id}`), 404, 'not_found')
      const csrf = await csrfToken(page)
      expectApiError(
        await b4Call(page, 'POST', `/events/${account.eventId}/tokens`, {
          csrf,
          body: { node_class: 'linux_vps', ttl_seconds: 120 },
        }),
        403,
        'forbidden',
      )
      expectApiError(await b4Call(page, 'GET', '/audit'), 403, 'forbidden')
      await page.goto(`${BASE_URL}/admin/users`)
      await expect(page).toHaveURL(/\/403$/, { timeout: 20_000 })
    }
    await closeLabSession(viewerA.session)

    // --- viewer B: the other independent event is visible, A is invisible.
    const viewerB = await loginAccount(browser, 'viewer_b')
    {
      const { page, account } = viewerB
      await expect(page.locator('.chip-list')).toContainText(account.eventId)
      await expect(page.locator('.chip-list')).not.toContainText(state.events.a.id)
      await screenshot(page, 'um-c-h8-viewer-b-dashboard')
      expectEventIds(b4EventIds(await b4Call(page, 'GET', '/events')), [account.eventId])
      expectApiError(await b4Call(page, 'GET', `/events/${state.events.a.id}`), 404, 'not_found')
    }
    await closeLabSession(viewerB.session)

    // --- event_admin B: independent event administration within scope B only.
    const eventAdminB = await loginAccount(browser, 'event_admin_b')
    {
      const { page, account } = eventAdminB
      expectEventIds(b4EventIds(await b4Call(page, 'GET', '/events')), [account.eventId])
      expectApiError(await b4Call(page, 'GET', `/events/${state.events.a.id}`), 404, 'not_found')
      const csrf = await csrfToken(page)
      const created = await b4Call(page, 'POST', `/events/${account.eventId}/tokens`, {
        csrf,
        body: { node_class: 'linux_vps', ttl_seconds: 120 },
      })
      expect(created.status, JSON.stringify(created.body)).toBe(201)
    }
    await closeLabSession(eventAdminB.session)
  })

  test('H8 CSRF: mutations require the session CSRF token and a valid B4 local bearer cannot authenticate the browser Web plane', async ({
    browser,
  }) => {
    test.setTimeout(180_000)
    const state = requireState()
    const bearer = state.b4_local_bearer

    // A plain browser page (no signed-in session) that holds the synthetic local
    // B4 bearer credential.
    const anonymous = await newLabSession(browser)
    const anonymousPage = anonymous.page
    await anonymousPage.goto(`${BASE_URL}/login`)

    // 1. The credential is genuinely valid on the real B4 local admin plane.
    const localPlane = await localB4Call(anonymousPage, state, '/api/v1/events', bearer)
    expect(localPlane.status, JSON.stringify(localPlane.body)).toBe(200)
    expectEventIds(b4EventIds(localPlane), [state.events.a.id, state.events.b.id])
    console.log('[H8] synthetic local B4 bearer accepted by the isolated B4 local admin listener')

    // 2. The same credential is rejected by the browser-facing Web plane: it
    //    never substitutes for a Cloudflare Access identity plus local session.
    expectApiError(await b4Call(anonymousPage, 'GET', '/events', { bearer }), 401, 'unauthenticated')
    expectApiError(
      await webUsersCall(anonymousPage, 'GET', '/users', { bearer }),
      401,
      'unauthenticated',
    )
    console.log('[H8] synthetic local B4 bearer rejected by the browser Web plane (no session)')

    // 3. A viewer session plus the valid local bearer cannot impersonate or
    //    escalate: the Web plane only ever uses the session principal.
    const viewer = await loginAccount(browser, 'viewer_b')
    const page = viewer.session.page
    const csrf = await csrfToken(page)
    expectApiError(await webUsersCall(page, 'GET', '/users', { bearer }), 403, 'forbidden')
    expectApiError(await b4Call(page, 'GET', '/audit', { bearer }), 403, 'forbidden')
    expectApiError(
      await webUsersCall(page, 'POST', '/users', {
        csrf,
        bearer,
        body: { username: 'e2e-bearer-escalation', role: 'viewer', event_ids: [state.events.b.id] },
      }),
      403,
      'forbidden',
    )

    // 4. CSRF negative cases: wrong or missing token is rejected before RBAC.
    expectApiError(
      await webUsersCall(page, 'POST', '/users', {
        csrf: 'not-the-session-csrf-token',
        body: { username: 'e2e-csrf-bypass', role: 'viewer', event_ids: [state.events.b.id] },
      }),
      403,
      'csrf_invalid',
    )
    expectApiError(await browserFetch(page, '/auth/logout', { method: 'POST' }), 403, 'csrf_invalid')
    expectApiError(
      await b4Call(page, 'POST', `/events/${state.events.b.id}/tokens`, {
        csrf: 'not-the-session-csrf-token',
        body: { node_class: 'linux_vps', ttl_seconds: 120 },
      }),
      403,
      'csrf_invalid',
    )

    // 5. With the correct CSRF token the viewer is still denied by server RBAC.
    expectApiError(
      await webUsersCall(page, 'POST', '/users', {
        csrf,
        body: { username: 'e2e-viewer-mutation', role: 'viewer', event_ids: [state.events.b.id] },
      }),
      403,
      'forbidden',
    )
    expectApiError(
      await b4Call(page, 'POST', `/events/${state.events.b.id}/tokens`, {
        csrf,
        body: { node_class: 'linux_vps', ttl_seconds: 120 },
      }),
      403,
      'forbidden',
    )

    // The session survives the rejected attempts and stays viewer.
    await page.goto(`${BASE_URL}/`)
    await expectDashboard(page)
    await expect(page.locator('.user-chip')).toContainText('只读')
    await screenshot(page, 'um-c-h8-csrf-and-bearer-rejected')

    await closeLabSession(viewer.session)
    await closeLabSession(anonymous)
  })

  test('H8 revocation: own and administrator session revocation, then an administrator password reset closes every session', async ({
    browser,
  }) => {
    test.setTimeout(240_000)
    const viewerB = await loginAccount(browser, 'viewer_b')
    await expect(viewerB.session.page.locator('.user-chip')).toContainText('只读')

    // --- own-session revocation through the account sessions page.
    const eventAdminA = await loginAccount(browser, 'event_admin_a')
    const ownPage = eventAdminA.session.page
    await navTo(ownPage, '登录会话')
    await expect(ownPage).toHaveURL(/\/account\/sessions$/)
    const ownSessionRows = ownPage.locator('section.card tbody tr')
    await expect(ownSessionRows.first()).toBeVisible({ timeout: 20_000 })
    console.log(`[H8] event_admin_a own server sessions: ${await ownSessionRows.count()}`)
    await ownSessionRows.first().getByRole('button', { name: '撤销' }).click()
    await ownPage
      .getByRole('dialog', { name: '撤销登录会话' })
      .getByRole('button', { name: '撤销会话' })
      .click()
    await expect(ownPage).toHaveURL(/\/expired$/, { timeout: 20_000 })
    await expect(ownPage.getByRole('heading', { name: '会话已过期' })).toBeVisible()
    await screenshot(ownPage, 'um-c-h8-own-session-revoked')
    console.log('[H8] own session revocation forced /expired')
    await closeLabSession(eventAdminA.session)

    // --- administrator revokes the live viewer B session through the user admin page.
    const admin = await loginAdmin(browser)
    await openUserAdmin(admin.page)
    const row = userMainRow(admin.page, viewerB.account.username)
    await expect(row).toBeVisible()
    await row.getByRole('button', { name: '会话' }).click()
    const panel = admin.page
      .locator('tr.table-row--panel')
      .filter({ hasText: `${viewerB.account.username} 的登录会话` })
    await expect(panel).toBeVisible({ timeout: 20_000 })
    const sessionItems = panel.locator('ul.session-list li')
    await expect(sessionItems.first()).toBeVisible({ timeout: 20_000 })
    console.log(`[H8] administrator sees viewer_b server sessions: ${await sessionItems.count()}`)
    await sessionItems.first().getByRole('button', { name: '撤销' }).click()
    await admin.page
      .getByRole('dialog', { name: '撤销用户会话' })
      .getByRole('button', { name: '撤销会话' })
      .click()
    await expect(admin.page.locator('.alert-success').filter({ hasText: '已撤销' })).toBeVisible({
      timeout: 20_000,
    })
    await navTo(viewerB.session.page, '登录会话')
    await expect(viewerB.session.page).toHaveURL(/\/expired$/, { timeout: 20_000 })
    await screenshot(viewerB.session.page, 'um-c-h8-admin-revoked-session')
    console.log('[H8] administrator session revocation forced the live viewer_b session to /expired')
    await closeLabSession(viewerB.session)

    // --- administrator password reset: old password rejected, temporary password works.
    await row.getByRole('button', { name: '重置密码' }).click()
    await admin.page
      .getByRole('dialog', { name: '重置密码' })
      .getByRole('button', { name: '重置密码' })
      .click()
    const resetNotice = admin.page.locator('.alert-success').filter({ hasText: '已为' }).first()
    await expect(resetNotice).toBeVisible({ timeout: 20_000 })
    const temporaryPassword = (await resetNotice.locator('.one-time-secret code.mono').innerText()).trim()
    expect(temporaryPassword.length).toBeGreaterThan(8)
    await resetNotice.getByRole('button', { name: '关闭' }).click()

    const oldPassword = viewerB.account.password
    const oldAttempt = await newLabSession(browser)
    await expectLoginRejected(oldAttempt.page, viewerB.account.username, oldPassword)
    await closeLabSession(oldAttempt)

    viewerB.account.password = temporaryPassword
    const relogin = await loginAccount(browser, 'viewer_b')
    await expect(relogin.session.page.locator('.user-chip')).toContainText('只读')
    await screenshot(relogin.session.page, 'um-c-h8-admin-password-reset-relogin')
    console.log('[H8] administrator password reset: old password rejected, temporary password + TOTP accepted')
    await closeLabSession(relogin.session)
    await closeLabSession(admin)
  })

  test('H8 permission change: role/scope update revokes sessions and the new authorization applies', async ({
    browser,
  }) => {
    test.setTimeout(240_000)
    const state = requireState()
    const viewerB = await loginAccount(browser, 'viewer_b')
    const admin = await loginAdmin(browser)
    await openUserAdmin(admin.page)

    const row = userMainRow(admin.page, viewerB.account.username)
    await row.getByRole('button', { name: '角色/范围' }).click()
    const editor = admin.page.locator('tr.table-row--panel').filter({ hasText: '保存角色与范围' })
    await expect(editor).toBeVisible({ timeout: 20_000 })
    await editor.locator('select').selectOption('event_admin')
    await editor
      .locator('label.check', { hasText: state.events.a.id })
      .locator('input[type="checkbox"]')
      .check()
    await editor
      .locator('label.check', { hasText: state.events.b.id })
      .locator('input[type="checkbox"]')
      .uncheck()
    await editor.getByRole('button', { name: '保存角色与范围' }).click()
    await expect(admin.page.locator('.alert-success').filter({ hasText: '已更新用户' })).toBeVisible({
      timeout: 20_000,
    })

    // Existing session of the changed account is revoked.
    await navTo(viewerB.session.page, '登录会话')
    await expect(viewerB.session.page).toHaveURL(/\/expired$/, { timeout: 20_000 })
    await screenshot(viewerB.session.page, 'um-c-h8-role-change-revoked')
    console.log('[H8] role/scope change revoked the existing viewer_b session')
    await closeLabSession(viewerB.session)

    // New login reflects the new role and event scope end to end.
    viewerB.account.role = 'event_admin'
    viewerB.account.eventId = state.events.a.id
    const changed = await loginAccount(browser, 'viewer_b')
    const changedPage = changed.session.page
    await expect(changedPage.locator('.user-chip')).toContainText('事件管理员')
    await expect(changedPage.locator('.chip-list')).toContainText(state.events.a.id)
    await expect(changedPage.locator('.chip-list')).not.toContainText(state.events.b.id)
    const csrf = await csrfToken(changedPage)
    expectEventIds(b4EventIds(await b4Call(changedPage, 'GET', '/events')), [state.events.a.id])
    expectApiError(await b4Call(changedPage, 'GET', `/events/${state.events.b.id}`), 404, 'not_found')
    const scopedMutation = await b4Call(changedPage, 'POST', `/events/${state.events.a.id}/tokens`, {
      csrf,
      body: { node_class: 'linux_vps', ttl_seconds: 120 },
    })
    expect(scopedMutation.status, JSON.stringify(scopedMutation.body)).toBe(201)
    await screenshot(changedPage, 'um-c-h8-scope-change-effective')
    console.log('[H8] role/scope change effective for the next browser session (event_admin + event A only)')
    await closeLabSession(changed.session)

    // --- disable / enable an account through the user admin UI.
    const currentRow = userMainRow(admin.page, viewerB.account.username)
    await currentRow.getByRole('button', { name: '禁用' }).click()
    await admin.page
      .getByRole('dialog', { name: '禁用用户' })
      .getByRole('button', { name: '禁用' })
      .click()
    await expect(admin.page.locator('.alert-success').filter({ hasText: '已禁用用户' })).toBeVisible({
      timeout: 20_000,
    })
    const disabledAttempt = await newLabSession(browser)
    await expectLoginRejected(disabledAttempt.page, viewerB.account.username, viewerB.account.password)
    await closeLabSession(disabledAttempt)
    console.log('[H8] disabled account cannot sign in')

    await userMainRow(admin.page, viewerB.account.username)
      .getByRole('button', { name: '启用' })
      .click()
    await admin.page
      .getByRole('dialog', { name: '启用用户' })
      .getByRole('button', { name: '启用' })
      .click()
    await expect(admin.page.locator('.alert-success').filter({ hasText: '已启用用户' })).toBeVisible({
      timeout: 20_000,
    })
    const reenabled = await loginAccount(browser, 'viewer_b')
    await expect(reenabled.session.page.locator('.user-chip')).toContainText('事件管理员')
    console.log('[H8] re-enabled account signs in again with the preserved role/scope')
    await closeLabSession(reenabled.session)
    await closeLabSession(admin)
  })

  test('H8 account recovery: own password change, recovery-code login, old authenticator invalidation and TOTP update', async ({
    browser,
  }) => {
    test.setTimeout(300_000)
    const viewerA = await loginAccount(browser, 'viewer_a')
    const page = viewerA.session.page
    const oldPassword = viewerA.account.password
    const oldSecret = viewerA.account.secret
    const newPassword = 'E2E-Viewer-A-New-Password-2026!'

    // --- password change through the account page revokes the session.
    await navTo(page, '修改密码')
    await expect(page).toHaveURL(/\/account\/password$/)
    const passwordInputs = page.locator('input[type="password"]')
    await passwordInputs.nth(0).fill(oldPassword)
    await passwordInputs.nth(1).fill(newPassword)
    await passwordInputs.nth(2).fill(newPassword)
    const changeResponse = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/auth/password' && response.request().method() === 'POST',
    )
    await page.getByRole('button', { name: '更新密码' }).click()
    expect((await changeResponse).status()).toBe(200)
    await expect(page).toHaveURL(/\/login\?reason=password_changed/, { timeout: 20_000 })
    await expect(page.locator('.alert-info').first()).toContainText('密码已修改')
    viewerA.account.password = newPassword
    await expectLoginRejected(page, viewerA.account.username, oldPassword)
    expect(await passwordLogin(page, viewerA.account.username, newPassword)).toBe('totp')
    await completeTotpLogin(page, viewerA.account.secret)
    await screenshot(page, 'um-c-h8-password-changed')
    console.log('[H8] own password change: old password rejected, new password + TOTP accepted')

    // --- recovery-code login forces a fresh TOTP enrolment.
    const consumedRecoveryCode = viewerA.account.recoveryCodes[0]
    await logoutUi(page)
    const recoveryContext = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/auth/context',
      { timeout: 20_000 },
    )
    await page.goto(`${BASE_URL}/recovery`)
    await recoveryContext
    await page.locator('input[name="username"]').fill(viewerA.account.username)
    await page.locator('input[name="password"]').fill(newPassword)
    await page.locator('input[name="recovery-code"]').fill(consumedRecoveryCode)
    const recoveryResponse = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/auth/recovery' && response.request().method() === 'POST',
    )
    await page.getByRole('button', { name: '使用恢复代码登录' }).click()
    expect((await recoveryResponse).status()).toBe(200)
    await expect(page).toHaveURL(/\/setup-totp$/, { timeout: 20_000 })
    const recoveryEnrollment = await completeFirstTimeTotpSetup(page)
    viewerA.account.secret = recoveryEnrollment.secret
    viewerA.account.recoveryCodes = recoveryEnrollment.recoveryCodes
    await screenshot(page, 'um-c-h8-recovery-enrolled')
    console.log('[H8] recovery-code login forced a fresh TOTP enrolment')
    await logoutUi(page)

    // --- a consumed recovery code is single-use.
    const recoveryContext2 = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/auth/context',
      { timeout: 20_000 },
    )
    await page.goto(`${BASE_URL}/recovery`)
    await recoveryContext2
    await page.locator('input[name="username"]').fill(viewerA.account.username)
    await page.locator('input[name="password"]').fill(newPassword)
    await page.locator('input[name="recovery-code"]').fill(consumedRecoveryCode)
    const reuseResponse = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/auth/recovery' && response.request().method() === 'POST',
    )
    await page.getByRole('button', { name: '使用恢复代码登录' }).click()
    const reuseResult = await reuseResponse
    const reuseBody = (await reuseResult.json()) as Record<string, unknown>
    expect(reuseResult.status(), JSON.stringify(reuseBody)).toBe(401)
    expect((reuseBody.error as Record<string, unknown> | undefined)?.code).toBe('invalid_recovery')
    // The SPA's global auth-error handler treats any 401 as an ended temporary
    // session, so the rejection is surfaced on the expired page with the
    // invalid_recovery reason; the account is still not signed in.
    await expect(page).toHaveURL(/\/expired$/, { timeout: 20_000 })
    await expect(page.locator('.alert-warn')).toContainText('恢复代码无效或已被使用')
    await screenshot(page, 'um-c-h8-recovery-code-reuse-rejected')
    console.log('[H8] consumed recovery code rejected on reuse (invalid_recovery 401)')

    // --- the pre-recovery authenticator secret is dead.
    expect(await passwordLogin(page, viewerA.account.username, newPassword)).toBe('totp')
    const staleRecoveryEraCode = await distinctStaleCode(page, oldSecret, viewerA.account.secret)
    await expectInvalidTotp(page, staleRecoveryEraCode)
    await completeTotpLogin(page, viewerA.account.secret)
    console.log('[H8] pre-recovery TOTP secret rejected after recovery')

    // --- TOTP update (re-enrolment) through the account security page.
    await navTo(page, '账户安全')
    await expect(page).toHaveURL(/\/account\/security$/)
    await page.getByRole('button', { name: '重新绑定 TOTP' }).click()
    const enrollmentPanel = page.locator('.security-enrollment')
    await expect(enrollmentPanel.locator('input[type="password"]')).toBeVisible({ timeout: 20_000 })
    await enrollmentPanel.locator('input[type="password"]').fill(newPassword)
    await page.getByRole('button', { name: '验证并重新绑定' }).click()
    const newSecretLocator = enrollmentPanel.locator('code.secret.mono')
    await expect(newSecretLocator).toBeVisible({ timeout: 20_000 })
    const updatedSecret = (await newSecretLocator.innerText()).trim()
    const updateCode = await nextTotpCode(page, updatedSecret)
    await enrollmentPanel.locator('input.input--code').fill(updateCode)
    const updateResponse = page.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return (path === '/auth/totp' || path === '/auth/totp/confirm') && response.request().method() === 'POST'
    })
    await enrollmentPanel.getByRole('button', { name: '完成绑定' }).click()
    expect((await updateResponse).status()).toBe(200)
    await expect(enrollmentPanel.locator('li.recovery-codes__item').first()).toBeVisible({
      timeout: 20_000,
    })
    const updatedRecoveryCodes = (await enrollmentPanel.locator('li.recovery-codes__item').allInnerTexts())
      .map((value) => value.trim())
      .filter(Boolean)
    expect(updatedRecoveryCodes.length).toBeGreaterThan(5)
    viewerA.account.secret = updatedSecret
    viewerA.account.recoveryCodes = updatedRecoveryCodes
    await enrollmentPanel.getByRole('button', { name: '我已保存，关闭' }).click()
    await expect(page.getByText('身份验证器已重新绑定')).toBeVisible({ timeout: 20_000 })
    await screenshot(page, 'um-c-h8-totp-update')
    console.log('[H8] TOTP update (re-enrolment) completed through the account security page')
    await logoutUi(page)

    // --- the recovery-era secret no longer authenticates; the updated one does.
    expect(await passwordLogin(page, viewerA.account.username, newPassword)).toBe('totp')
    const staleRecoveryEraSecret = recoveryEnrollment.secret
    const staleUpdatedCode = await distinctStaleCode(page, staleRecoveryEraSecret, updatedSecret)
    await expectInvalidTotp(page, staleUpdatedCode)
    await completeTotpLogin(page, updatedSecret)
    console.log('[H8] recovery-era TOTP secret rejected after TOTP update')
    await closeLabSession(viewerA.session)
  })

  test('H8 session expiry: idle-timeout expiry, logout and the 404 surfaces', async ({ browser }) => {
    test.setTimeout(180_000)
    const state = requireState()
    const admin = await loginAdmin(browser)
    const page = admin.page

    // 404 UI route served by the real SPA fallback and Vue catch-all route.
    await page.goto(`${BASE_URL}/definitely-not-a-real-page`)
    await expect(page.getByRole('heading', { name: '页面不存在' })).toBeVisible({ timeout: 20_000 })
    await screenshot(page, 'um-c-h8-not-found')

    // 404 API for an unknown event id (platform admin has global scope).
    await page.goto(`${BASE_URL}/`)
    await expectDashboard(page)
    expectApiError(
      await b4Call(page, 'GET', '/events/cccccccc-cccc-4ccc-8ccc-cccccccccccc'),
      404,
      'not_found',
    )

    // Jump past the real 30-minute idle window; the next API call must expire
    // the session and land on the dedicated expired page.
    await advanceLabClock(page, 31 * 60)
    await navTo(page, '登录会话')
    await expect(page).toHaveURL(/\/expired$/, { timeout: 20_000 })
    await expect(page.getByRole('heading', { name: '会话已过期' })).toBeVisible()
    await screenshot(page, 'um-c-h8-session-expired')
    console.log('[H8] idle-timeout expiry redirected the browser to /expired')

    // Recovery from the expired page: fresh login, then explicit logout.
    await page.getByRole('button', { name: '重新登录' }).click()
    await expect(page).toHaveURL(/\/login/)
    expect(await passwordLogin(page, state.platform_admin.username, state.platform_admin.password)).toBe(
      'totp',
    )
    await completeTotpLogin(page, lab.ownerSecret)
    await logoutUi(page)
    await screenshot(page, 'um-c-h8-logout')
    await page.goto(`${BASE_URL}/`)
    await expect(page).toHaveURL(/\/login/, { timeout: 20_000 })
    console.log('[H8] logout cleared the server session; protected route falls back to /login')
    await closeLabSession(admin)
  })
})

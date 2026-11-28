/**
 * Shared helpers for the UM-C real-browser lab.
 *
 * The lab drives the real built Vue bundle against the real center Web handler,
 * the real SQLite store and the real B4 management bridge over real HTTPS
 * cookies. The isolated `um/cmd/um-c-e2e` harness supplies only synthetic
 * Cloudflare Access JWKS/JWT material, a self-signed loopback certificate and a
 * deterministic forward-only lab clock via `/__lab/*`. Nothing here proves a
 * real Cloudflare edge deployment.
 *
 * Determinism: the harness clock is global to the harness process, and this file
 * issues lab-only clock advances. The browser lab therefore MUST run as a single
 * Playwright worker: keep this the only `*.spec.ts` under `tests/e2e` or force
 * `workers: 1` if more spec files are ever added.
 */

import { createHmac } from 'node:crypto'
import { expect, type Browser, type BrowserContext, type Page } from '@playwright/test'

export const BASE_URL = process.env.UM_C_E2E_URL ?? ''
export const ACCESS_TOKEN = process.env.UM_C_E2E_TOKEN ?? ''
export const E2E_ADMIN_USER = process.env.UM_C_E2E_USER ?? ''
export const E2E_ADMIN_PASSWORD = process.env.UM_C_E2E_PASSWORD ?? ''

if (!BASE_URL || !ACCESS_TOKEN || !E2E_ADMIN_USER || !E2E_ADMIN_PASSWORD) {
  throw new Error('UM_C_E2E_URL/TOKEN/USER/PASSWORD are required; the real-browser lab must never skip to green')
}

const WEB_ORIGIN = new URL(BASE_URL).origin
const TOTP_PERIOD_SECONDS = 30

// ---------------------------------------------------------------------------
// TOTP helpers
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function decodeBase32(value: string): Buffer {
  const clean = value.toUpperCase().replace(/[^A-Z2-7]/g, '')
  let bits = 0n
  let acc = 0n
  const out: number[] = []
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch)
    if (idx < 0) continue
    acc = (acc << 5n) | BigInt(idx)
    bits += 5n
    while (bits >= 8n) {
      out.push(Number((acc >> (bits - 8n)) & 0xffn))
      bits -= 8n
      acc &= (1n << bits) - 1n
    }
  }
  return Buffer.from(out)
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30s) for an explicit lab-clock Unix second. */
export function totpAt(secret: string, unixSeconds: number): string {
  const counter = Math.floor(unixSeconds / TOTP_PERIOD_SECONDS)
  const buf = Buffer.alloc(8)
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0)
  buf.writeUInt32BE(counter >>> 0, 4)
  const digest = createHmac('sha1', decodeBase32(secret)).update(buf).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const code =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  return String(code % 1_000_000).padStart(6, '0')
}

// ---------------------------------------------------------------------------
// Browser/page plumbing
// ---------------------------------------------------------------------------

export interface LabSession {
  context: BrowserContext
  page: Page
}

export async function installAccessRoute(page: Page): Promise<void> {
  await page.route('**/*', async (route) => {
    const request = route.request()
    if (!request.url().startsWith(WEB_ORIGIN)) {
      await route.continue()
      return
    }
    await route.continue({
      headers: { ...request.headers(), 'cf-access-jwt-assertion': ACCESS_TOKEN },
    })
  })
}

/** Open an isolated cookie jar with the synthetic Access header installed. */
export async function newLabSession(browser: Browser): Promise<LabSession> {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
  })
  const page = await context.newPage()
  await installAccessRoute(page)
  return { context, page }
}

export async function closeLabSession(session: LabSession): Promise<void> {
  await session.context.close()
}

export async function screenshot(page: Page, name: string): Promise<void> {
  await page.screenshot({ path: `test-results/${name}.png`, fullPage: true })
}

// ---------------------------------------------------------------------------
// Same-origin browser fetch helpers (real Chromium network + cookies + Access)
// ---------------------------------------------------------------------------

export type LabHttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS'

export interface FetchInit {
  method?: LabHttpMethod
  headers?: Record<string, string>
  body?: unknown
}

export interface ApiResult {
  status: number
  body: any
}

export async function browserFetch(page: Page, url: string, init: FetchInit = {}): Promise<ApiResult> {
  const payload = {
    url,
    init: {
      method: init.method ?? 'GET',
      headers: init.headers ?? {},
      body: init.body === undefined ? null : JSON.stringify(init.body),
    },
  }
  return page.evaluate(async ({ url, init }) => {
    const response = await fetch(url, {
      method: init.method,
      headers: init.headers,
      body: init.body,
      cache: 'no-store',
    })
    let body: unknown = null
    try {
      body = await response.json()
    } catch {
      body = null
    }
    return { status: response.status, body }
  }, payload) as Promise<ApiResult>
}

export async function b4Call(
  page: Page,
  method: LabHttpMethod,
  path: string,
  options: { csrf?: string; bearer?: string; body?: unknown } = {},
): Promise<ApiResult> {
  const headers: Record<string, string> = {}
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (options.csrf !== undefined) headers['X-CSRF-Token'] = options.csrf
  if (options.bearer !== undefined) headers['Authorization'] = `Bearer ${options.bearer}`
  return browserFetch(page, `/api/v1${path}`, { method, headers, body: options.body })
}

export async function webUsersCall(
  page: Page,
  method: LabHttpMethod,
  path: string,
  options: { csrf?: string; bearer?: string; body?: unknown } = {},
): Promise<ApiResult> {
  const headers: Record<string, string> = {}
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (options.csrf !== undefined) headers['X-CSRF-Token'] = options.csrf
  if (options.bearer !== undefined) headers['Authorization'] = `Bearer ${options.bearer}`
  return browserFetch(page, `/web/api${path}`, { method, headers, body: options.body })
}

/** Call the synthetic local B4 admin listener (separate loopback TLS origin). */
export async function localB4Call(page: Page, state: LabState, path: string, bearer: string): Promise<ApiResult> {
  return browserFetch(page, `${state.b4_local_admin_url}${path}`, {
    headers: { Authorization: `Bearer ${bearer}` },
  })
}

export function b4Data(result: ApiResult): any {
  if (result.status < 200 || result.status >= 300) {
    throw new Error(`B4 request failed: ${result.status} ${JSON.stringify(result.body)}`)
  }
  return result.body?.data
}

export function b4EventIds(result: ApiResult): string[] {
  const data = b4Data(result)
  const events = Array.isArray(data?.events) ? data.events : []
  return events.map((event: { event_id?: string }) => String(event.event_id ?? ''))
}

export function apiErrorCode(result: ApiResult): string | null {
  const code = result.body?.error?.code
  return typeof code === 'string' ? code : null
}

export function expectApiError(result: ApiResult, status: number, code: string): void {
  expect(result.status, JSON.stringify(result.body)).toBe(status)
  expect(apiErrorCode(result), JSON.stringify(result.body)).toBe(code)
}

// ---------------------------------------------------------------------------
// Deterministic lab clock
// ---------------------------------------------------------------------------

export interface LabEvent {
  id: string
  name: string
}

export interface LabState {
  now_unix: number
  b4_local_bearer: string
  b4_local_admin_url: string
  platform_admin: { username: string; password: string }
  events: { a: LabEvent; b: LabEvent }
}

export async function labState(page: Page): Promise<LabState> {
  // Relative same-origin fetch is only meaningful once the page has a document
  // origin; a freshly created page is still about:blank.
  if (page.url() === 'about:blank') {
    await page.goto(`${BASE_URL}/login`)
  }
  const result = await browserFetch(page, '/__lab/state')
  if (result.status !== 200) throw new Error(`lab state unavailable: ${result.status}`)
  return result.body as LabState
}

export async function advanceLabClock(page: Page, seconds: number): Promise<number> {
  const result = await browserFetch(page, '/__lab/advance', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: { seconds },
  })
  if (result.status !== 200) throw new Error(`lab advance failed: ${result.status} ${JSON.stringify(result.body)}`)
  return Number(result.body.now_unix)
}

/**
 * Advance the lab clock to the middle (+15s) of the next TOTP time step and
 * return that lab Unix second. Guarantees the TOTP counter moves forward by one
 * full step versus any code previously issued by this helper, which the server
 * replay guard requires.
 */
export async function nextTotpStep(page: Page): Promise<number> {
  const state = await labState(page)
  const target = (Math.floor(state.now_unix / TOTP_PERIOD_SECONDS) + 1) * TOTP_PERIOD_SECONDS + 15
  return advanceLabClock(page, target - state.now_unix)
}

/** Produce one fresh TOTP code for `secret`, advancing the lab clock one step. */
export async function nextTotpCode(page: Page, secret: string): Promise<string> {
  const now = await nextTotpStep(page)
  return totpAt(secret, now)
}

/**
 * Produce two codes for the same lab time step that are guaranteed to differ.
 * Used to prove an old authenticator secret is rejected while the active secret
 * still authenticates. `staleSecret` is also compared against the active
 * secret's adjacent accepted steps so the stale code cannot accidentally match
 * the +/-1 skew window.
 */
export async function distinctStaleCode(page: Page, staleSecret: string, activeSecret: string): Promise<string> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const now = await nextTotpStep(page)
    const stale = totpAt(staleSecret, now)
    const activeSteps = [
      totpAt(activeSecret, now - TOTP_PERIOD_SECONDS),
      totpAt(activeSecret, now),
      totpAt(activeSecret, now + TOTP_PERIOD_SECONDS),
    ]
    if (!activeSteps.includes(stale)) return stale
  }
  throw new Error('could not find a TOTP step with distinct stale/active codes')
}

// ---------------------------------------------------------------------------
// Real login / TOTP / enrolment UI flows
// ---------------------------------------------------------------------------

export type LoginStage = 'dashboard' | 'totp' | 'setup'

async function waitForContext(page: Page): Promise<void> {
  const contextResponse = page.waitForResponse(
    (response) => new URL(response.url()).pathname === '/auth/context',
    { timeout: 20_000 },
  )
  await page.goto(`${BASE_URL}/login`)
  await contextResponse
}

/** Password login through the real Vue login form; returns the next UI stage. */
export async function passwordLogin(page: Page, username: string, password: string): Promise<LoginStage> {
  await waitForContext(page)
  await page.locator('input[name="username"]').fill(username)
  await page.locator('input[name="password"]').fill(password)
  const loginResponse = page.waitForResponse(
    (response) => new URL(response.url()).pathname === '/auth/login' && response.request().method() === 'POST',
    { timeout: 20_000 },
  )
  await page.getByRole('button', { name: '登录' }).click()
  const response = await loginResponse
  const body = (await response.json()) as Record<string, unknown>
  if (response.status() !== 200) {
    throw new Error(`login for ${username} failed: ${response.status()} ${JSON.stringify(body)}`)
  }
  if (body.totp_setup_required === true) {
    await expect(page).toHaveURL(/\/setup-totp$/, { timeout: 20_000 })
    return 'setup'
  }
  if (body.totp_required === true) {
    await expect(page).toHaveURL(/\/totp$/, { timeout: 20_000 })
    return 'totp'
  }
  if (body.authenticated === true) {
    await expectDashboard(page)
    return 'dashboard'
  }
  throw new Error(`unexpected login state for ${username}: ${JSON.stringify(body)}`)
}

/** Assert a rejected password login stays on the login page with a bounded error. */
export async function expectLoginRejected(
  page: Page,
  username: string,
  password: string,
  expectedText = '用户名或密码错误。',
): Promise<void> {
  await waitForContext(page)
  await page.locator('input[name="username"]').fill(username)
  await page.locator('input[name="password"]').fill(password)
  await page.getByRole('button', { name: '登录' }).click()
  await expect(page.locator('.alert-error').first()).toContainText(expectedText, { timeout: 20_000 })
  await expect(page).toHaveURL(/\/login/)
}

export async function expectDashboard(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { name: '当前账号', level: 2 })).toBeVisible({ timeout: 20_000 })
}

export interface TotpEnrollment {
  secret: string
  recoveryCodes: string[]
}

/** First-login forced TOTP enrolment through the real setup page. */
export async function completeFirstTimeTotpSetup(page: Page): Promise<TotpEnrollment> {
  await expect(page).toHaveURL(/\/setup-totp$/, { timeout: 20_000 })
  const secretLocator = page.locator('code.secret.mono')
  await expect(secretLocator).toBeVisible({ timeout: 20_000 })
  const secret = (await secretLocator.innerText()).trim()
  expect(secret.length).toBeGreaterThan(10)
  const code = await nextTotpCode(page, secret)
  await page.locator('input.input--code').fill(code)
  const confirmResponse = page.waitForResponse(
    (response) => {
      const path = new URL(response.url()).pathname
      return (path === '/auth/totp' || path === '/auth/totp/confirm') && response.request().method() === 'POST'
    },
    { timeout: 20_000 },
  )
  await page.getByRole('button', { name: '完成绑定' }).click()
  expect((await confirmResponse).status()).toBe(200)
  const codeItems = page.locator('section.recovery-codes li.recovery-codes__item')
  await expect(codeItems.first()).toBeVisible({ timeout: 20_000 })
  const recoveryCodes = (await codeItems.allInnerTexts()).map((value) => value.trim()).filter(Boolean)
  expect(recoveryCodes.length).toBeGreaterThan(5)
  await page.getByRole('button', { name: '我已保存，关闭' }).click()
  await expectDashboard(page)
  return { secret, recoveryCodes }
}

/** Normal password + TOTP login on the challenge page. */
export async function completeTotpLogin(page: Page, secret: string): Promise<void> {
  await expect(page).toHaveURL(/\/totp$/, { timeout: 20_000 })
  const code = await nextTotpCode(page, secret)
  await page.locator('input.input--code').fill(code)
  const verifyResponse = page.waitForResponse(
    (response) => new URL(response.url()).pathname === '/auth/totp' && response.request().method() === 'POST',
    { timeout: 20_000 },
  )
  await page.getByRole('button', { name: '验证并登录' }).click()
  expect((await verifyResponse).status()).toBe(200)
  await expectDashboard(page)
}

/** Submit a TOTP code that must be rejected, keeping the pending session open. */
export async function expectInvalidTotp(page: Page, code: string): Promise<void> {
  await expect(page).toHaveURL(/\/totp$/, { timeout: 20_000 })
  await page.locator('input.input--code').fill(code)
  const verifyResponse = page.waitForResponse(
    (response) => new URL(response.url()).pathname === '/auth/totp' && response.request().method() === 'POST',
    { timeout: 20_000 },
  )
  await page.getByRole('button', { name: '验证并登录' }).click()
  const response = await verifyResponse
  expect(response.status(), await response.text()).toBe(401)
  await expect(page.locator('.alert-error').first()).toContainText('验证码无效', { timeout: 20_000 })
}

export async function logoutUi(page: Page): Promise<void> {
  await page.getByRole('button', { name: '退出登录' }).click()
  await expect(page).toHaveURL(/\/login$/, { timeout: 20_000 })
}

/** Fetch the per-session CSRF token from `/auth/context` through real Chromium. */
export async function csrfToken(page: Page): Promise<string> {
  const result = await browserFetch(page, '/auth/context')
  expect(result.status, JSON.stringify(result.body)).toBe(200)
  const token = result.body?.csrf_token
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error(`/auth/context did not return a CSRF token: ${JSON.stringify(result.body)}`)
  }
  return token
}

export function roleBadgeText(role: string): string {
  switch (role) {
    case 'platform_admin':
      return '平台管理员'
    case 'event_admin':
      return '事件管理员'
    case 'viewer':
      return '只读'
    default:
      return role
  }
}

export function eventDisplayName(state: LabState, eventId: string): string {
  if (eventId === state.events.a.id) return state.events.a.name
  if (eventId === state.events.b.id) return state.events.b.name
  throw new Error(`unknown lab event id ${eventId}`)
}

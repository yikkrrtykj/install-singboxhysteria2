import { createHmac } from 'node:crypto'
import { test, expect, type Page } from '@playwright/test'

const baseURL = process.env.UM_C_E2E_URL ?? ''
const accessToken = process.env.UM_C_E2E_TOKEN ?? ''
const username = process.env.UM_C_E2E_USER ?? ''
const password = process.env.UM_C_E2E_PASSWORD ?? ''

function decodeBase32(value: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = value.toUpperCase().replace(/[^A-Z2-7]/g, '')
  let bits = 0n
  let acc = 0n
  const out: number[] = []
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch)
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
function totp(secret: string, offsetSeconds = 0): string {
  const counter = Math.floor((Date.now() + offsetSeconds * 1000) / 30_000)
  const buf = Buffer.alloc(8)
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0)
  buf.writeUInt32BE(counter >>> 0, 4)
  const digest = createHmac('sha1', decodeBase32(secret)).update(buf).digest()
  const off = digest[digest.length - 1] & 0x0f
  const code =
    ((digest[off] & 0x7f) << 24) |
    ((digest[off + 1] & 0xff) << 16) |
    ((digest[off + 2] & 0xff) << 8) |
    (digest[off + 3] & 0xff)
  return String(code % 1_000_000).padStart(6, '0')
}

async function installAccessRoute(page: Page): Promise<void> {
  await page.route('**/*', async (route) => {
    const headers = { ...route.request().headers(), 'cf-access-jwt-assertion': accessToken }
    await route.continue({ headers })
  })
}

async function login(page: Page): Promise<Record<string, unknown> | null> {
  await page.goto(baseURL + '/login')
  await page.locator('input[name="username"]').fill(username)
  await page.locator('input[name="password"]').fill(password)
  const responsePromise = page
    .waitForResponse((r) => r.url().endsWith('/auth/login') && r.request().method() === 'POST')
    .catch(() => null)
  await page.getByRole('button', { name: '登录' }).click()
  const response = await responsePromise
  if (!response) return null
  return (await response.json()) as Record<string, unknown>
}

test.describe('UM-C real browser authentication closure', () => {
  test.skip(!baseURL || !accessToken || !username || !password, 'UM_C_E2E_* env required')

  test('login, forced TOTP setup, session, RBAC pages, logout and TOTP login', async ({ page }) => {
    await installAccessRoute(page)
    await login(page)
    await expect(page).toHaveURL(/\/setup-totp$/, { timeout: 15_000 })
    const secret = (await page.locator('code.secret.mono').innerText()).trim()
    expect(secret.length).toBeGreaterThan(10)
    await page.locator('input.input--code').fill(totp(secret))
    await page.getByRole('button', { name: '完成绑定' }).click()
    await expect(page.getByRole('button', { name: '我已保存，关闭' })).toBeVisible({ timeout: 15_000 })
    await page.getByRole('button', { name: '我已保存，关闭' }).click()
    await expect(page.getByRole('heading', { name: '当前账号', level: 2 })).toBeVisible({ timeout: 15_000 })
    await page.screenshot({ path: 'test-results/um-c-browser-dashboard.png', fullPage: true })

    // B4 management API through the Web session bridge + platform-admin page.
    await page.getByRole('link', { name: '用户管理' }).click()
    await expect(page).toHaveURL(/\/admin\/users$/)
    await expect(page.getByRole('table').getByText('e2e-admin')).toBeVisible({ timeout: 15_000 })
    await page.screenshot({ path: 'test-results/um-c-browser-users.png', fullPage: true })

    // Logout is a CSRF-protected mutation and clears the server session.
    await page.getByRole('button', { name: '退出登录' }).click()
    await expect(page).toHaveURL(/\/login/)

    // Second login needs only TOTP (password + session rotate), using the next
    // time step to avoid replaying the setup code.
    await login(page)
    await expect(page).toHaveURL(/\/totp$/, { timeout: 15_000 })
    await page.locator('input.input--code').fill(totp(secret, 30))
    await page.getByRole('button', { name: '验证并登录' }).click()
    await expect(page.getByRole('heading', { name: '当前账号', level: 2 })).toBeVisible({ timeout: 15_000 })
  })
})

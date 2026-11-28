/**
 * User-facing error text for API failures.
 *
 * Known backend codes get a stable Chinese message; otherwise the server's
 * message is shown (it is rendered as text, never as HTML).
 */

import { toApiError } from '@/api/http'

const CODE_MESSAGES: Record<string, string> = {
  invalid_credentials: '用户名或密码错误。',
  bad_credentials: '用户名或密码错误。',
  invalid_password: '当前密码错误。',
  password_required: '需要提供当前密码才能继续。',
  weak_password: '新密码不符合中心服务策略：至少 12 字节，且包含非空白字符。',
  invalid_totp: '验证码无效或已过期，请重新输入。',
  invalid_code: '验证码无效或已过期。',
  totp_replayed: '该验证码已被使用，请等待验证器生成新验证码。',
  invalid_recovery: '恢复代码无效或已被使用。',
  invalid_recovery_code: '恢复代码无效或已被使用。',
  totp_required: '需要完成两步验证。',
  totp_setup_required: '需要先绑定身份验证器。',
  session_expired: '会话已过期，请重新登录。',
  preauth_expired: '登录会话已过期，请重新登录。',
  access_redirect: 'Cloudflare Access 会话已失效，请重新登录。',
  access_unauthorized: 'Cloudflare Access 身份校验失败，请确认已通过 Access 登录。',
  login_csrf_failed: '登录前置会话已失效，请刷新页面后重试。',
  unauthenticated: '当前会话未认证或已过期，请重新登录。',
  csrf_invalid: '请求被拒绝（CSRF 校验失败），请刷新页面后重试。',
  forbidden: '当前账号无权执行该操作。',
  permission_denied: '当前账号无权执行该操作。',
  insufficient_role: '当前账号角色不足，无法执行该操作。',
  invalid_role: '该角色不能通过 Web 控制台授予；平台管理员需由中心本地 Owner 策略管理。',
  user_exists: '用户名已存在。',
  last_platform_admin: '不能移除最后一个启用的平台管理员。',
  already_initialized: '账号体系已初始化，不能重复执行该操作。',
  not_found: '请求的资源不存在。',
  invalid_request: '请求参数无效，请检查输入后重试。',
  endpoint_not_found: '中心服务未提供该接口（可能版本不一致）。',
  method_not_allowed: '请求方法不被允许。',
  conflict: '操作冲突，请刷新后重试。',
  rate_limited: '尝试过于频繁，请稍后重试。',
  kdf_busy: '认证服务繁忙，请稍后重试。',
  network_error: '网络连接失败，请检查网络或 Cloudflare Access 会话。',
  timeout: '请求超时，请稍后重试。',
  invalid_b4_response: '中心服务返回了无法识别的 B4 响应。',
  invalid_totp_setup: '服务端未返回有效的 TOTP 配置。',
  totp_unavailable: 'TOTP 状态暂不可用，请稍后重试或联系管理员。',
  internal: '中心服务内部错误，请稍后重试。',
  ui_unavailable: '中心服务未配置 Web 前端静态资源。',
}

export function describeApiError(error: unknown, fallback = '请求失败'): string {
  const apiError = toApiError(error, fallback)
  const known = CODE_MESSAGES[apiError.code]
  if (known) return known
  if (apiError.message && apiError.message.trim().length > 0) return apiError.message
  return fallback
}

/** A retryable status/message hint for error state UIs (does not auto-retry). */
export function isRetryableError(error: unknown): boolean {
  return toApiError(error).retryable
}

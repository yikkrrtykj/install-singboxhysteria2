import { useRouter } from 'vue-router'
import { isExpiredError, toApiError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { describeApiError } from '@/utils/errors'

/**
 * Convert an API error into an inline message. Expired sessions are cleared and
 * routed to the dedicated expired page instead (returns null).
 */
export function useApiErrorHandler(): {
  handle: (error: unknown, fallback?: string) => string | null
} {
  const auth = useAuthStore()
  const router = useRouter()

  function handle(error: unknown, fallback = '请求失败'): string | null {
    const apiError = toApiError(error, fallback)
    if (isExpiredError(apiError)) {
      auth.markSessionExpired(apiError)
      void router.replace({ name: 'session-expired' })
      return null
    }
    return describeApiError(apiError, fallback)
  }

  return { handle }
}

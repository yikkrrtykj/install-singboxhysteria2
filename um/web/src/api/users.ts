/**
 * UM-C user-administration endpoints (`/web/api/**`, platform_admin only).
 *
 * The UI never treats hidden buttons as security: these calls fail closed with
 * 403 unless the backend resolves a platform_admin session.
 */

import { ApiError, getJson, postJson } from './http'
import { normalizeMutationResult, normalizeSessionList, normalizeUserList } from './normalize'
import type {
  CreateUserInput,
  MutationResult,
  RoleUpdateInput,
  SessionModel,
  UserModel,
} from './types'

export function listUsers(): Promise<UserModel[]> {
  return getJson<unknown>('/web/api/users').then(normalizeUserList)
}

export function createUser(input: CreateUserInput): Promise<MutationResult> {
  return postJson<unknown>('/web/api/users', {
    username: input.username,
    role: input.role,
    event_ids: input.event_ids,
  }).then(normalizeMutationResult)
}

export function setUserRole(userId: string, input: RoleUpdateInput): Promise<MutationResult> {
  return postJson<unknown>(`/web/api/users/${encodeURIComponent(userId)}/role`, {
    role: input.role,
    event_ids: input.event_ids,
  }).then(normalizeMutationResult)
}

export function disableUser(userId: string): Promise<MutationResult> {
  return postJson<unknown>(`/web/api/users/${encodeURIComponent(userId)}/disable`).then(
    normalizeMutationResult,
  )
}

export function enableUser(userId: string): Promise<MutationResult> {
  return postJson<unknown>(`/web/api/users/${encodeURIComponent(userId)}/enable`).then(
    normalizeMutationResult,
  )
}

export function resetUserPassword(userId: string): Promise<MutationResult> {
  return postJson<unknown>(`/web/api/users/${encodeURIComponent(userId)}/reset-password`).then(
    normalizeMutationResult,
  )
}

export function listUserSessions(userId: string): Promise<SessionModel[]> {
  return getJson<unknown>(`/web/api/users/${encodeURIComponent(userId)}/sessions`).then(
    normalizeSessionList,
  )
}

/**
 * Revoke a session belonging to another user (platform_admin only).
 *
 * The implemented center exposes the nested route
 * `POST /web/api/users/{user_id}/sessions/{session_id}/revoke`. The drafted
 * contract used `POST /web/api/sessions/{id}/revoke`; fall back only when the
 * endpoint itself is missing (404/405), never when the session is not found.
 */
export async function revokeUserSession(userId: string, sessionId: string): Promise<unknown> {
  try {
    return await postJson<unknown>(
      `/web/api/users/${encodeURIComponent(userId)}/sessions/${encodeURIComponent(sessionId)}/revoke`,
    )
  } catch (error) {
    if (
      error instanceof ApiError &&
      (error.status === 404 || error.status === 405) &&
      (error.code === 'endpoint_not_found' || error.code === 'method_not_allowed')
    ) {
      return postJson<unknown>(`/web/api/sessions/${encodeURIComponent(sessionId)}/revoke`)
    }
    throw error
  }
}

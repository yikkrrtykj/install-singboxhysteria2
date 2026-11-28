/**
 * B4 management reads exposed through the Web plane session bridge
 * (`/api/v1/*`, `{v:1,data}` envelope, CSRF required for mutations).
 *
 * UM-C only uses this for the event catalogue needed by user administration;
 * no monitoring/dashboard implementation lives here (that is UM-D scope).
 */

import { b4Get } from './http'
import { normalizeEventList } from './normalize'
import type { EventScope } from './types'

/** Read the event catalogue for role/event-scope assignment in user admin. */
export async function listAssignableEvents(): Promise<EventScope[]> {
  const payload = await b4Get<unknown>('/events')
  return normalizeEventList(payload)
}

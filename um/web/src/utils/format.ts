import type { Timestamp } from '@/api/types'

const dateTimeFormatter = new Intl.DateTimeFormat('zh-CN', {
  dateStyle: 'medium',
  timeStyle: 'short',
})

/**
 * Format a backend timestamp defensively.
 * Accepts unix seconds, unix milliseconds, ISO strings and numeric strings.
 * Unknown/invalid values render an em dash, never "Invalid Date".
 */
export function formatTimestamp(value: Timestamp | undefined): string {
  if (value === null || value === undefined || value === '') return '—'

  let date: Date
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) return '—'
    date = new Date(value < 1_000_000_000_000 ? value * 1000 : value)
  } else {
    const trimmed = value.trim()
    if (trimmed === '') return '—'
    if (/^\d+$/.test(trimmed)) {
      const numeric = Number(trimmed)
      if (!Number.isFinite(numeric) || numeric <= 0) return '—'
      date = new Date(numeric < 1_000_000_000_000 ? numeric * 1000 : numeric)
    } else {
      date = new Date(trimmed)
    }
  }

  if (Number.isNaN(date.getTime())) return '—'
  return dateTimeFormatter.format(date)
}

/** Truncate long opaque IDs for compact tables while keeping a stable prefix. */
export function shortId(id: string, length = 12): string {
  if (id.length <= length) return id
  return `${id.slice(0, length)}…`
}

/** Compact user-agent label for session tables. */
export function shortUserAgent(userAgent: string | null, maxLength = 60): string {
  if (!userAgent) return '未知客户端'
  return userAgent.length <= maxLength ? userAgent : `${userAgent.slice(0, maxLength)}…`
}

export function pluralize(count: number, singular: string, plural: string): string {
  return count === 1 ? singular : plural
}

import { describe, expect, it } from 'vitest'
import { formatTimestamp, shortId, shortUserAgent } from './format'

describe('formatTimestamp', () => {
  it('renders an em dash for absent values', () => {
    expect(formatTimestamp(null)).toBe('—')
    expect(formatTimestamp(undefined)).toBe('—')
    expect(formatTimestamp('')).toBe('—')
  })

  it('accepts unix seconds, unix milliseconds and ISO strings', () => {
    const seconds = formatTimestamp(1_700_000_000)
    const milliseconds = formatTimestamp(1_700_000_000_000)
    const iso = formatTimestamp('2023-11-14T22:13:20Z')
    expect(seconds).toBe(milliseconds)
    expect(seconds).toBe(iso)
    expect(seconds).not.toBe('—')
  })

  it('does not render Invalid Date for malformed input', () => {
    expect(formatTimestamp('not-a-date')).toBe('—')
    expect(formatTimestamp(Number.NaN)).toBe('—')
  })
})

describe('shortId and shortUserAgent', () => {
  it('keeps short values and truncates long ones', () => {
    expect(shortId('abc')).toBe('abc')
    expect(shortId('1234567890abcdef', 6)).toBe('123456…')
    expect(shortUserAgent(null)).toBe('未知客户端')
    expect(shortUserAgent('Mozilla/5.0', 5)).toBe('Mozil…')
  })
})

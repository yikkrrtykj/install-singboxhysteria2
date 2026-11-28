/** Clipboard helper with a CSP-safe fallback (no inline style / script). */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // fall through to the legacy path
  }

  try {
    const helper = document.createElement('textarea')
    helper.value = text
    helper.setAttribute('readonly', '')
    helper.className = 'clipboard-helper'
    document.body.appendChild(helper)
    helper.select()
    const copied = typeof document.execCommand === 'function' && document.execCommand('copy')
    document.body.removeChild(helper)
    return copied
  } catch {
    return false
  }
}

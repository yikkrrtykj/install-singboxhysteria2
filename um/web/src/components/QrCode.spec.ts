import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import QrCode from './QrCode.vue'

const { toCanvasMock } = vi.hoisted(() => ({ toCanvasMock: vi.fn() }))

vi.mock('qrcode', () => ({
  default: { toCanvas: toCanvasMock },
}))

const OTPAUTH_URI = 'otpauth://totp/UM-C:alice?secret=JBSWY3DPEHPK3PXP&issuer=UM-C'

beforeEach(() => {
  toCanvasMock.mockReset()
  toCanvasMock.mockResolvedValue(undefined)
})

describe('QrCode', () => {
  it('renders the otpauth URI locally through the qrcode library', async () => {
    const wrapper = mount(QrCode, { props: { value: OTPAUTH_URI } })
    await flushPromises()

    expect(toCanvasMock).toHaveBeenCalledTimes(1)
    const call = toCanvasMock.mock.calls[0] as [HTMLCanvasElement, string, { errorCorrectionLevel: string }]
    expect(call[0]).toBeInstanceOf(HTMLCanvasElement)
    expect(call[1]).toBe(OTPAUTH_URI)
    expect(call[2].errorCorrectionLevel).toBe('M')
    expect(wrapper.find('.qr-code__fallback').exists()).toBe(false)
  })

  it('shows a CSP-safe fallback message when rendering fails', async () => {
    toCanvasMock.mockRejectedValue(new Error('canvas unavailable'))
    const wrapper = mount(QrCode, { props: { value: OTPAUTH_URI } })
    await flushPromises()

    expect(wrapper.find('.qr-code__fallback').exists()).toBe(true)
    expect(wrapper.text()).toContain('手动密钥')
  })
})

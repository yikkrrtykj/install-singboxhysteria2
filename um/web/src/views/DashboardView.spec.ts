import { beforeEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import DashboardView from './DashboardView.vue'
import { useAuthStore } from '@/stores/auth'

beforeEach(() => {
  setActivePinia(createPinia())
})

describe('DashboardView', () => {
  it('shows the current user, role, event scopes and the health placeholder', () => {
    const auth = useAuthStore()
    auth.initialized = true
    auth.authenticated = true
    auth.user = {
      id: 'u-1',
      username: 'alice',
      role: 'platform_admin',
      enabled: true,
      eventIds: ['ev-1'],
      totpEnrolled: true,
      createdAt: null,
      lastLoginAt: null,
    }
    auth.allowedEvents = [{ id: 'ev-1', name: '生产事件' }]

    const wrapper = mount(DashboardView, {
      global: {
        stubs: {
          RouterLink: { props: ['to'], template: '<a><slot /></a>' },
        },
      },
    })

    const text = wrapper.text()
    expect(text).toContain('alice')
    expect(text).toContain('平台管理员')
    expect(text).toContain('生产事件')
    expect(text).toContain('系统健康')
    expect(text).toContain('占位')
    expect(text).toContain('UM-D')
  })
})

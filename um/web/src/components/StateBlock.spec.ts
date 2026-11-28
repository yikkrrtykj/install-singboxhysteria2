import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import StateBlock from './StateBlock.vue'

describe('StateBlock', () => {
  it('renders a loading state with a spinner', () => {
    const wrapper = mount(StateBlock, { props: { kind: 'loading' } })
    expect(wrapper.text()).toContain('加载中')
    expect(wrapper.find('.spinner').exists()).toBe(true)
    expect(wrapper.find('button').exists()).toBe(false)
  })

  it('renders an error state and emits retry', async () => {
    const wrapper = mount(StateBlock, {
      props: { kind: 'error', message: '网络连接失败', code: 'network_error' },
    })

    expect(wrapper.text()).toContain('加载失败')
    expect(wrapper.text()).toContain('网络连接失败')
    expect(wrapper.text()).toContain('network_error')

    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('retry')).toHaveLength(1)
  })

  it('renders an empty state without a retry button', () => {
    const wrapper = mount(StateBlock, { props: { kind: 'empty', message: '暂无会话' } })
    expect(wrapper.text()).toContain('暂无数据')
    expect(wrapper.text()).toContain('暂无会话')
    expect(wrapper.find('button').exists()).toBe(false)
  })
})

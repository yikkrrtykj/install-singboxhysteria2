<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import QRCode from 'qrcode'

const props = withDefaults(
  defineProps<{
    value: string
    size?: number
    label?: string
  }>(),
  {
    size: 208,
    label: '身份验证器二维码',
  },
)

const canvas = ref<HTMLCanvasElement | null>(null)
const failed = ref(false)
let renderToken = 0

async function render(): Promise<void> {
  const token = ++renderToken
  const element = canvas.value
  if (!element || props.value.length === 0) return
  try {
    // QR is rendered locally in the browser by the `qrcode` npm library; no
    // external QR service, CDN or network request is involved.
    await QRCode.toCanvas(element, props.value, {
      width: props.size,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: { dark: '#102231', light: '#ffffff' },
    })
    if (token === renderToken) failed.value = false
  } catch {
    if (token === renderToken) failed.value = true
  }
}

onMounted(() => {
  void render()
})

watch([() => props.value, () => props.size], () => {
  void render()
})

onBeforeUnmount(() => {
  renderToken += 1
})
</script>

<template>
  <div class="qr-code">
    <canvas v-if="!failed" ref="canvas" role="img" :aria-label="label"></canvas>
    <p v-if="failed" class="qr-code__fallback" role="alert">
      二维码渲染失败，请使用下方手动密钥或 otpauth URI 添加身份验证器。
    </p>
  </div>
</template>

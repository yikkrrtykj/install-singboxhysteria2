import { fileURLToPath, URL } from 'node:url'
import { loadEnv } from 'vite'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

/**
 * Production Content-Security-Policy injected into dist/index.html only.
 * The center Web plane also sets the authoritative CSP response header; this
 * meta tag is defence-in-depth for static hosting and mirrors the same rules
 * (frame-ancestors is omitted because it is ignored in meta CSP).
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ')

const API_PREFIXES = ['/auth', '/web/api', '/api/v1']

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxyTarget = env.VITE_DEV_PROXY_TARGET?.trim()
  const proxy = proxyTarget
    ? Object.fromEntries(
        API_PREFIXES.map((prefix) => [
          prefix,
          {
            target: proxyTarget,
            changeOrigin: false,
            secure: false,
          },
        ]),
      )
    : undefined

  return {
    plugins: [
      vue(),
      {
        name: 'um-c-csp-meta',
        apply: 'build',
        transformIndexHtml() {
          const cspTag = {
            tag: 'meta',
            attrs: {
              'http-equiv': 'Content-Security-Policy',
              content: CONTENT_SECURITY_POLICY,
            },
            injectTo: 'head-prepend' as const,
          }
          return [cspTag]
        },
      },
    ],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: false,
      ...(proxy ? { proxy } : {}),
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      ...(proxy ? { proxy } : {}),
    },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      sourcemap: false,
      target: 'es2022',
    },
    test: {
      environment: 'jsdom',
      include: ['src/**/*.spec.ts'],
      restoreMocks: true,
      clearMocks: true,
      css: false,
    },
  }
})

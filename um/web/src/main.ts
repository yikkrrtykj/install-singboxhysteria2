import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { setAuthFailureHandler } from './api/http'
import { useAuthStore } from './stores/auth'
import './assets/main.css'

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)

const auth = useAuthStore(pinia)

// Any authenticated request that hits 401/419/edge redirect clears memory state
// and lands on the expired page instead of leaving a stale UI behind.
setAuthFailureHandler((error) => {
  auth.markSessionExpired(error)
  if (router.currentRoute.value.name !== 'session-expired') {
    void router.replace({ name: 'session-expired' })
  }
})

app.use(router)
app.mount('#app')

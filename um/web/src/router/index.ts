import { createRouter, createWebHistory } from 'vue-router'
import { installAuthGuard } from './guard'
import { routes } from './routes'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

installAuthGuard(router)

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} · UM-C 运维控制台` : 'UM-C 运维控制台'
})

export default router

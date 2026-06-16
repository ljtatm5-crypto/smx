import { createRouter, createWebHashHistory } from 'vue-router'

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', name: 'Home', component: () => import('../views/HomeView.vue') },
    { path: '/file', name: 'FileEncrypt', component: () => import('../views/FileEncrypt.vue') },
    { path: '/sign', name: 'DataSign', component: () => import('../views/DataSign.vue') },
    { path: '/hash', name: 'HashCheck', component: () => import('../views/HashCheck.vue') },
    { path: '/learn', name: 'Learn', component: () => import('../views/LearnView.vue') },
    { path: '/visual', name: 'Visualize', component: () => import('../views/Visualize.vue') },
    { path: '/challenge', name: 'Challenge', component: () => import('../views/ChallengeView.vue') },
    { path: '/sdk', name: 'SDK', component: () => import('../views/SDKView.vue') },
    { path: '/guide', name: 'Guide', component: () => import('../views/GuideView.vue') },
    { path: '/audit', name: 'Audit', component: () => import('../views/AuditLog.vue') }
  ]
})

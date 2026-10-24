import { createRouter, createWebHistory } from 'vue-router'
import VulnerabilityListView from '../views/VulnerabilityListView.vue'
import VulnerabilityDetailView from '../views/VulnerabilityDetailView.vue'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'vulnerabilities', component: VulnerabilityListView },
    { path: '/vulnerabilities/:cveId', name: 'vulnerability', component: VulnerabilityDetailView, props: true },
  ],
})

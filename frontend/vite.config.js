import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    // En développement, les appels à /api sont transmis au back Spring Boot.
    // Le navigateur ne voit qu'une seule origine : pas besoin de configurer CORS.
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
})

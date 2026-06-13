import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    proxy: {
      // Proxy all /api requests to the local backend server
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    rollupOptions: {
      input: 'index.html',
    },
  },
})

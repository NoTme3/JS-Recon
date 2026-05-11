import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    proxy: {
      // Proxy /api requests to the local API server
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

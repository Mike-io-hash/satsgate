import { defineConfig } from 'vite'

export default defineConfig({
  base: '/connect/',
  build: {
    sourcemap: false,
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/v1/connect': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})

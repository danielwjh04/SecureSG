import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

const BACKEND = 'http://127.0.0.1:8080'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/sessions': { target: BACKEND, changeOrigin: true },
      // One entry covers the dashboard REST routes and the /dashboard/ws socket.
      '/dashboard': { target: BACKEND, changeOrigin: true, ws: true },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
  },
})

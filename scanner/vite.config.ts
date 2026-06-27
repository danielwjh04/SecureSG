import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { cloudflare } from '@cloudflare/vite-plugin'
import { defineConfig } from 'vitest/config'

// https://vite.dev/config/
//
// The @cloudflare/vite-plugin gives single-process, same-origin dev: the Vite
// SPA and the Worker (/api/*) are served from one origin, so there is no
// server.proxy and no CORS to configure.
export default defineConfig({
  plugins: [react(), tailwindcss(), cloudflare()],
  test: {
    // Vitest 4 multi-project layout. Worker/shared logic runs in a plain Node
    // environment; the React SPA runs in jsdom with the testing-library setup.
    // NOTE: the `test.projects` shape is the documented Vitest 4 API; if the
    // installed Vitest minor diverges, this block may need a small adjustment.
    projects: [
      {
        test: {
          name: 'node',
          environment: 'node',
          globals: true,
          include: ['shared/**/*.test.ts', 'worker/**/*.test.ts'],
        },
      },
      {
        test: {
          name: 'dom',
          environment: 'jsdom',
          globals: true,
          setupFiles: ['./src/test/setup.ts'],
          include: ['src/**/*.test.{ts,tsx}'],
        },
      },
    ],
  },
})

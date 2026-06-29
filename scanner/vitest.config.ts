import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Dedicated Vitest config, kept separate from vite.config.ts on purpose.
//
// vite.config.ts loads @cloudflare/vite-plugin for single-process dev/build,
// which pulls `wrangler` into the config graph. The unit suite tests pure TS
// modules (shared proof core) and the React SPA, it must not boot
// the Worker runtime, so this config omits the Cloudflare plugin entirely.
// Vitest prefers vitest.config.* over vite.config.*, so `vitest` picks this up
// automatically while `vite dev`/`vite build` keep using vite.config.ts.
//
// Shared proof logic runs in a plain Node environment (Node exposes Web Crypto
// globally); the React SPA runs in jsdom with the testing-library setup.
export default defineConfig({
  plugins: [react()],
  test: {
    projects: [
      {
        test: {
          name: 'node',
          environment: 'node',
          globals: true,
          include: ['shared/**/*.test.ts'],
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

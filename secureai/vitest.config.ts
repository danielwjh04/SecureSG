import { defineConfig } from 'vitest/config'

// Pure pipeline/audit modules are runtime-agnostic (Web Crypto, fetch, Request
// are present in the Node test runtime), so they run under the default Node
// environment. When route tests need real Worker bindings (AI, D1, KV), this
// switches to @cloudflare/vitest-pool-workers.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/schemas/contract.ts'],
      thresholds: { lines: 85, functions: 85, statements: 85, branches: 80 },
    },
  },
})

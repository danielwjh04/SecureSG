import { describe, expect, it, vi } from 'vitest'
import { MemoryD1, MemoryStore } from './db/memory.test'
import { memoryDatabase } from './db/memory.test'
import { createFreeUser } from './db/accounts'
import { createGuardDeviceCredential } from './db/guardDevices'
import worker from './index'

const controller = { scheduledTime: 1700, cron: '0 * * * *', noRetry: () => {} }

function call(env: Record<string, unknown>): Promise<void> {
  return worker.scheduled!(controller as unknown as ScheduledController, env)
}

describe('worker.scheduled (threat-feed cron)', () => {
  it('no-ops when the feed is disabled', async () => {
    const store = new MemoryStore()
    await call({ DB: new MemoryD1(store) as unknown as D1Database })
    expect(store.feedMetaVersion).toBeNull()
  })

  it('no-ops without throwing when DB is unbound', async () => {
    await expect(call({ SCANNER_FEED_ENABLED: 'true' })).resolves.toBeUndefined()
  })

  it('loads a feed version stamped with the scheduledTime when enabled', async () => {
    const store = new MemoryStore()
    const bodies: Record<string, string> = {
      'https://f.test/u': '',
      'https://f.test/h': 'evilhost.test\n',
      'https://f.test/t': '',
    }
    vi.stubGlobal('fetch', (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString()
      return new Response(bodies[url] ?? '', { status: url in bodies ? 200 : 404 })
    }) as unknown as typeof fetch)
    await call({
      DB: new MemoryD1(store) as unknown as D1Database,
      SCANNER_FEED_ENABLED: 'true',
      URLHAUS_AUTH_KEY: 'k',
      SCANNER_FEED_URLHAUS_URLS: 'https://f.test/u',
      SCANNER_FEED_URLHAUS_HOSTS: 'https://f.test/h',
      SCANNER_FEED_THREATFOX: 'https://f.test/t',
    })
    vi.unstubAllGlobals()
    expect(store.feedMetaVersion).toBe(1700)
  })

  it('the cron purges expired guard credentials past the grace window', async () => {
    const { db, store } = memoryDatabase()
    const { user } = await createFreeUser(db, 'purge-cron@example.com')

    // Insert a credential whose expires_at is before scheduledTime (1700 ms epoch),
    // so it will be past the grace window regardless of the configured grace days.
    await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: 'dev_expired',
      name: null,
      integration: 'claude-code',
      scopes: ['guard:decision'],
      createdAt: '1970-01-01T00:00:00.000Z',
      expiresAt: '1970-01-01T00:00:00.000Z',
    })

    expect(store.guardDeviceCredentials.size).toBe(1)

    // Run cron with feed disabled but DB bound. Grace days = 0 so the cutoff equals scheduledTime.
    await call({
      DB: new MemoryD1(store) as unknown as D1Database,
      SCANNER_GUARD_DEVICE_PURGE_GRACE_DAYS: '0',
    })

    expect(store.guardDeviceCredentials.size).toBe(0)
  })

  it('a purge failure does not fail the scheduled run', async () => {
    // Build a MemoryD1 whose execute rejects for the DELETE statement.
    const store = new MemoryStore()
    const faultyD1 = new MemoryD1(store)
    const originalPrepare = faultyD1.prepare.bind(faultyD1)
    vi.spyOn(faultyD1, 'prepare').mockImplementation((sql: string) => {
      const stmt = originalPrepare(sql)
      if (sql.startsWith('DELETE FROM guard_device_credentials WHERE expires_at')) {
        return {
          bind: (..._: unknown[]) => ({
            run: () => Promise.reject(new Error('injected purge failure')),
            first: stmt.first.bind(stmt),
            all: stmt.all.bind(stmt),
          }),
          run: () => Promise.reject(new Error('injected purge failure')),
          first: stmt.first.bind(stmt),
          all: stmt.all.bind(stmt),
        } as ReturnType<typeof faultyD1.prepare>
      }
      return stmt
    })

    await expect(
      call({ DB: faultyD1 as unknown as D1Database }),
    ).resolves.toBeUndefined()
  })
})

/**
 * In-memory fake of the Cloudflare D1 binding, plus its own self-tests.
 *
 * The fake implements the `prepare().bind().first()/run()` surface the
 * {@link d1Database} adapter calls, so tests exercise the SAME code path as
 * production: route → `d1Database(env.DB)` → repositories. It recognizes exactly
 * the statements the repositories emit (matched by stable substrings) and
 * applies them against plain `Map`s, faithfully modeling D1's
 * primary-key/upsert semantics. It is defined in a `.test.ts` file so it is
 * excluded from the production coverage surface yet importable by other suites.
 *
 * Use {@link memoryDatabase} to obtain a `(Database fake, MemoryStore)` pair, or
 * pass a {@link MemoryD1} instance directly as a fake `env.DB`.
 */

import { describe, expect, it } from 'vitest'
import type { Database } from './database'
import { d1Database } from './database'

interface UserRecord {
  id: string
  email: string
  tier: string
  stripe_customer_id: string | null
  created_at: string
}

interface ApiKeyRecord {
  key_sha256: string
  user_id: string
  status: string
  created_at: string
}

interface UsageRecord {
  subject: string
  day: string
  scans: number
  ai_scans: number
}

/** Composite key for the usage map, mirroring the `(subject, day)` PK. */
function usageKey(subject: string, day: string): string {
  return `${subject} ${day}`
}

/**
 * Backing store for the fake. Exposed so assertions can confirm what was (and
 * was NOT) persisted — notably that no raw API key is ever stored.
 */
export class MemoryStore {
  public readonly users = new Map<string, UserRecord>()
  /** Keyed by `key_sha256`, so the raw key never appears as a key or value. */
  public readonly apiKeys = new Map<string, ApiKeyRecord>()
  /** Keyed by `${subject} ${day}`. */
  public readonly usage = new Map<string, UsageRecord>()

  /** Per-statement failure injection: when armed, the next call throws once. */
  public failNext = false

  /** Throw once if failure injection is armed, then disarm. */
  public maybeFail(): void {
    if (this.failNext) {
      this.failNext = false
      throw new Error('injected database failure')
    }
  }

  /** Apply a read returning at most one row. */
  public queryOne(sql: string, params: readonly unknown[]): Record<string, unknown> | null {
    this.maybeFail()
    if (sql.includes('FROM api_keys k JOIN users u')) {
      const key = this.apiKeys.get(String(params[0]))
      if (key === undefined || key.status !== 'active') {
        return null
      }
      const user = this.users.get(key.user_id)
      return user === undefined ? null : { id: user.id, tier: user.tier }
    }
    if (sql.includes('FROM usage WHERE subject')) {
      const record = this.usage.get(usageKey(String(params[0]), String(params[1])))
      return record === undefined ? null : { scans: record.scans, ai_scans: record.ai_scans }
    }
    throw new Error(`MemoryStore: unrecognized queryOne SQL: ${sql}`)
  }

  /** Apply a write (insert / update / upsert). */
  public execute(sql: string, params: readonly unknown[]): void {
    this.maybeFail()
    if (sql.startsWith('INSERT INTO users')) {
      const id = String(params[0])
      const email = String(params[1])
      for (const existing of this.users.values()) {
        if (existing.email === email) {
          throw new Error('UNIQUE constraint failed: users.email')
        }
      }
      this.users.set(id, {
        id,
        email,
        tier: String(params[2]),
        stripe_customer_id: params[3] === null ? null : String(params[3]),
        created_at: String(params[4]),
      })
      return
    }
    if (sql.startsWith('INSERT INTO api_keys')) {
      const keyHash = String(params[0])
      this.apiKeys.set(keyHash, {
        key_sha256: keyHash,
        user_id: String(params[1]),
        status: String(params[2]),
        created_at: String(params[3]),
      })
      return
    }
    if (sql.startsWith('INSERT INTO usage')) {
      const subject = String(params[0])
      const day = String(params[1])
      const aiDelta = Number(params[2])
      const composite = usageKey(subject, day)
      const existing = this.usage.get(composite)
      if (existing === undefined) {
        this.usage.set(composite, { subject, day, scans: 1, ai_scans: aiDelta })
      } else {
        existing.scans += 1
        existing.ai_scans += aiDelta
      }
      return
    }
    if (sql.startsWith('UPDATE users SET tier = ? WHERE stripe_customer_id')) {
      const tier = String(params[0])
      const customerId = String(params[1])
      for (const user of this.users.values()) {
        if (user.stripe_customer_id === customerId) {
          user.tier = tier
        }
      }
      return
    }
    if (sql.startsWith('UPDATE users SET tier = ? WHERE id')) {
      const tier = String(params[0])
      const user = this.users.get(String(params[1]))
      if (user !== undefined) {
        user.tier = tier
      }
      return
    }
    throw new Error(`MemoryStore: unrecognized execute SQL: ${sql}`)
  }
}

/** A prepared statement over the {@link MemoryStore}, capturing the SQL + binds. */
class MemoryStatement {
  private params: readonly unknown[] = []
  public constructor(
    private readonly store: MemoryStore,
    private readonly sql: string,
  ) {}

  public bind(...values: unknown[]): MemoryStatement {
    this.params = values
    return this
  }

  public async first<T = Record<string, unknown>>(): Promise<T | null> {
    return this.store.queryOne(this.sql, this.params) as T | null
  }

  public async run(): Promise<void> {
    this.store.execute(this.sql, this.params)
  }
}

/**
 * A fake `D1Database` binding backed by a {@link MemoryStore}. Implements only
 * the `prepare()` surface the {@link d1Database} adapter uses; the unused D1
 * methods would never be reached, so they are intentionally omitted (the cast at
 * the env boundary is how production already supplies the binding).
 */
export class MemoryD1 {
  public constructor(public readonly store: MemoryStore = new MemoryStore()) {}

  public prepare(sql: string): MemoryStatement {
    return new MemoryStatement(this.store, sql)
  }
}

/**
 * Build a `(Database, MemoryStore)` pair for direct repository unit tests: the
 * adapter-wrapped fake plus its backing store for assertions.
 */
export function memoryDatabase(): { db: Database; store: MemoryStore } {
  const store = new MemoryStore()
  const d1 = new MemoryD1(store)
  return { db: d1Database(d1 as unknown as D1Database), store }
}

// The fake is a test double; this trivial suite keeps the file a valid test
// module and asserts the double's own invariants (it backs every other suite).
describe('MemoryD1', () => {
  it('upserts usage rows on the composite (subject, day) key via the adapter', async () => {
    const { db, store } = memoryDatabase()
    const upsert =
      'INSERT INTO usage (subject, day, scans, ai_scans) VALUES (?, ?, 1, ?) ' +
      'ON CONFLICT (subject, day) DO UPDATE SET scans = scans + 1, ai_scans = ai_scans + ?'
    await db.execute(upsert, ['u1', '2026-06-28', 1, 1])
    await db.execute(upsert, ['u1', '2026-06-28', 0, 0])
    expect(store.usage.get('u1 2026-06-28')).toMatchObject({ scans: 2, ai_scans: 1 })
  })

  it('throws on an unrecognized statement', async () => {
    const { db } = memoryDatabase()
    await expect(db.execute('DROP TABLE users', [])).rejects.toThrow(/unrecognized/)
    await expect(db.queryOne('SELECT 1', [])).rejects.toThrow(/unrecognized/)
  })

  it('injects a failure exactly once when armed', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(db.execute('INSERT INTO users (id) VALUES (?)', ['x'])).rejects.toThrow(/injected/)
    expect(store.failNext).toBe(false)
  })
})

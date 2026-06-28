import { describe, expect, it } from 'vitest'
import { d1Database, d1Session } from './database'
import { MemoryD1, MemoryStore } from './memory.test'
import { PersistenceError } from '../errors'

/** Build a Database adapter over a fresh in-memory fake, exposing the store. */
function adapter(): { db: ReturnType<typeof d1Database>; store: MemoryStore } {
  const store = new MemoryStore()
  const d1 = new MemoryD1(store)
  return { db: d1Database(d1 as unknown as D1Database), store }
}

describe('d1Database.batch', () => {
  it('applies every statement and returns one WriteResult per statement, in order', async () => {
    const { db, store } = adapter()
    const results = await db.batch([
      {
        sql:
          'INSERT INTO users (id, email, tier, stripe_customer_id, created_at, email_verified) ' +
          'VALUES (?, ?, ?, ?, ?, 1)',
        params: ['u1', 'batch@example.com', 'free', null, '2026-06-28T00:00:00.000Z'],
      },
      {
        sql:
          'INSERT INTO usage (subject, day, scans, ai_scans, allows, reviews, blocks, flagged) ' +
          'VALUES (?, ?, 1, ?, ?, ?, ?, ?) ' +
          'ON CONFLICT (subject, day) DO UPDATE SET scans = scans + 1, ai_scans = ai_scans + ?, ' +
          'allows = allows + 1, flagged = flagged + ?',
        params: ['u1', '2026-06-28', 0, 1, 0, 0, 0, 0, 0],
      },
    ])
    expect(results).toHaveLength(2)
    expect(results.every((r) => r.changes === 1)).toBe(true)
    expect(store.users.get('u1')?.email).toBe('batch@example.com')
    expect(store.usage.get('u1 2026-06-28')?.scans).toBe(1)
  })

  it('wraps an underlying batch rejection as a PersistenceError', async () => {
    const { db, store } = adapter()
    store.failNext = true // the first statement in the batch throws
    await expect(
      db.batch([
        {
          sql:
            'INSERT INTO users (id, email, tier, stripe_customer_id, created_at, email_verified) ' +
            'VALUES (?, ?, ?, ?, ?, 1)',
          params: ['u2', 'fail@example.com', 'free', null, '2026-06-28T00:00:00.000Z'],
        },
      ]),
    ).rejects.toBeInstanceOf(PersistenceError)
  })

  it('returns an empty result array for an empty batch', async () => {
    const { db } = adapter()
    expect(await db.batch([])).toEqual([])
  })
})

describe('d1Session', () => {
  it('reads and writes through a session and surfaces a bookmark that advances on writes', async () => {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    const session = d1Session(d1, null)

    const before = session.getBookmark()
    await session.execute(
      'INSERT INTO users (id, email, tier, stripe_customer_id, created_at, email_verified) VALUES (?, ?, ?, ?, ?, 1)',
      ['u1', 's@x.test', 'free', null, '2026-06-28T00:00:00.000Z'],
    )
    const after = session.getBookmark()
    // The bookmark advances after a write (read-your-writes marker).
    expect(after).not.toBe(before)
    // Reads go through the same session.
    const row = await session.queryOne('SELECT tier FROM users WHERE id = ?', ['u1'])
    expect(row?.['tier']).toBe('free')
  })

  it('accepts a prior bookmark constraint without error', async () => {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    const session = d1Session(d1, 'bm-prior')
    expect(typeof session.getBookmark()).toBe('string')
  })
})

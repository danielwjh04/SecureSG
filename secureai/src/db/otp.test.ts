import { describe, expect, it } from 'vitest'
import { OtpError } from '../errors'
import { memoryDatabase } from './memory.test'
import {
  createChallenge,
  deleteChallenge,
  deleteUserChallenges,
  getChallenge,
  incrementAttempt,
} from './otp'

function newChallenge(overrides: Partial<Parameters<typeof createChallenge>[1]> = {}) {
  return {
    id: 'chal-1',
    userId: 'user-1',
    codeHash: 'a'.repeat(64),
    expiresAt: '2026-06-28T00:10:00.000Z',
    createdAt: '2026-06-28T00:00:00.000Z',
    ...overrides,
  }
}

describe('createChallenge / getChallenge', () => {
  it('persists a challenge with attempts initialized to 0 and reads it back', async () => {
    const { db, store } = memoryDatabase()
    await createChallenge(db, newChallenge())

    expect(store.otpChallenges.size).toBe(1)
    const challenge = await getChallenge(db, 'chal-1')
    expect(challenge).toEqual({
      id: 'chal-1',
      userId: 'user-1',
      codeHash: 'a'.repeat(64),
      expiresAt: '2026-06-28T00:10:00.000Z',
      attempts: 0,
      createdAt: '2026-06-28T00:00:00.000Z',
    })
  })

  it('returns null for an unknown challenge id (a miss is not an error)', async () => {
    const { db } = memoryDatabase()
    expect(await getChallenge(db, 'nope')).toBeNull()
  })

  it('wraps a persistence fault in OtpError on create', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(createChallenge(db, newChallenge())).rejects.toBeInstanceOf(OtpError)
  })

  it('wraps a persistence fault in OtpError on read', async () => {
    const { db, store } = memoryDatabase()
    await createChallenge(db, newChallenge())
    store.failNext = true
    await expect(getChallenge(db, 'chal-1')).rejects.toBeInstanceOf(OtpError)
  })
})

describe('incrementAttempt', () => {
  it('bumps the attempt counter by one each call', async () => {
    const { db } = memoryDatabase()
    await createChallenge(db, newChallenge())
    await incrementAttempt(db, 'chal-1')
    await incrementAttempt(db, 'chal-1')
    expect((await getChallenge(db, 'chal-1'))?.attempts).toBe(2)
  })

  it('wraps a persistence fault in OtpError', async () => {
    const { db, store } = memoryDatabase()
    await createChallenge(db, newChallenge())
    store.failNext = true
    await expect(incrementAttempt(db, 'chal-1')).rejects.toBeInstanceOf(OtpError)
  })
})

describe('deleteChallenge / deleteUserChallenges', () => {
  it('deletes a single challenge by id (idempotent on a missing id)', async () => {
    const { db } = memoryDatabase()
    await createChallenge(db, newChallenge())
    await deleteChallenge(db, 'chal-1')
    expect(await getChallenge(db, 'chal-1')).toBeNull()
    // A second delete is a no-op, not an error.
    await expect(deleteChallenge(db, 'chal-1')).resolves.toBeUndefined()
  })

  it('deletes every challenge for a user, leaving other users untouched', async () => {
    const { db, store } = memoryDatabase()
    await createChallenge(db, newChallenge({ id: 'a', userId: 'user-1' }))
    await createChallenge(db, newChallenge({ id: 'b', userId: 'user-1' }))
    await createChallenge(db, newChallenge({ id: 'c', userId: 'user-2' }))

    await deleteUserChallenges(db, 'user-1')
    expect(await getChallenge(db, 'a')).toBeNull()
    expect(await getChallenge(db, 'b')).toBeNull()
    expect(await getChallenge(db, 'c')).not.toBeNull()
    expect(store.otpChallenges.size).toBe(1)
  })

  it('wraps a persistence fault in OtpError on delete', async () => {
    const { db, store } = memoryDatabase()
    await createChallenge(db, newChallenge())
    store.failNext = true
    await expect(deleteChallenge(db, 'chal-1')).rejects.toBeInstanceOf(OtpError)
  })
})

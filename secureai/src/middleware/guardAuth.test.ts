import { describe, expect, it } from 'vitest'
import type { Database, WriteResult } from '../db/database'
import { loadConfig } from '../config/env'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import {
  createGuardDeviceCredential,
  listGuardDevices,
  touchGuardDeviceCredential,
} from '../db/guardDevices'
import { authenticateGuard } from './guardAuth'

function request(key?: string): Request {
  return new Request('https://secureai.test/api/guard', {
    method: 'POST',
    headers: key === undefined ? {} : { Authorization: `Bearer ${key}` },
  })
}

async function deviceKey(db: ReturnType<typeof memoryDatabase>['db'], userId: string): Promise<string> {
  const minted = await createGuardDeviceCredential(db, {
    userId,
    deviceId: 'dev_auth',
    name: 'Auth test',
    integration: 'codex',
    scopes: ['guard:decision'],
    createdAt: '2026-06-30T00:00:00.000Z',
    expiresAt: '2026-07-30T00:00:00.000Z',
  })
  return minted.credential
}

async function mintDevice(
  db: ReturnType<typeof memoryDatabase>['db'],
  userId: string,
): Promise<{ deviceId: string; credential: string }> {
  const minted = await createGuardDeviceCredential(db, {
    userId,
    deviceId: 'dev_throttle',
    name: 'Throttle test',
    integration: 'claude-code',
    scopes: ['guard:decision'],
    createdAt: '2026-06-30T00:00:00.000Z',
    expiresAt: '2026-07-30T00:00:00.000Z',
  })
  return { deviceId: minted.device.id, credential: minted.credential }
}

describe('authenticateGuard', () => {
  it('resolves a valid device credential with device context', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'guard-auth@example.com')
    const credential = await deviceKey(db, user.id)

    await expect(
      authenticateGuard(
        request(credential),
        db,
        loadConfig({}),
        '2026-06-30T01:00:00.000Z',
      ),
    ).resolves.toEqual({
      subject: user.id,
      tier: 'free',
      credentialKind: 'guard_device',
      deviceId: 'dev_auth',
      integration: 'codex',
    })
  })

  it('rejects account API keys unless fallback is explicitly enabled', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'account-fallback@example.com')

    await expect(
      authenticateGuard(request(apiKey), db, loadConfig({}), '2026-06-30T01:00:00.000Z'),
    ).resolves.toMatchObject({ tier: 'anonymous', credentialKind: 'anonymous' })

    await expect(
      authenticateGuard(
        request(apiKey),
        db,
        loadConfig({ SCANNER_GUARD_ALLOW_ACCOUNT_CREDENTIALS: 'true' }),
        '2026-06-30T01:00:00.000Z',
      ),
    ).resolves.toEqual({ subject: user.id, tier: 'free', credentialKind: 'account' })
  })

  it('does not rewrite last_seen within the throttle window', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'throttle-skip@example.com')
    const { deviceId, credential } = await mintDevice(db, user.id)
    const seededAt = '2026-06-30T12:00:00.000Z'
    await touchGuardDeviceCredential(db, deviceId, seededAt)

    // 100 seconds later, well within the 300-second default throttle.
    const nowIso = '2026-06-30T12:01:40.000Z'
    await authenticateGuard(request(credential), db, loadConfig({}), nowIso)

    const devices = await listGuardDevices(db, user.id)
    expect(devices[0]?.lastSeenAt).toBe(seededAt)
  })

  it('writes last_seen when null or older than the throttle window', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'throttle-write@example.com')
    const { credential } = await mintDevice(db, user.id)

    // Fresh credential: lastSeenAt is null, so a write is due.
    const firstNow = '2026-06-30T10:00:00.000Z'
    await authenticateGuard(request(credential), db, loadConfig({}), firstNow)
    const afterFirst = await listGuardDevices(db, user.id)
    expect(afterFirst[0]?.lastSeenAt).toBe(firstNow)

    // 400 seconds later, beyond the 300-second throttle window.
    const secondNow = '2026-06-30T10:06:40.000Z'
    await authenticateGuard(request(credential), db, loadConfig({}), secondNow)
    const afterSecond = await listGuardDevices(db, user.id)
    expect(afterSecond[0]?.lastSeenAt).toBe(secondNow)
  })

  it('returns the device context even when the last-seen write throws', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'throw-tolerant@example.com')
    const { credential } = await mintDevice(db, user.id)

    // Wrap db so execute always throws; queryOne, queryAll, and batch still delegate.
    const failingDb: Database = {
      queryOne: (sql, params) => db.queryOne(sql, params),
      queryAll: (sql, params) => db.queryAll(sql, params),
      execute: (_sql: string, _params: readonly unknown[]): Promise<WriteResult> =>
        Promise.reject(new Error('injected execute failure')),
      batch: (statements) => db.batch(statements),
    }

    // lastSeenAt is null, so a write would be due, but execute throws. Auth must still resolve.
    const context = await authenticateGuard(
      request(credential),
      failingDb,
      loadConfig({}),
      '2026-06-30T12:00:00.000Z',
    )
    expect(context.credentialKind).toBe('guard_device')
    expect(context.subject).toBe(user.id)
  })
})

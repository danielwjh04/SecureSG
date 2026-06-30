import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import { createFreeUser, sha256Hex } from './accounts'
import {
  createGuardDeviceCredential,
  findGuardDeviceByCredential,
  listGuardDevices,
  revokeGuardDevice,
  touchGuardDeviceCredential,
} from './guardDevices'

function tomorrow(): string {
  return new Date(Date.now() + 86400000).toISOString()
}

describe('guard device credentials', () => {
  it('mints a raw credential once and stores only its SHA-256 digest', async () => {
    const { db, store } = memoryDatabase()
    const { user } = await createFreeUser(db, 'device@example.com')
    const minted = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: 'dev_one',
      name: 'Laptop',
      integration: 'codex',
      scopes: ['guard:decision'],
      createdAt: '2026-06-30T00:00:00.000Z',
      expiresAt: tomorrow(),
    })

    expect(minted.credential).toMatch(/^gd_secureai_[0-9a-f]{64}$/)
    const digest = await sha256Hex(minted.credential)
    expect(store.guardDeviceCredentials.has(digest)).toBe(true)
    expect(JSON.stringify([...store.guardDeviceCredentials.entries()])).not.toContain(
      minted.credential,
    )
  })

  it('resolves active unexpired credentials and rejects expired or revoked ones', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'resolve-device@example.com')
    const minted = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: 'dev_one',
      name: null,
      integration: 'cursor',
      scopes: ['guard:decision'],
      createdAt: '2026-06-30T00:00:00.000Z',
      expiresAt: '2026-07-01T00:00:00.000Z',
    })

    await expect(
      findGuardDeviceByCredential(db, minted.credential, '2026-06-30T12:00:00.000Z'),
    ).resolves.toMatchObject({
      userId: user.id,
      tier: 'free',
      deviceId: 'dev_one',
      integration: 'cursor',
    })
    await expect(
      findGuardDeviceByCredential(db, minted.credential, '2026-07-02T00:00:00.000Z'),
    ).resolves.toBeNull()

    expect(await revokeGuardDevice(db, user.id, minted.device.id)).toBe(true)
    await expect(
      findGuardDeviceByCredential(db, minted.credential, '2026-06-30T12:00:00.000Z'),
    ).resolves.toBeNull()
  })

  it('findGuardDeviceByCredential returns lastSeenAt', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'last-seen@example.com')
    const minted = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: 'dev_ls',
      name: null,
      integration: 'claude-code',
      scopes: ['guard:decision'],
      createdAt: '2026-06-30T00:00:00.000Z',
      expiresAt: '2026-07-30T00:00:00.000Z',
    })

    const fresh = await findGuardDeviceByCredential(db, minted.credential, '2026-06-30T12:00:00.000Z')
    expect(fresh?.lastSeenAt).toBeNull()

    await touchGuardDeviceCredential(db, minted.device.id, '2026-06-30T13:00:00.000Z')

    const seen = await findGuardDeviceByCredential(db, minted.credential, '2026-06-30T14:00:00.000Z')
    expect(seen?.lastSeenAt).toBe('2026-06-30T13:00:00.000Z')
  })

  it('lists devices without exposing raw credentials', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'list-device@example.com')
    const minted = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: 'dev_list',
      name: 'Work laptop',
      integration: 'claude-code',
      scopes: ['guard:decision'],
      createdAt: '2026-06-30T00:00:00.000Z',
      expiresAt: '2026-07-30T00:00:00.000Z',
    })

    const devices = await listGuardDevices(db, user.id)
    expect(devices).toHaveLength(1)
    expect(devices[0]).toMatchObject({
      id: minted.device.id,
      deviceId: 'dev_list',
      name: 'Work laptop',
      integration: 'claude-code',
      status: 'active',
    })
    expect(JSON.stringify(devices)).not.toContain(minted.credential)
  })
})

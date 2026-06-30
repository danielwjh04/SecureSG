import { describe, expect, it } from 'vitest'
import { loadConfig } from '../config/env'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { createGuardDeviceCredential } from '../db/guardDevices'
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
})

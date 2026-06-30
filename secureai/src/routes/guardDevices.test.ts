import { describe, expect, it } from 'vitest'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { loadConfig } from '../config/env'
import {
  handleGuardDeviceList,
  handleGuardDeviceRegister,
  handleGuardDeviceRevoke,
  type GuardDeviceDeps,
} from './guardDevices'

const config = loadConfig({ SCANNER_GUARD_DEVICE_TTL_DAYS: '30' })

function deps(db: GuardDeviceDeps['db']): GuardDeviceDeps {
  return { db, sessionSecret: null, config }
}

function req(
  method: string,
  body: unknown | undefined,
  apiKey?: string,
): Request {
  return new Request('https://secureai.test/api/guard/devices', {
    method,
    headers: {
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(apiKey === undefined ? {} : { Authorization: `Bearer ${apiKey}` }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

describe('guard device routes', () => {
  it('registers a device and returns the raw credential once', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'route-device@example.com')

    const res = await handleGuardDeviceRegister(
      req('POST', { deviceId: 'dev_route', name: 'Route laptop', integration: 'codex' }, apiKey),
      deps(db),
    )

    expect(res.status).toBe(201)
    const body = (await res.json()) as {
      credential: string
      device: { deviceId: string; integration: string; scopes: string[] }
    }
    expect(body.credential).toMatch(/^gd_secureai_/)
    expect(body.device).toMatchObject({
      deviceId: 'dev_route',
      integration: 'codex',
      scopes: ['guard:decision'],
    })
  })

  it('lists and revokes account-owned devices', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'list-route-device@example.com')
    const register = await handleGuardDeviceRegister(
      req('POST', { deviceId: 'dev_list', integration: 'cursor' }, apiKey),
      deps(db),
    )
    const registered = (await register.json()) as { device: { id: string } }

    const list = await handleGuardDeviceList(req('GET', undefined, apiKey), deps(db))
    expect(list.status).toBe(200)
    const listed = (await list.json()) as { devices: { id: string; status: string }[] }
    expect(listed.devices).toHaveLength(1)
    expect(listed.devices[0]).toMatchObject({ id: registered.device.id, status: 'active' })

    const revoke = await handleGuardDeviceRevoke(
      req('POST', { id: registered.device.id }, apiKey),
      deps(db),
    )
    expect(revoke.status).toBe(200)
    await expect(revoke.json()).resolves.toEqual({ revoked: true })
  })

  it('requires account authentication to manage devices', async () => {
    const { db } = memoryDatabase()
    const res = await handleGuardDeviceRegister(
      req('POST', { integration: 'codex' }),
      deps(db),
    )
    expect(res.status).toBe(401)
  })
})

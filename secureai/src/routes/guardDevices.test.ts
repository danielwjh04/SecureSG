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
const capConfig = loadConfig({ SCANNER_GUARD_DEVICE_TTL_DAYS: '30', SCANNER_GUARD_MAX_DEVICES_PER_ACCOUNT: '2' })

function deps(db: GuardDeviceDeps['db']): GuardDeviceDeps {
  return { db, sessionSecret: null, config }
}

function capDeps(db: GuardDeviceDeps['db']): GuardDeviceDeps {
  return { db, sessionSecret: null, config: capConfig }
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

  it('rejects registration of a new device when the active cap is reached (429)', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'cap-test@example.com')

    // Fill the cap (2 devices, 2 different device IDs).
    await handleGuardDeviceRegister(
      req('POST', { deviceId: 'cap_dev_1', integration: 'claude-code' }, apiKey),
      capDeps(db),
    )
    await handleGuardDeviceRegister(
      req('POST', { deviceId: 'cap_dev_2', integration: 'claude-code' }, apiKey),
      capDeps(db),
    )

    // Third NEW device should be rejected.
    const res = await handleGuardDeviceRegister(
      req('POST', { deviceId: 'cap_dev_3', integration: 'claude-code' }, apiKey),
      capDeps(db),
    )
    expect(res.status).toBe(429)
  })

  it('re-registering an existing device at the cap still returns 201 (rotation, not a new device)', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'cap-rotate@example.com')

    // Fill the cap.
    await handleGuardDeviceRegister(
      req('POST', { deviceId: 'rot_dev_1', integration: 'claude-code' }, apiKey),
      capDeps(db),
    )
    await handleGuardDeviceRegister(
      req('POST', { deviceId: 'rot_dev_2', integration: 'claude-code' }, apiKey),
      capDeps(db),
    )

    // Re-registering an already-active (deviceId, integration) is rotation, allowed at the cap.
    const res = await handleGuardDeviceRegister(
      req('POST', { deviceId: 'rot_dev_1', integration: 'claude-code' }, apiKey),
      capDeps(db),
    )
    expect(res.status).toBe(201)
  })
})

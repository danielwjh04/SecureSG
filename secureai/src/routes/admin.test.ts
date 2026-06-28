import { describe, expect, it } from 'vitest'
import type { AdminDeps, AdminMembersPage, AdminOverview } from './admin'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser, setUserTier, sha256Hex } from '../db/accounts'
import { setUserRole } from '../db/admin'
import { recordVerdict } from '../db/usage'
import { upsertSubscription } from '../db/billing'
import { insertScan } from '../db/scans'
import { createChallenge } from '../db/otp'
import { loadConfig } from '../config/env'
import { signSession, SESSION_COOKIE_NAME } from '../auth/session'
import {
  handleAdminMemberRemove,
  handleAdminMemberRole,
  handleAdminMembers,
  handleAdminOverview,
} from './admin'

const ADMIN_EMAIL = 'owner@example.com'
const SECRET = 'admin-route-test-secret'
const config = loadConfig({ SCANNER_ADMIN_EMAILS: ADMIN_EMAIL })

function deps(db: AdminDeps['db'], sessionSecret: string | null = SECRET): AdminDeps {
  return { db, sessionSecret, config }
}

function getReq(headers: Record<string, string> = {}): Request {
  return new Request('https://secureai.test/api/admin/overview', { headers })
}

/** Provision an account at a tier and return a Bearer-auth request for it. */
async function adminBearer(db: AdminDeps['db']): Promise<string> {
  if (db === null) throw new Error('db required')
  const { apiKey } = await createFreeUser(db, ADMIN_EMAIL)
  return apiKey
}

function bearer(apiKey: string): Record<string, string> {
  return { Authorization: `Bearer ${apiKey}` }
}

function membersReq(headers: Record<string, string> = {}, query = ''): Request {
  return new Request(`https://secureai.test/api/admin/members${query}`, { headers })
}

function roleReq(headers: Record<string, string>, body: unknown): Request {
  return new Request('https://secureai.test/api/admin/members/role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

function removeReq(headers: Record<string, string>, body: unknown): Request {
  return new Request('https://secureai.test/api/admin/members/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

describe('handleAdminOverview', () => {
  it('returns 200 with the full overview for an admin email', async () => {
    const { db, store } = memoryDatabase()
    const apiKey = await adminBearer(db)
    // A second (non-admin) pro account + a usage row + an active subscription.
    const { user: pro } = await createFreeUser(db, 'paid@example.com')
    await setUserTier(db, pro.id, 'pro')
    const day = new Date().toISOString().slice(0, 10)
    await recordVerdict(db, pro.id, day, 'BLOCK', 4, { ai: true })
    await upsertSubscription(db, pro.id, 'active', 'price_pro', null)
    // Stamp both signups to today so they fall in the 30-day window.
    for (const u of store.users.values()) {
      u.created_at = `${day}T08:00:00.000Z`
    }

    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as AdminOverview
    expect(body.totalUsers).toBe(2)
    expect(body.usersByTier).toEqual({ free: 1, pro: 1, enterprise: 0 })
    expect(body.usageTotals).toEqual({ scans: 1, allows: 0, reviews: 0, blocks: 1, flagged: 4 })
    expect(body.activeSubscriptions).toBe(1)
    expect(body.signupsDaily).toEqual([{ day, count: 2 }])
    expect(typeof body.generatedAt).toBe('string')
    expect(Number.isNaN(Date.parse(body.generatedAt))).toBe(false)
  })

  it('authenticates an admin via a session cookie too', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, ADMIN_EMAIL)
    const token = await signSession(user.id, Math.floor(Date.now() / 1000), 3600, SECRET)
    const res = await handleAdminOverview(
      getReq({ Cookie: `${SESSION_COOKIE_NAME}=${token}` }),
      deps(db),
    )
    expect(res.status).toBe(200)
  })

  it('returns 403 for an authenticated non-admin account', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'notadmin@example.com')
    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(403)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('forbidden')
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const res = await handleAdminOverview(getReq(), deps(db))
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleAdminOverview(getReq(), deps(null))
    expect(res.status).toBe(503)
  })

  it('returns an all-zero overview when there is no data beyond the admin', async () => {
    const { db } = memoryDatabase()
    const apiKey = await adminBearer(db)
    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as AdminOverview
    expect(body.totalUsers).toBe(1)
    expect(body.usageTotals).toEqual({ scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 })
    expect(body.activeSubscriptions).toBe(0)
  })

  it('maps a persistence fault during aggregation to 500', async () => {
    const { db, store } = memoryDatabase()
    const apiKey = await adminBearer(db)
    // Auth + profile reads succeed; the user-count aggregate read throws.
    const original = store.queryOne.bind(store)
    store.queryOne = (sql: string, params: readonly unknown[]) => {
      if (sql.includes('COUNT(*) AS total FROM users')) {
        throw new Error('injected admin failure')
      }
      return original(sql, params)
    }
    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(500)
  })

  it('lets an admin (granted role) view the overview, not just an owner', async () => {
    const { db } = memoryDatabase()
    await adminBearer(db) // the owner exists
    const { user, apiKey } = await createFreeUser(db, 'staff@example.com')
    await setUserRole(db, user.id, 'admin')
    const res = await handleAdminOverview(getReq(bearer(apiKey)), deps(db))
    expect(res.status).toBe(200)
  })
})

describe('handleAdminMembers', () => {
  it('returns the directory for an owner, with the owner shown as role owner', async () => {
    const { db } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const { user: u } = await createFreeUser(db, 'member@example.com')
    const day = new Date().toISOString().slice(0, 10)
    await recordVerdict(db, u.id, day, 'ALLOW', 0, { ai: false })

    const res = await handleAdminMembers(membersReq(bearer(ownerKey)), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as AdminMembersPage
    expect(body.total).toBe(2)
    const owner = body.members.find((m) => m.email === ADMIN_EMAIL)
    const member = body.members.find((m) => m.email === 'member@example.com')
    expect(owner?.role).toBe('owner')
    expect(member?.role).toBe('member')
    expect(member?.scans).toBe(1)
  })

  it('lets a granted admin view the directory too (200)', async () => {
    const { db } = memoryDatabase()
    await adminBearer(db)
    const { user, apiKey } = await createFreeUser(db, 'admin2@example.com')
    await setUserRole(db, user.id, 'admin')
    const res = await handleAdminMembers(membersReq(bearer(apiKey)), deps(db))
    expect(res.status).toBe(200)
  })

  it('forbids a plain member (403)', async () => {
    const { db } = memoryDatabase()
    await adminBearer(db)
    const { apiKey } = await createFreeUser(db, 'plain@example.com')
    const res = await handleAdminMembers(membersReq(bearer(apiKey)), deps(db))
    expect(res.status).toBe(403)
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const res = await handleAdminMembers(membersReq(), deps(db))
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleAdminMembers(membersReq(), deps(null))
    expect(res.status).toBe(503)
  })

  it('honors limit + offset query params', async () => {
    const { db, store } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    // Make the owner the oldest so the page boundary is deterministic.
    for (const u of store.users.values()) {
      u.created_at = '2026-01-01T00:00:00.000Z'
    }
    await createFreeUser(db, 'b@example.com')
    await createFreeUser(db, 'c@example.com')
    const res = await handleAdminMembers(membersReq(bearer(ownerKey), '?limit=1&offset=1'), deps(db))
    const body = (await res.json()) as AdminMembersPage
    expect(body.members).toHaveLength(1)
    expect(body.total).toBe(3)
  })
})

describe('handleAdminMemberRole', () => {
  it('lets an owner promote a member to admin (200) and persists it', async () => {
    const { db } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const { user } = await createFreeUser(db, 'promote@example.com')
    const res = await handleAdminMemberRole(roleReq(bearer(ownerKey), { userId: user.id, role: 'admin' }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { id: string; role: string }
    expect(body).toEqual({ id: user.id, role: 'admin' })
  })

  it('lets an owner demote an admin back to member (200)', async () => {
    const { db } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const { user } = await createFreeUser(db, 'demote@example.com')
    await setUserRole(db, user.id, 'admin')
    const res = await handleAdminMemberRole(roleReq(bearer(ownerKey), { userId: user.id, role: 'member' }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { id: string; role: string }
    expect(body.role).toBe('member')
  })

  it('forbids a granted admin from changing roles (403)', async () => {
    const { db } = memoryDatabase()
    await adminBearer(db)
    const { user: adminUser, apiKey: adminKey } = await createFreeUser(db, 'admin3@example.com')
    await setUserRole(db, adminUser.id, 'admin')
    const { user: target } = await createFreeUser(db, 'target@example.com')
    const res = await handleAdminMemberRole(roleReq(bearer(adminKey), { userId: target.id, role: 'admin' }), deps(db))
    expect(res.status).toBe(403)
  })

  it('forbids a plain member from changing roles (403)', async () => {
    const { db } = memoryDatabase()
    await adminBearer(db)
    const { apiKey: memberKey } = await createFreeUser(db, 'm@example.com')
    const { user: target } = await createFreeUser(db, 't@example.com')
    const res = await handleAdminMemberRole(roleReq(bearer(memberKey), { userId: target.id, role: 'admin' }), deps(db))
    expect(res.status).toBe(403)
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const { user: target } = await createFreeUser(db, 't@example.com')
    const res = await handleAdminMemberRole(roleReq({}, { userId: target.id, role: 'admin' }), deps(db))
    expect(res.status).toBe(401)
  })

  it('rejects an invalid role with 422 and leaves the target untouched', async () => {
    const { db, store } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const { user: target } = await createFreeUser(db, 't@example.com')
    const res = await handleAdminMemberRole(roleReq(bearer(ownerKey), { userId: target.id, role: 'owner' }), deps(db))
    expect(res.status).toBe(422)
    // `owner` is never assignable: the stored column stays at the default member.
    expect(store.users.get(target.id)?.role).toBe('member')
  })

  it('forbids changing an owner-by-email target with 403', async () => {
    const { db } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    // A SECOND owner email, to be the target of an attempted demotion.
    const ownerConfig = loadConfig({ SCANNER_ADMIN_EMAILS: `${ADMIN_EMAIL},co-owner@example.com` })
    const { user: coOwner } = await createFreeUser(db, 'co-owner@example.com')
    const res = await handleAdminMemberRole(
      roleReq(bearer(ownerKey), { userId: coOwner.id, role: 'member' }),
      { db, sessionSecret: SECRET, config: ownerConfig },
    )
    expect(res.status).toBe(403)
  })

  it('returns 404 for an unknown user id', async () => {
    const { db } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const res = await handleAdminMemberRole(roleReq(bearer(ownerKey), { userId: 'ghost', role: 'admin' }), deps(db))
    expect(res.status).toBe(404)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleAdminMemberRole(roleReq({}, { userId: 'x', role: 'admin' }), deps(null))
    expect(res.status).toBe(503)
  })
})

describe('handleAdminMemberRemove', () => {
  it('lets an owner remove a member (200) and hard-deletes the user + every related row', async () => {
    const { db, store } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const { user: target, apiKey: targetKey } = await createFreeUser(db, 'gone@example.com')
    // Seed a row in every table keyed by the target's user id.
    const day = new Date().toISOString().slice(0, 10)
    await recordVerdict(db, target.id, day, 'BLOCK', 2, { ai: true })
    await upsertSubscription(db, target.id, 'active', 'price_pro', null)
    await insertScan(db, {
      id: 'scan-1',
      userId: target.id,
      verdict: 'BLOCK',
      sourceKind: 'url',
      sourceRef: 'https://x.test',
      flagged: 2,
      headHash: 'h1',
      scannedAt: `${day}T00:00:00.000Z`,
    })
    await createChallenge(db, {
      id: 'otp-1',
      userId: target.id,
      codeHash: 'codehash',
      expiresAt: `${day}T01:00:00.000Z`,
      createdAt: `${day}T00:00:00.000Z`,
    })
    const targetKeyHash = await sha256Hex(targetKey)
    // Precondition: every table holds the target's row.
    expect(store.users.has(target.id)).toBe(true)
    expect(store.apiKeys.has(targetKeyHash)).toBe(true)
    expect(store.usage.has(`${target.id} ${day}`)).toBe(true)
    expect(store.scanHistory.has('scan-1')).toBe(true)
    expect(store.subscriptions.has(target.id)).toBe(true)
    expect(store.otpChallenges.has('otp-1')).toBe(true)

    const res = await handleAdminMemberRemove(removeReq(bearer(ownerKey), { userId: target.id }), deps(db))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ removed: target.id })

    // Postcondition: the user and EVERY row keyed by its id are gone.
    expect(store.users.has(target.id)).toBe(false)
    expect(store.apiKeys.has(targetKeyHash)).toBe(false)
    expect(store.usage.has(`${target.id} ${day}`)).toBe(false)
    expect(store.scanHistory.has('scan-1')).toBe(false)
    expect(store.subscriptions.has(target.id)).toBe(false)
    expect(store.otpChallenges.has('otp-1')).toBe(false)
  })

  it('forbids a granted admin from removing a member (403) and leaves the target intact', async () => {
    const { db, store } = memoryDatabase()
    await adminBearer(db)
    const { user: adminUser, apiKey: adminKey } = await createFreeUser(db, 'admin-rm@example.com')
    await setUserRole(db, adminUser.id, 'admin')
    const { user: target } = await createFreeUser(db, 'keep@example.com')
    const res = await handleAdminMemberRemove(removeReq(bearer(adminKey), { userId: target.id }), deps(db))
    expect(res.status).toBe(403)
    expect(store.users.has(target.id)).toBe(true)
  })

  it('forbids a plain member from removing anyone (403)', async () => {
    const { db, store } = memoryDatabase()
    await adminBearer(db)
    const { apiKey: memberKey } = await createFreeUser(db, 'm-rm@example.com')
    const { user: target } = await createFreeUser(db, 't-rm@example.com')
    const res = await handleAdminMemberRemove(removeReq(bearer(memberKey), { userId: target.id }), deps(db))
    expect(res.status).toBe(403)
    expect(store.users.has(target.id)).toBe(true)
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const { user: target } = await createFreeUser(db, 't-anon@example.com')
    const res = await handleAdminMemberRemove(removeReq({}, { userId: target.id }), deps(db))
    expect(res.status).toBe(401)
  })

  it('forbids removing an owner-by-email target with 403 and leaves it intact', async () => {
    const { db, store } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const ownerConfig = loadConfig({ SCANNER_ADMIN_EMAILS: `${ADMIN_EMAIL},co-owner@example.com` })
    const { user: coOwner } = await createFreeUser(db, 'co-owner@example.com')
    const res = await handleAdminMemberRemove(
      removeReq(bearer(ownerKey), { userId: coOwner.id }),
      { db, sessionSecret: SECRET, config: ownerConfig },
    )
    expect(res.status).toBe(403)
    expect(store.users.has(coOwner.id)).toBe(true)
  })

  it('forbids an owner from removing their own account with 403', async () => {
    const { db, store } = memoryDatabase()
    const { user: owner, apiKey: ownerKey } = await createFreeUser(db, ADMIN_EMAIL)
    const res = await handleAdminMemberRemove(removeReq(bearer(ownerKey), { userId: owner.id }), deps(db))
    expect(res.status).toBe(403)
    expect(store.users.has(owner.id)).toBe(true)
  })

  it('returns 404 for an unknown user id', async () => {
    const { db } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const res = await handleAdminMemberRemove(removeReq(bearer(ownerKey), { userId: 'ghost' }), deps(db))
    expect(res.status).toBe(404)
  })

  it('rejects a malformed body with 422', async () => {
    const { db } = memoryDatabase()
    const ownerKey = await adminBearer(db)
    const res = await handleAdminMemberRemove(removeReq(bearer(ownerKey), { nope: true }), deps(db))
    expect(res.status).toBe(422)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleAdminMemberRemove(removeReq({}, { userId: 'x' }), deps(null))
    expect(res.status).toBe(503)
  })
})

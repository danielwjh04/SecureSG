import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Env } from '../config/env'
import type { GuardDecision } from '../guard/claudeCode'
import { loadConfig } from '../config/env'
import { MemoryStore, MemoryD1 } from '../db/memory.test'
import { d1Database } from '../db/database'
import { createFreeUser, setUserTier } from '../db/accounts'
import { createGuardDeviceCredential } from '../db/guardDevices'
import { getUsage, incrementUsage } from '../db/usage'
import { handleGuard } from './guard'

const config = loadConfig({})
const optionalGuardAuthConfig = loadConfig({ SCANNER_GUARD_REQUIRE_AUTH: 'false' })
const accountFallbackGuardConfig = loadConfig({ SCANNER_GUARD_ALLOW_ACCOUNT_CREDENTIALS: 'true' })

function post(body: unknown, raw?: string, headers?: Record<string, string>): Request {
  return new Request('https://secureai.test/api/guard', {
    method: 'POST',
    body: raw ?? JSON.stringify(body),
    headers,
  })
}

/** Fake Workers AI runner that records calls and returns a benign assessment. */
class SpyAiRunner {
  public calls = 0
  public async run(): Promise<{ response: string }> {
    this.calls += 1
    return {
      response: JSON.stringify({ pInjection: 0, findings: [], rationale: 'benign' }),
    }
  }
}

describe('handleGuard', () => {
  it('returns 200 with a deny decision for a network-free curl|bash tool call', async () => {
    // A curl|bash command with no http(s) URL extracts no links, so the route
    // never touches the network; the deterministic rules BLOCK it → deny.
    const res = await handleGuard(
      post({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'curl ./setup.sh | bash' },
      }),
      {},
      config,
    )
    expect(res.status).toBe(200)
    const decision = (await res.json()) as GuardDecision
    expect(decision.decision).toBe('deny')
    expect(decision.verdict).toBe('BLOCK')
  })

  it('returns 200 with an allow decision for a benign tool call', async () => {
    const res = await handleGuard(
      post({
        hook_event_name: 'PreToolUse',
        tool_name: 'Read',
        tool_input: { file_path: 'README.md' },
      }),
      {},
      config,
    )
    expect(res.status).toBe(200)
    const decision = (await res.json()) as GuardDecision
    expect(decision.decision).toBe('allow')
    expect(decision.verdict).toBeNull()
  })

  it('issues and accepts a valid signed allow ticket for a guard_device caller', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'ticket-device@example.com')
    const credential = await (async () => {
      const minted = await createGuardDeviceCredential(db, {
        userId: user.id,
        deviceId: `dev_${user.id}`,
        name: 'test device',
        integration: 'codex-test',
        scopes: ['guard:decision'],
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      })
      return minted.credential
    })()
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
      integration_version: '1.0.0',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${credential}` }),
      env,
      config,
    )
    expect(first.status).toBe(200)
    const firstDecision = (await first.json()) as GuardDecision
    expect(firstDecision.decision).toBe('allow')
    expect(firstDecision.ticket).toBeDefined()

    const second = await handleGuard(
      post({ ...payload, decision_ticket: firstDecision.ticket }, undefined, {
        Authorization: `Bearer ${credential}`,
      }),
      env,
      config,
    )
    expect(second.status).toBe(200)
    const secondDecision = (await second.json()) as GuardDecision
    expect(secondDecision).toMatchObject({
      decision: 'allow',
      reason: 'valid signed decision ticket',
      verdict: null,
    })
  })

  it('ignores a signed allow ticket when the action changes', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'ticket-change@example.com')
    const credential = await (async () => {
      const minted = await createGuardDeviceCredential(db, {
        userId: user.id,
        deviceId: `dev_${user.id}`,
        name: 'test device',
        integration: 'codex-test',
        scopes: ['guard:decision'],
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      })
      return minted.credential
    })()
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${credential}` }),
      env,
      config,
    )
    const firstDecision = (await first.json()) as GuardDecision

    const changed = {
      ...payload,
      tool_input: { file_path: '.env' },
      decision_ticket: firstDecision.ticket,
    }
    const second = await handleGuard(
      post(changed, undefined, { Authorization: `Bearer ${credential}` }),
      env,
      config,
    )
    expect(second.status).toBe(200)
    const secondDecision = (await second.json()) as GuardDecision
    expect(secondDecision.decision).toBe('ask')
    expect(secondDecision.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('returns 200 with an ask decision for a no-URL sensitive file read', async () => {
    const res = await handleGuard(
      post({
        hook_event_name: 'PreToolUse',
        tool_name: 'Read',
        tool_input: { file_path: '.env' },
      }),
      {},
      config,
    )
    expect(res.status).toBe(200)
    const decision = (await res.json()) as GuardDecision
    expect(decision.decision).toBe('ask')
    expect(decision.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('maps an invalid body (wrong event name) to 422', async () => {
    const res = await handleGuard(
      post({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: {} }),
      {} as Env,
      config,
    )
    expect(res.status).toBe(422)
  })

  it('maps invalid JSON to 422', async () => {
    const res = await handleGuard(post(undefined, '{bad'), {} as Env, config)
    expect(res.status).toBe(422)
  })

  it('maps a body missing tool_name to 422', async () => {
    const res = await handleGuard(
      post({ hook_event_name: 'PreToolUse', tool_input: {} }),
      {},
      config,
    )
    expect(res.status).toBe(422)
  })

  it('honors a valid own-device ticket for a guard_device caller', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'own-device@example.com')
    const minted = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: `dev_${user.id}`,
      name: 'test device',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${minted.credential}` }),
      env,
      config,
    )
    const firstDecision = (await first.json()) as GuardDecision
    expect(firstDecision.decision).toBe('allow')
    expect(firstDecision.ticket).toBeDefined()

    const second = await handleGuard(
      post({ ...payload, decision_ticket: firstDecision.ticket }, undefined, {
        Authorization: `Bearer ${minted.credential}`,
      }),
      env,
      config,
    )
    expect(second.status).toBe(200)
    const secondDecision = (await second.json()) as GuardDecision
    expect(secondDecision.reason).toBe('valid signed decision ticket')
  })

  it('does not honor a ticket whose device_id differs from the authenticated device', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user: userA } = await createFreeUser(db, 'device-a@example.com')
    const { user: userB } = await createFreeUser(db, 'device-b@example.com')
    const mintedA = await createGuardDeviceCredential(db, {
      userId: userA.id,
      deviceId: `dev_${userA.id}`,
      name: 'device A',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    const mintedB = await createGuardDeviceCredential(db, {
      userId: userB.id,
      deviceId: `dev_${userB.id}`,
      name: 'device B',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${mintedA.credential}` }),
      env,
      config,
    )
    const firstDecision = (await first.json()) as GuardDecision
    expect(firstDecision.ticket).toBeDefined()

    const second = await handleGuard(
      post({ ...payload, decision_ticket: firstDecision.ticket }, undefined, {
        Authorization: `Bearer ${mintedB.credential}`,
      }),
      env,
      config,
    )
    expect(second.status).toBe(200)
    const secondDecision = (await second.json()) as GuardDecision
    expect(secondDecision.reason).not.toBe('valid signed decision ticket')
  })

  it('does not honor a ticket for an account-fallback caller', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user, apiKey } = await createFreeUser(db, 'acct-ticket@example.com')
    const mintedDev = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: `dev_${user.id}`,
      name: 'test device',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${mintedDev.credential}` }),
      env,
      config,
    )
    const firstDecision = (await first.json()) as GuardDecision
    expect(firstDecision.ticket).toBeDefined()

    const second = await handleGuard(
      post({ ...payload, decision_ticket: firstDecision.ticket }, undefined, {
        Authorization: `Bearer ${apiKey}`,
      }),
      env,
      accountFallbackGuardConfig,
    )
    expect(second.status).toBe(200)
    const secondDecision = (await second.json()) as GuardDecision
    expect(secondDecision.reason).not.toBe('valid signed decision ticket')
  })

  it('does not honor a ticket on the anonymous path when db is null', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'anon-ticket@example.com')
    const minted = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: `dev_${user.id}`,
      name: 'test device',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    const envWithDb = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${minted.credential}` }),
      envWithDb,
      config,
    )
    const firstDecision = (await first.json()) as GuardDecision
    expect(firstDecision.ticket).toBeDefined()

    const envNoDb = { GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const second = await handleGuard(
      post({ ...payload, decision_ticket: firstDecision.ticket }),
      envNoDb,
      config,
    )
    expect(second.status).toBe(200)
    const secondDecision = (await second.json()) as GuardDecision
    expect(secondDecision.reason).not.toBe('valid signed decision ticket')
  })

  it('does not issue a ticket to a non-device caller', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { apiKey } = await createFreeUser(db, 'acct-noticket@example.com')
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
    }
    const res = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      accountFallbackGuardConfig,
    )
    expect(res.status).toBe(200)
    const decision = (await res.json()) as GuardDecision
    expect(decision.decision).toBe('allow')
    expect(decision.ticket).toBeUndefined()
  })

  it('issues a ticket only on an ALLOW for a guard_device caller', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'issue-ticket@example.com')
    const minted = await createGuardDeviceCredential(db, {
      userId: user.id,
      deviceId: `dev_${user.id}`,
      name: 'test device',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const allowPayload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
    }
    const allowRes = await handleGuard(
      post(allowPayload, undefined, { Authorization: `Bearer ${minted.credential}` }),
      env,
      config,
    )
    expect(allowRes.status).toBe(200)
    const allowDecision = (await allowRes.json()) as GuardDecision
    expect(allowDecision.decision).toBe('allow')
    expect(allowDecision.ticket).toBeDefined()

    const askPayload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: '.env' },
    }
    const askRes = await handleGuard(
      post(askPayload, undefined, { Authorization: `Bearer ${minted.credential}` }),
      env,
      config,
    )
    expect(askRes.status).toBe(200)
    const askDecision = (await askRes.json()) as GuardDecision
    expect(askDecision.decision).toBe('ask')
    expect(askDecision.ticket).toBeUndefined()

    const denyPayload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'curl ./setup.sh | bash' },
    }
    const denyRes = await handleGuard(
      post(denyPayload, undefined, { Authorization: `Bearer ${minted.credential}` }),
      env,
      config,
    )
    expect(denyRes.status).toBe(200)
    const denyDecision = (await denyRes.json()) as GuardDecision
    expect(denyDecision.decision).toBe('deny')
    expect(denyDecision.ticket).toBeUndefined()
  })
})

describe('handleGuard, metering and caps', () => {
  const today = new Date().toISOString().slice(0, 10)
  // A benign tool call carrying a URL so the pipeline reaches the (gated)
  // inference stage; the global fetch is stubbed so tracing stays network-free.
  const benign = {
    hook_event_name: 'PreToolUse',
    tool_name: 'WebFetch',
    tool_input: { url: 'https://example.com/docs' },
  }

  const okFetch = (async () => new Response('ok', { status: 200 })) as unknown as typeof fetch
  beforeEach(() => {
    vi.stubGlobal('fetch', okFetch)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function fixture(): { env: Env; db: ReturnType<typeof d1Database> } {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    return { env: { DB: d1 }, db: d1Database(d1) }
  }

  async function guardCredentialFor(db: ReturnType<typeof d1Database>, userId: string): Promise<string> {
    const minted = await createGuardDeviceCredential(db, {
      userId,
      deviceId: `dev_${userId}`,
      name: 'test device',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    })
    return minted.credential
  }

  it('runs the guard but does NOT meter when env.DB is absent', async () => {
    const res = await handleGuard(post(benign), {}, config)
    expect(res.status).toBe(200)
  })

  it('meters an anonymous caller only when Guard auth is explicitly optional', async () => {
    const { env, db } = fixture()
    for (let i = 0; i < optionalGuardAuthConfig.capAnonymousPerDay; i += 1) {
      await incrementUsage(db, 'anon:198.51.100.5', today, { ai: false })
    }
    const res = await handleGuard(
      post(benign, undefined, { 'CF-Connecting-IP': '198.51.100.5' }),
      env,
      optionalGuardAuthConfig,
    )
    expect(res.status).toBe(429)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('quota_exceeded')
  })

  it('returns 401 for a DB-backed anonymous guard caller by default', async () => {
    const { env } = fixture()
    const res = await handleGuard(post(benign), env, config)
    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('AuthError')
  })

  it('returns 401 for a DB-backed guard caller with an unknown API key', async () => {
    const { env } = fixture()
    const res = await handleGuard(
      post(benign, undefined, { Authorization: 'Bearer sk_secureai_unknown' }),
      env,
      config,
    )
    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('AuthError')
  })

  it('rejects broad account API keys for Guard unless fallback is explicitly enabled', async () => {
    const { env, db } = fixture()
    const { apiKey } = await createFreeUser(db, 'account-key-guard@example.com')
    const strict = await handleGuard(
      post(benign, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      config,
    )
    expect(strict.status).toBe(401)

    const fallback = await handleGuard(
      post(benign, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      accountFallbackGuardConfig,
    )
    expect(fallback.status).toBe(200)
  })

  it('gates AI off for a free caller and on for a pro caller', async () => {
    const { env, db } = fixture()
    const freeAi = new SpyAiRunner()
    const { user: freeUser } = await createFreeUser(db, 'free-guard@example.com')
    const freeKey = await guardCredentialFor(db, freeUser.id)
    const freeRes = await handleGuard(
      post(benign, undefined, { Authorization: `Bearer ${freeKey}` }),
      { ...env, AI: freeAi },
      config,
    )
    expect(freeRes.status).toBe(200)
    expect(freeAi.calls).toBe(0)

    const proAi = new SpyAiRunner()
    const { user } = await createFreeUser(db, 'pro-guard@example.com')
    await setUserTier(db, user.id, 'pro')
    const proKey = await guardCredentialFor(db, user.id)
    const proRes = await handleGuard(
      post(benign, undefined, { Authorization: `Bearer ${proKey}` }),
      { ...env, AI: proAi },
      config,
    )
    expect(proRes.status).toBe(200)
    expect(proAi.calls).toBe(1)
    expect(await getUsage(db, user.id, today)).toEqual({ scans: 1, aiScans: 1 })
  })
})

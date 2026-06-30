import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Env } from '../config/env'
import type { GuardDecision } from '../guard/claudeCode'
import { loadConfig } from '../config/env'
import { MemoryStore, MemoryD1 } from '../db/memory.test'
import { d1Database } from '../db/database'
import { createFreeUser, setUserTier } from '../db/accounts'
import { createGuardDeviceCredential } from '../db/guardDevices'
import { signGuardDecisionTicket } from '../guard/decisionTicket'
import { getUsage, incrementUsage } from '../db/usage'
import { replaceFeed } from '../db/feed'
import { setMetricsDataset } from '../observability/metrics'
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

async function guardCredentialFor(db: ReturnType<typeof d1Database>, userId: string): Promise<string> {
  const minted = await createGuardDeviceCredential(
    db,
    {
      userId,
      deviceId: `dev_${userId}`,
      name: 'test device',
      integration: 'codex-test',
      scopes: ['guard:decision'],
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    },
    32,
  )
  return minted.credential
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
    const credential = await guardCredentialFor(db, user.id)
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
    const credential = await guardCredentialFor(db, user.id)
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
    const credential = await guardCredentialFor(db, user.id)
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
    expect(secondDecision.reason).toBe('valid signed decision ticket')
  })

  it('does not honor a ticket whose device_id differs from the authenticated device', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user: userA } = await createFreeUser(db, 'device-a@example.com')
    const { user: userB } = await createFreeUser(db, 'device-b@example.com')
    const mintedA = await createGuardDeviceCredential(
      db,
      {
        userId: userA.id,
        deviceId: `dev_${userA.id}`,
        name: 'device A',
        integration: 'codex-test',
        scopes: ['guard:decision'],
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      },
      32,
    )
    const mintedB = await createGuardDeviceCredential(
      db,
      {
        userId: userB.id,
        deviceId: `dev_${userB.id}`,
        name: 'device B',
        integration: 'codex-test',
        scopes: ['guard:decision'],
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      },
      32,
    )
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
    const devCredential = await guardCredentialFor(db, user.id)
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${devCredential}` }),
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
    const anonCredential = await guardCredentialFor(db, user.id)
    const envWithDb = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${anonCredential}` }),
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

  it('issues a ticket only on an ALLOW for a guard_device caller with a project scope', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'issue-ticket@example.com')
    const issueCredential = await guardCredentialFor(db, user.id)
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const allowPayload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }
    const allowRes = await handleGuard(
      post(allowPayload, undefined, { Authorization: `Bearer ${issueCredential}` }),
      env,
      config,
    )
    expect(allowRes.status).toBe(200)
    const allowDecision = (await allowRes.json()) as GuardDecision
    expect(allowDecision.decision).toBe('allow')
    expect(allowDecision.ticket).toBeDefined()

    // No cwd: no ticket even on allow (requires project scope).
    const noCwdPayload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
    }
    const noCwdRes = await handleGuard(
      post(noCwdPayload, undefined, { Authorization: `Bearer ${issueCredential}` }),
      env,
      config,
    )
    expect(noCwdRes.status).toBe(200)
    const noCwdDecision = (await noCwdRes.json()) as GuardDecision
    expect(noCwdDecision.decision).toBe('allow')
    expect(noCwdDecision.ticket).toBeUndefined()

    const askPayload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: '.env' },
      cwd: '/workspace/project',
    }
    const askRes = await handleGuard(
      post(askPayload, undefined, { Authorization: `Bearer ${issueCredential}` }),
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
      cwd: '/workspace/project',
    }
    const denyRes = await handleGuard(
      post(denyPayload, undefined, { Authorization: `Bearer ${issueCredential}` }),
      env,
      config,
    )
    expect(denyRes.status).toBe(200)
    const denyDecision = (await denyRes.json()) as GuardDecision
    expect(denyDecision.decision).toBe('deny')
    expect(denyDecision.ticket).toBeUndefined()
  })

  it('a ticket stops being honored after the feed version changes', async () => {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'feed-ticket@example.com')
    const credential = await guardCredentialFor(db, user.id)
    const feedConfig = loadConfig({ SCANNER_FEED_ENABLED: 'true' })
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }

    // Seed feed at version A.
    await replaceFeed(db, 1000, '2026-06-30T00:00:00.000Z', [
      { kind: 'host', value: 'evil.com', source: 'urlhaus' },
    ])

    // Issue a ticket at feed version A.
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${credential}` }),
      env,
      feedConfig,
    )
    const firstDecision = (await first.json()) as GuardDecision
    expect(firstDecision.ticket).toBeDefined()

    // Bump feed to version B.
    store.feedMetaVersion = 2000

    // Present the ticket at version B: it must NOT be honored.
    const second = await handleGuard(
      post({ ...payload, decision_ticket: firstDecision.ticket }, undefined, {
        Authorization: `Bearer ${credential}`,
      }),
      env,
      feedConfig,
    )
    expect(second.status).toBe(200)
    const secondDecision = (await second.json()) as GuardDecision
    expect(secondDecision.reason).not.toBe('valid signed decision ticket')
  })

  it('an expired credential at the live guard route is rejected (401)', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'expired-cred@example.com')
    // Mint a credential whose expiresAt is one second in the past.
    const minted = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_expired',
        name: 'expired device',
        integration: 'codex-test',
        scopes: ['guard:decision'],
        createdAt: new Date(Date.now() - 7200000).toISOString(),
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      },
      32,
    )
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const res = await handleGuard(
      post(
        {
          hook_event_name: 'PreToolUse',
          tool_name: 'Read',
          tool_input: { file_path: 'README.md' },
        },
        undefined,
        { Authorization: `Bearer ${minted.credential}` },
      ),
      env,
      config,
    )
    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('AuthError')
  })

  it('a benign would-be-ALLOW action with a bad credential under strict auth is denied (401), never an anonymous ALLOW', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    // A Read tool call against a benign file would produce a 200 ALLOW under anonymous or valid auth.
    // Under strict auth a garbage credential must produce 401, not 200.
    const res = await handleGuard(
      post(
        {
          hook_event_name: 'PreToolUse',
          tool_name: 'Read',
          tool_input: { file_path: 'README.md' },
        },
        undefined,
        { Authorization: 'Bearer gd_secureai_not_a_real_credential_garbage' },
      ),
      env,
      config,
    )
    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: string; decision?: string }
    expect(body.error).toBe('AuthError')
    expect(body.decision).toBeUndefined()
  })

  it('only a ticket with decision allow is honored; deny and ask tickets fall through to the pipeline', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'deny-ticket@example.com')
    const credential = await guardCredentialFor(db, user.id)
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }

    // The base payload. cwd is required by the ticket signer.
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }

    // bindGuardIdentity sets device_id = ctx.deviceId on the payload before
    // hashing. The guardCredentialFor helper mints deviceId as `dev_${userId}`,
    // so we must use the same value here so the action hash matches.
    const boundPayload = {
      ...payload,
      device_id: `dev_${user.id}`,
    } as Parameters<typeof signGuardDecisionTicket>[0]

    // The route builds its ticket context from config.guardTicketKeyId (default
    // 'guard-ticket-v1') and env.GUARD_TICKET_SECRET. Mirror that exactly so the
    // verifier finds a matching kid+secret pair.
    const ticketContext = {
      signer: { alg: 'HS256' as const, kid: config.guardTicketKeyId, secret: 'guard-ticket-secret' },
      verifiers: [{ alg: 'HS256' as const, kid: config.guardTicketKeyId, secret: 'guard-ticket-secret' }],
      policyVersion: config.guardPolicyVersion,
      trustRevision: config.guardTrustRevision,
      ttlSeconds: config.guardTicketTtlSeconds,
      now: new Date(),
    }

    // POSITIVE CONTROL: an allow ticket with a correct kid, secret, and device
    // binding must be honored. This proves every ticket field is valid so the
    // only variable in the negative cases below is the decision field.
    const allowTicket = await signGuardDecisionTicket(boundPayload, 'allow', ticketContext)
    expect(allowTicket).not.toBeNull()
    const allowRes = await handleGuard(
      post({ ...payload, decision_ticket: allowTicket }, undefined, {
        Authorization: `Bearer ${credential}`,
      }),
      env,
      config,
    )
    expect(allowRes.status).toBe(200)
    const allowDecision = (await allowRes.json()) as GuardDecision
    expect(allowDecision.reason).toBe('valid signed decision ticket')

    // NEGATIVE: deny and ask tickets share the same kid, secret, device binding,
    // and action hash as the allow ticket above. The only difference is the
    // decision field. Neither must be honored; the pipeline runs and produces the
    // real verdict for this benign Read action (allow).
    for (const badDecision of ['deny', 'ask'] as const) {
      const badTicket = await signGuardDecisionTicket(boundPayload, badDecision, ticketContext)
      expect(badTicket).not.toBeNull()
      const res = await handleGuard(
        post({ ...payload, decision_ticket: badTicket }, undefined, {
          Authorization: `Bearer ${credential}`,
        }),
        env,
        config,
      )
      expect(res.status).toBe(200)
      const decision = (await res.json()) as GuardDecision
      expect(decision.reason).not.toBe('valid signed decision ticket')
      // The pipeline ran and produced the real verdict, not a ticket fast-path.
      expect(decision.decision).toBe('allow')
    }
  })

  it('a cached decision is not reused after the feed version changes', async () => {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'feed-cache@example.com')
    const credential = await guardCredentialFor(db, user.id)
    const feedConfig = loadConfig({ SCANNER_FEED_ENABLED: 'true' })

    const cacheStore = new Map<string, string>()
    const kv = {
      get: async (key: string) => cacheStore.get(key) ?? null,
      put: async (key: string, value: string) => { cacheStore.set(key, value) },
    }
    const env = { DB: d1, KV: kv }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
    }

    // Seed feed at version A.
    await replaceFeed(db, 1000, '2026-06-30T00:00:00.000Z', [
      { kind: 'host', value: 'evil.com', source: 'urlhaus' },
    ])

    // First request: populates the cache at feed version 1000.
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${credential}` }),
      env as unknown as Env,
      feedConfig,
    )
    expect(first.status).toBe(200)
    const cacheSize = cacheStore.size
    expect(cacheSize).toBeGreaterThan(0)

    // Bump feed to version B.
    store.feedMetaVersion = 2000

    // Second request with the same payload: must NOT be served from the old cache entry.
    const second = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${credential}` }),
      env as unknown as Env,
      feedConfig,
    )
    expect(second.status).toBe(200)
    // A new cache entry must have been written (total keys increased).
    expect(cacheStore.size).toBeGreaterThan(cacheSize)
  })
})

describe('handleGuard, ticket-reject metric', () => {
  afterEach(() => {
    setMetricsDataset(null)
  })

  it('emits guard.ticket.reject with the reason when a presented ticket fails verification', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const db = d1Database(d1)
    const { user } = await createFreeUser(db, 'ticket-reject-metric@example.com')
    const credential = await guardCredentialFor(db, user.id)
    const env = { DB: d1, GUARD_TICKET_SECRET: 'guard-ticket-secret' }
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 'README.md' },
      cwd: '/workspace/project',
      integration_version: '1.0.0',
    }

    // Obtain a valid ticket first.
    const first = await handleGuard(
      post(payload, undefined, { Authorization: `Bearer ${credential}` }),
      env,
      config,
    )
    const firstDecision = (await first.json()) as GuardDecision
    expect(firstDecision.ticket).toBeDefined()

    // Tamper the ticket so it will fail verification (wrong action_hash).
    const badTicket = { ...firstDecision.ticket, action_hash: 'deadbeef' }

    const writeDataPoint = vi.fn()
    setMetricsDataset({ writeDataPoint })

    await handleGuard(
      post({ ...payload, decision_ticket: badTicket }, undefined, {
        Authorization: `Bearer ${credential}`,
      }),
      env,
      config,
    )

    // writeDataPoint must have been called with blobs starting with
    // 'guard.ticket.reject' followed by the rejection reason.
    const rejectCall = writeDataPoint.mock.calls.find(
      (call: unknown[]) => {
        const event = call[0] as { blobs?: string[] }
        return Array.isArray(event.blobs) && event.blobs[0] === 'guard.ticket.reject'
      },
    )
    expect(rejectCall).toBeDefined()
    const rejectEvent = (rejectCall as [{ blobs: string[] }])[0]
    const rejectBlobs = rejectEvent.blobs
    expect(rejectBlobs[0]).toBe('guard.ticket.reject')
    const rejectReason = rejectBlobs[1]
    expect(typeof rejectReason).toBe('string')
    expect((rejectReason ?? '').length).toBeGreaterThan(0)
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

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Env } from '../config/env'
import type { GuardDecision } from '../guard/claudeCode'
import { loadConfig } from '../config/env'
import { MemoryStore, MemoryD1 } from '../db/memory.test'
import { d1Database } from '../db/database'
import { createFreeUser, setUserTier } from '../db/accounts'
import { getUsage, incrementUsage } from '../db/usage'
import { handleGuard } from './guard'

const config = loadConfig({})

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
        tool_input: { file_path: '/tmp/notes.txt' },
      }),
      {},
      config,
    )
    expect(res.status).toBe(200)
    const decision = (await res.json()) as GuardDecision
    expect(decision.decision).toBe('allow')
    expect(decision.verdict).toBeNull()
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
})

describe('handleGuard — metering and caps', () => {
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

  it('meters an anonymous caller and returns 429 once the cap is reached', async () => {
    const { env, db } = fixture()
    for (let i = 0; i < config.capAnonymousPerDay; i += 1) {
      await incrementUsage(db, 'anon:198.51.100.5', today, { ai: false })
    }
    const res = await handleGuard(
      post(benign, undefined, { 'CF-Connecting-IP': '198.51.100.5' }),
      env,
      config,
    )
    expect(res.status).toBe(429)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('quota_exceeded')
  })

  it('gates AI off for a free caller and on for a pro caller', async () => {
    const { env, db } = fixture()
    const freeAi = new SpyAiRunner()
    const { apiKey: freeKey } = await createFreeUser(db, 'free-guard@example.com')
    const freeRes = await handleGuard(
      post(benign, undefined, { Authorization: `Bearer ${freeKey}` }),
      { ...env, AI: freeAi },
      config,
    )
    expect(freeRes.status).toBe(200)
    expect(freeAi.calls).toBe(0)

    const proAi = new SpyAiRunner()
    const { user, apiKey: proKey } = await createFreeUser(db, 'pro-guard@example.com')
    await setUserTier(db, user.id, 'pro')
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

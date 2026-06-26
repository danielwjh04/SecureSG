import { expect, it, vi } from 'vitest'
import type { DemoClient } from '../api/client'
import { DEMO_INTENT, DEMO_STEPS, runAttackDemo } from './runAttackDemo'

it('creates a session then runs the four canon steps in order', async () => {
  const createSession = vi.fn().mockResolvedValue({ session_id: 'sess-1' })
  const rpcCall = vi.fn().mockResolvedValue({ jsonrpc: '2.0', id: 1, result: 'ok' })
  const client: DemoClient = { createSession, rpcCall }

  const result = await runAttackDemo({ client, sleep: async () => {}, stepDelayMs: 0 })

  expect(createSession).toHaveBeenCalledWith(DEMO_INTENT)
  expect(rpcCall).toHaveBeenCalledTimes(4)
  expect(result.sessionId).toBe('sess-1')
  rpcCall.mock.calls.forEach((call, index) => {
    const [sessionId, toolCall, id] = call
    expect(sessionId).toBe('sess-1')
    expect(toolCall).toEqual(DEMO_STEPS[index])
    expect(id).toBe(index + 1)
  })
})

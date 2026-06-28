import { describe, expect, it } from 'vitest'
import { createCircuitBreaker, type BreakerStore } from './circuitBreaker'

/** In-memory KV fake exposing its store for assertions. */
function fakeStore(): BreakerStore & { map: Map<string, string> } {
  const map = new Map<string, string>()
  return {
    map,
    get: async (key) => map.get(key) ?? null,
    put: async (key, value) => {
      map.set(key, value)
    },
  }
}

const CONFIG = { enabled: true, failureThreshold: 3, cooldownSeconds: 30 }

/** A mutable clock (seconds) so cooldown transitions are deterministic. */
function clock(start = 1000): { now: () => number; advance: (s: number) => void } {
  let t = start
  return { now: () => t, advance: (s) => (t += s) }
}

const fail = async (): Promise<never> => {
  throw new Error('upstream down')
}
const ok = async (): Promise<string> => 'ok'

describe('createCircuitBreaker', () => {
  it('runs operations while closed and re-throws their errors', async () => {
    const breaker = createCircuitBreaker({
      store: fakeStore(),
      config: CONFIG,
      name: 'svc',
      onOpen: () => new Error('open'),
      now: clock().now,
    })
    await expect(breaker.run(ok)).resolves.toBe('ok')
    await expect(breaker.run(fail)).rejects.toThrow('upstream down')
  })

  it('trips OPEN after failureThreshold failures and then short-circuits without calling the op', async () => {
    const c = clock()
    const onOpen = (): Error => new Error('circuit open')
    const breaker = createCircuitBreaker({ store: fakeStore(), config: CONFIG, name: 'svc', onOpen, now: c.now })

    // 3 failures trip it.
    for (let i = 0; i < 3; i += 1) {
      await expect(breaker.run(fail)).rejects.toThrow('upstream down')
    }
    // Now open: the next call must NOT invoke the operation, and throws onOpen().
    let invoked = false
    await expect(
      breaker.run(async () => {
        invoked = true
        return 'should not run'
      }),
    ).rejects.toThrow('circuit open')
    expect(invoked).toBe(false)
  })

  it('moves OPEN → half-open after cooldown and CLOSES on a successful probe', async () => {
    const c = clock()
    const breaker = createCircuitBreaker({
      store: fakeStore(),
      config: CONFIG,
      name: 'svc',
      onOpen: () => new Error('open'),
      now: c.now,
    })
    for (let i = 0; i < 3; i += 1) {
      await expect(breaker.run(fail)).rejects.toThrow()
    }
    c.advance(CONFIG.cooldownSeconds) // cooldown elapsed → probe allowed
    await expect(breaker.run(ok)).resolves.toBe('ok')
    // Closed again: a subsequent failure does not immediately short-circuit.
    await expect(breaker.run(fail)).rejects.toThrow('upstream down')
  })

  it('re-OPENS when the half-open probe fails', async () => {
    const c = clock()
    const breaker = createCircuitBreaker({
      store: fakeStore(),
      config: CONFIG,
      name: 'svc',
      onOpen: () => new Error('open'),
      now: c.now,
    })
    for (let i = 0; i < 3; i += 1) {
      await expect(breaker.run(fail)).rejects.toThrow()
    }
    c.advance(CONFIG.cooldownSeconds)
    // The probe fails → re-open; the very next call short-circuits again.
    await expect(breaker.run(fail)).rejects.toThrow('upstream down')
    let invoked = false
    await expect(
      breaker.run(async () => {
        invoked = true
      }),
    ).rejects.toThrow('open')
    expect(invoked).toBe(false)
  })

  it('is a pass-through when the store is null (always runs the op)', async () => {
    const breaker = createCircuitBreaker({
      store: null,
      config: CONFIG,
      name: 'svc',
      onOpen: () => new Error('open'),
      now: clock().now,
    })
    // Even after many failures, with no store there is no state to trip.
    for (let i = 0; i < 5; i += 1) {
      await expect(breaker.run(fail)).rejects.toThrow('upstream down')
    }
    let invoked = false
    await breaker.run(async () => {
      invoked = true
    })
    expect(invoked).toBe(true)
  })

  it('is a pass-through when disabled', async () => {
    const store = fakeStore()
    const breaker = createCircuitBreaker({
      store,
      config: { ...CONFIG, enabled: false },
      name: 'svc',
      onOpen: () => new Error('open'),
      now: clock().now,
    })
    for (let i = 0; i < 5; i += 1) {
      await expect(breaker.run(fail)).rejects.toThrow('upstream down')
    }
    // Disabled → never wrote any state.
    expect(store.map.size).toBe(0)
  })

  it('treats a corrupt stored record as closed (allows traffic)', async () => {
    const store = fakeStore()
    store.map.set('cb:v1:svc', 'not json{')
    const breaker = createCircuitBreaker({
      store,
      config: CONFIG,
      name: 'svc',
      onOpen: () => new Error('open'),
      now: clock().now,
    })
    // A corrupt record must not wedge the circuit — the op runs.
    await expect(breaker.run(ok)).resolves.toBe('ok')
  })
})

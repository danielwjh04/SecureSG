import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { DashboardEvent } from '../api/types'
import {
  FakeWebSocket,
  installFakeWebSocket,
  resetFakeWebSocket,
} from '../test/fakeWebSocket'
import { dashboardReducer, initialLiveState, useDashboardLive } from './useDashboardLive'

function event(
  partial: Partial<DashboardEvent> & { kind: DashboardEvent['kind'] },
): DashboardEvent {
  return {
    created_at: '2026-06-26T00:00:00+00:00',
    session_id: 's',
    tool_name: null,
    verdict: null,
    rule_id: null,
    category: null,
    content: null,
    reason: null,
    model_state: null,
    transaction_id: null,
    ...partial,
  }
}

describe('dashboardReducer', () => {
  it('toggles connected on open and close', () => {
    const opened = dashboardReducer(initialLiveState, { type: 'open' })
    expect(opened.connected).toBe(true)
    expect(dashboardReducer(opened, { type: 'close' }).connected).toBe(false)
  })

  it('bumps eventSeq on a VERDICT event', () => {
    const next = dashboardReducer(initialLiveState, {
      type: 'event',
      event: event({ kind: 'VERDICT', verdict: 'BLOCK' }),
    })
    expect(next.eventSeq).toBe(1)
  })

  it('bumps eventSeq and captures content on a CONTENT event', () => {
    const next = dashboardReducer(initialLiveState, {
      type: 'event',
      event: event({ kind: 'CONTENT', content: 'hello', verdict: 'ALLOW' }),
    })
    expect(next.eventSeq).toBe(1)
    expect(next.latestContent?.text).toBe('hello')
  })

  it('sets modelState without bumping eventSeq on a MODEL_STATE event', () => {
    const next = dashboardReducer(initialLiveState, {
      type: 'event',
      event: event({ kind: 'MODEL_STATE', model_state: 'screening' }),
    })
    expect(next.modelState).toBe('screening')
    expect(next.eventSeq).toBe(0)
  })
})

describe('useDashboardLive', () => {
  beforeEach(() => {
    installFakeWebSocket()
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
    resetFakeWebSocket()
  })

  it('connects, and reconnects after the socket closes', () => {
    const { unmount } = renderHook(() => useDashboardLive())
    expect(FakeWebSocket.instances).toHaveLength(1)
    act(() => FakeWebSocket.instances[0].emitOpen())
    act(() => FakeWebSocket.instances[0].emitClose())
    act(() => vi.advanceTimersByTime(2000))
    expect(FakeWebSocket.instances.length).toBeGreaterThanOrEqual(2)
    unmount()
  })
})

import { render, screen, fireEvent } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Settings } from './Settings'
import type { AuthState } from '../hooks/useAuth'
import type { AccountTier, MeResponse } from '../api/types'
import * as client from '../api/client'

function user(tier: AccountTier): MeResponse {
  return {
    email: 'ada@securesg.test',
    tier,
    createdAt: '2026-06-01T00:00:00.000Z',
    apiKeyPrefix: 'sk_live_ab',
    firstName: 'Ada',
    lastName: 'Lovelace',
    role: 'member',
    isAdmin: false,
    isOwner: false,
  }
}

function authState(): AuthState {
  return { status: 'authenticated', user: user('free'), isAdmin: false, isOwner: false, refresh: vi.fn() }
}

/**
 * Capture `window.location.assign` calls. jsdom's `location.assign` is a
 * non-configurable navigation method (and not spyable), so swap in a minimal
 * location stub whose `assign` records the target. Restored in `afterEach`.
 */
function stubAssign(): { calls: string[] } {
  const calls: string[] = []
  const original = window.location
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...original, assign: (url: string | URL) => calls.push(String(url)) },
  })
  restoreLocation = () =>
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: original,
    })
  return { calls }
}

let restoreLocation: (() => void) | null = null

afterEach(() => {
  restoreLocation?.()
  restoreLocation = null
  vi.restoreAllMocks()
})

describe('Settings billing', () => {
  it('routes Manage plan to the dynamic pricing page for a paid account', () => {
    const { calls } = stubAssign()
    const portal = vi.spyOn(client, 'openPortal')

    render(<Settings user={user('pro')} auth={authState()} />)

    fireEvent.click(screen.getByRole('button', { name: /Manage plan/ }))

    // Manage plan now leads to #pricing (which adapts to the tier), not straight
    // to Stripe: no portal/checkout call is made from Settings.
    expect(calls).toContain('#pricing')
    expect(portal).not.toHaveBeenCalled()
  })

  it('routes Manage plan to the pricing page for a free account too', () => {
    const { calls } = stubAssign()
    const checkout = vi.spyOn(client, 'startCheckout')

    render(<Settings user={user('free')} auth={authState()} />)

    // The button is always "Manage plan" now (the pricing page adapts per tier).
    fireEvent.click(screen.getByRole('button', { name: /Manage plan/ }))

    expect(calls).toContain('#pricing')
    expect(checkout).not.toHaveBeenCalled()
  })
})

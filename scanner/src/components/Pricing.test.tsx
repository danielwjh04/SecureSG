import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Pricing } from './Pricing'
import type { AuthState } from '../hooks/useAuth'
import * as client from '../api/client'

function authState(overrides: Partial<AuthState> = {}): AuthState {
  return {
    status: 'anonymous',
    user: null,
    isAdmin: false,
    isOwner: false,
    refresh: vi.fn(),
    ...overrides,
  }
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

describe('Pricing', () => {
  it('renders the three plans with prices and a recommended Pro badge', () => {
    render(<Pricing auth={authState()} />)

    expect(screen.getByText('Free')).toBeInTheDocument()
    expect(screen.getByText('Pro')).toBeInTheDocument()
    expect(screen.getByText('Enterprise')).toBeInTheDocument()

    expect(screen.getByText('S$0')).toBeInTheDocument()
    expect(screen.getByText('S$9.90')).toBeInTheDocument()
    expect(screen.getByText('Recommended')).toBeInTheDocument()
  })

  it('sends an anonymous visitor to register when they click Subscribe', () => {
    const { calls } = stubAssign()
    const checkout = vi.spyOn(client, 'startCheckout')
    render(<Pricing auth={authState({ status: 'anonymous' })} />)

    fireEvent.click(screen.getByRole('button', { name: /Subscribe/ }))

    expect(calls).toContain('#register')
    expect(checkout).not.toHaveBeenCalled()
  })

  it('opens the contact form when the Enterprise CTA is clicked', () => {
    render(<Pricing auth={authState()} />)

    expect(screen.queryByRole('dialog', { name: 'Contact sales' })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Contact sales/ }))

    expect(screen.getByRole('dialog', { name: 'Contact sales' })).toBeInTheDocument()
  })

  it('starts Stripe checkout for a signed-in visitor and redirects to the URL', async () => {
    const { calls } = stubAssign()
    vi.spyOn(client, 'startCheckout').mockResolvedValue({
      url: 'https://checkout.stripe.test/session',
    })
    render(
      <Pricing
        auth={authState({
          status: 'authenticated',
          user: {
            email: 'a@b.com',
            tier: 'free',
            createdAt: '2026-06-01T00:00:00.000Z',
            apiKeyPrefix: 'sk_live_ab',
            role: 'member',
            isAdmin: false,
            isOwner: false,
          },
        })}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: /Subscribe/ }))

    await waitFor(() =>
      expect(calls).toContain('https://checkout.stripe.test/session'),
    )
  })
})

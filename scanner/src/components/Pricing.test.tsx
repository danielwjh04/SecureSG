import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Pricing } from './Pricing'
import type { AuthState } from '../hooks/useAuth'
import type { AccountTier, MeResponse, SubscriptionStatus } from '../api/types'
import * as client from '../api/client'

function authState(overrides: Partial<AuthState> = {}): AuthState {
  return {
    status: 'anonymous',
    user: null,
    isAdmin: false,
    isOwner: false,
    refresh: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  }
}

const NO_SUB: SubscriptionStatus = {
  hasSubscription: false,
  cancelAtPeriodEnd: false,
  currentPeriodEnd: null,
}

/** A signed-in account on `tier` for the dynamic-CTA cases. */
function meUser(tier: AccountTier): MeResponse {
  return {
    email: 'a@b.com',
    tier,
    createdAt: '2026-06-01T00:00:00.000Z',
    apiKeyPrefix: 'sk_live_ab',
    firstName: null,
    lastName: null,
    role: 'member',
    isAdmin: false,
    isOwner: false,
  }
}

/** An authenticated {@link AuthState} on the given tier. */
function authAs(tier: AccountTier): AuthState {
  return authState({ status: 'authenticated', user: meUser(tier) })
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
  it('renders the consumer plans with prices and a recommended Personal badge', () => {
    render(<Pricing auth={authState()} />)

    expect(screen.getByText('Free')).toBeInTheDocument()
    expect(screen.getByText('Personal')).toBeInTheDocument()
    expect(screen.getByText('Pro')).toBeInTheDocument()
    expect(screen.getByText('Enterprise')).toBeInTheDocument()

    expect(screen.getByText('S$0')).toBeInTheDocument()
    expect(screen.getByText('S$4.90')).toBeInTheDocument()
    expect(screen.getByText('S$9.90')).toBeInTheDocument()
    expect(screen.getByText('Recommended')).toBeInTheDocument()
    // Enterprise is a contact-sales plan, not a self-serve checkout.
    expect(screen.getByRole('button', { name: /Contact us/ })).toBeInTheDocument()
  })

  it('sends an anonymous visitor to register when they click a paid plan', () => {
    const { calls } = stubAssign()
    const checkout = vi.spyOn(client, 'startCheckout')
    render(<Pricing auth={authState({ status: 'anonymous' })} />)

    fireEvent.click(screen.getByRole('button', { name: /Start Personal/ }))

    expect(calls).toContain('#register')
    expect(checkout).not.toHaveBeenCalled()
  })

  it('starts Stripe checkout for a signed-in visitor and redirects to the URL', async () => {
    vi.spyOn(client, 'fetchSubscriptionStatus').mockResolvedValue(NO_SUB)
    const { calls } = stubAssign()
    const checkout = vi.spyOn(client, 'startCheckout').mockResolvedValue({
      url: 'https://checkout.stripe.test/session',
    })
    render(<Pricing auth={authAs('free')} />)

    fireEvent.click(screen.getByRole('button', { name: /Start Personal/ }))

    await waitFor(() => expect(checkout).toHaveBeenCalledWith('personal'))
    await waitFor(() =>
      expect(calls).toContain('https://checkout.stripe.test/session'),
    )
  })
})

describe('Pricing · dynamic (signed-in)', () => {
  it('marks the current plan and offers downgrade + cancel for a Pro account', async () => {
    vi.spyOn(client, 'fetchSubscriptionStatus').mockResolvedValue(NO_SUB)
    render(<Pricing auth={authAs('pro')} />)

    // Pro is the current plan (a disabled pill); Personal offers a downgrade and
    // Free offers to cancel.
    await waitFor(() => expect(screen.getByText('Current plan')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /Downgrade to Personal/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Cancel plan/ })).toBeInTheDocument()
    // Free → paid checkout button is NOT shown for a paid account.
    expect(screen.queryByRole('button', { name: /Start Personal/ })).toBeNull()
  })

  it('changes plan in place (no redirect) when a downgrade is clicked', async () => {
    vi.spyOn(client, 'fetchSubscriptionStatus').mockResolvedValue(NO_SUB)
    const change = vi.spyOn(client, 'changePlan').mockResolvedValue({ tier: 'personal' })
    const auth = authAs('pro')
    render(<Pricing auth={auth} />)

    fireEvent.click(await screen.findByRole('button', { name: /Downgrade to Personal/ }))

    await waitFor(() => expect(change).toHaveBeenCalledWith('personal'))
    // The account tier is refreshed so the cards re-resolve.
    expect(auth.refresh).toHaveBeenCalled()
  })

  it('cancels the plan in place when Cancel is clicked', async () => {
    vi.spyOn(client, 'fetchSubscriptionStatus').mockResolvedValue(NO_SUB)
    const cancel = vi.spyOn(client, 'cancelPlan').mockResolvedValue({
      hasSubscription: true,
      cancelAtPeriodEnd: true,
      currentPeriodEnd: '2026-09-01T00:00:00.000Z',
    })
    render(<Pricing auth={authAs('pro')} />)

    fireEvent.click(await screen.findByRole('button', { name: /Cancel plan/ }))
    await waitFor(() => expect(cancel).toHaveBeenCalled())
  })

  it('surfaces a scheduled cancellation from the subscription snapshot', async () => {
    vi.spyOn(client, 'fetchSubscriptionStatus').mockResolvedValue({
      hasSubscription: true,
      cancelAtPeriodEnd: true,
      currentPeriodEnd: '2026-09-01T00:00:00.000Z',
    })
    render(<Pricing auth={authAs('personal')} />)

    // The current (Personal) plan shows "Cancels <date>"; Free shows "Active until".
    await waitFor(() => expect(screen.getByText(/Cancels /)).toBeInTheDocument())
    expect(screen.getByText(/Active until /)).toBeInTheDocument()
  })
})

/** Open the Enterprise contact modal and fill the three fields. */
function openAndFillContactForm(): void {
  fireEvent.click(screen.getByRole('button', { name: /Contact us/ }))
  fireEvent.change(screen.getByPlaceholderText('Ada Lovelace'), {
    target: { value: 'Ada Lovelace' },
  })
  fireEvent.change(screen.getByPlaceholderText('ada@yourcompany.com'), {
    target: { value: 'ada@corp.test' },
  })
  fireEvent.change(screen.getByPlaceholderText(/How many agents/), {
    target: { value: 'We run 50 agents and need central control.' },
  })
}

describe('Pricing · Enterprise contact modal', () => {
  it('sends a sales inquiry and confirms', async () => {
    const send = vi.spyOn(client, 'submitContact').mockResolvedValue({ ok: true })
    render(<Pricing auth={authState()} />)

    openAndFillContactForm()
    fireEvent.click(screen.getByRole('button', { name: /Send message/ }))

    await waitFor(() => expect(screen.getByText('Message sent')).toBeInTheDocument())
    expect(send).toHaveBeenCalledWith({
      name: 'Ada Lovelace',
      email: 'ada@corp.test',
      message: 'We run 50 agents and need central control.',
    })
  })

  it('rejects an empty submission inline, before any request', () => {
    const send = vi.spyOn(client, 'submitContact').mockResolvedValue({ ok: true })
    render(<Pricing auth={authState()} />)

    fireEvent.click(screen.getByRole('button', { name: /Contact us/ }))
    fireEvent.click(screen.getByRole('button', { name: /Send message/ }))

    expect(screen.getByText(/Please fill in every field/)).toBeInTheDocument()
    expect(send).not.toHaveBeenCalled()
  })

  it('maps a rate-limit (429) to an inline message', async () => {
    vi.spyOn(client, 'submitContact').mockRejectedValue(new client.ApiError(429, 'rate limited'))
    render(<Pricing auth={authState()} />)

    openAndFillContactForm()
    fireEvent.click(screen.getByRole('button', { name: /Send message/ }))

    await waitFor(() =>
      expect(screen.getByText(/Too many messages just now/)).toBeInTheDocument(),
    )
  })
})

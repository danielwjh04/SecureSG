import { describe, expect, it } from 'vitest'
import type Stripe from 'stripe'
import { buildStripe, StripeBillingGateway } from './stripe'
import { BillingError } from '../errors'

/**
 * A minimal fake of the Stripe client surface the gateway touches. Each
 * sub-resource returns a scripted value or throws, so the gateway's narrowing
 * and fail-closed branches run without any network.
 */
function fakeStripe(overrides: {
  customer?: () => Promise<{ id: string }>
  checkout?: () => Promise<{ url: string | null }>
  portal?: () => Promise<{ url: string }>
}): Stripe {
  return {
    customers: {
      create: overrides.customer ?? (async () => ({ id: 'cus_default' })),
    },
    checkout: {
      sessions: {
        create: overrides.checkout ?? (async () => ({ url: 'https://checkout' })),
      },
    },
    billingPortal: {
      sessions: {
        create: overrides.portal ?? (async () => ({ url: 'https://portal' })),
      },
    },
  } as unknown as Stripe
}

describe('buildStripe', () => {
  it('constructs a Stripe client without throwing', () => {
    const stripe = buildStripe('sk_test_dummy')
    expect(stripe).toBeDefined()
    // The fetch HTTP client is wired (Workers correctness); webhooks surface is present.
    expect(typeof stripe.webhooks.constructEventAsync).toBe('function')
  })
})

describe('StripeBillingGateway.constructEvent', () => {
  it('fails closed (BillingError) on an unverifiable signature', async () => {
    const gateway = new StripeBillingGateway(buildStripe('sk_test_dummy'), 'whsec_dummy')
    // A body+signature that cannot verify against the secret must NOT be trusted.
    await expect(
      gateway.constructEvent('{"id":"evt_1"}', 't=1,v1=deadbeef'),
    ).rejects.toBeInstanceOf(BillingError)
  })
})

describe('StripeBillingGateway operations', () => {
  it('ensureCustomer returns the created customer id', async () => {
    const gw = new StripeBillingGateway(
      fakeStripe({ customer: async () => ({ id: 'cus_made' }) }),
      'whsec',
    )
    expect(await gw.ensureCustomer('u1', 'a@b.com')).toBe('cus_made')
    // Email may be null (no email on file).
    expect(await gw.ensureCustomer('u2', null)).toBe('cus_made')
  })

  it('createCheckoutSession returns the hosted url', async () => {
    const gw = new StripeBillingGateway(
      fakeStripe({ checkout: async () => ({ url: 'https://pay' }) }),
      'whsec',
    )
    const url = await gw.createCheckoutSession({
      customerId: 'cus_1',
      priceId: 'price_pro',
      successUrl: 's',
      cancelUrl: 'c',
    })
    expect(url).toBe('https://pay')
  })

  it('createCheckoutSession fails closed when Stripe returns no url', async () => {
    const gw = new StripeBillingGateway(
      fakeStripe({ checkout: async () => ({ url: null }) }),
      'whsec',
    )
    await expect(
      gw.createCheckoutSession({ customerId: 'c', priceId: 'p', successUrl: 's', cancelUrl: 'x' }),
    ).rejects.toBeInstanceOf(BillingError)
  })

  it('createPortalSession returns the hosted url', async () => {
    const gw = new StripeBillingGateway(
      fakeStripe({ portal: async () => ({ url: 'https://manage' }) }),
      'whsec',
    )
    expect(await gw.createPortalSession({ customerId: 'cus_1', returnUrl: 'r' })).toBe(
      'https://manage',
    )
  })

  it('wraps a Stripe API failure as a BillingError (ensureCustomer)', async () => {
    const gw = new StripeBillingGateway(
      fakeStripe({
        customer: async () => {
          throw new Error('stripe down')
        },
      }),
      'whsec',
    )
    await expect(gw.ensureCustomer('u1', 'a@b.com')).rejects.toBeInstanceOf(BillingError)
  })

  it('wraps a Stripe API failure as a BillingError (createCheckoutSession)', async () => {
    const gw = new StripeBillingGateway(
      fakeStripe({
        checkout: async () => {
          throw new Error('stripe down')
        },
      }),
      'whsec',
    )
    await expect(
      gw.createCheckoutSession({ customerId: 'c', priceId: 'p', successUrl: 's', cancelUrl: 'x' }),
    ).rejects.toBeInstanceOf(BillingError)
  })

  it('wraps a Stripe API failure as a BillingError (createPortalSession)', async () => {
    const gw = new StripeBillingGateway(
      fakeStripe({
        portal: async () => {
          throw new Error('stripe down')
        },
      }),
      'whsec',
    )
    await expect(
      gw.createPortalSession({ customerId: 'c', returnUrl: 'r' }),
    ).rejects.toBeInstanceOf(BillingError)
  })
})

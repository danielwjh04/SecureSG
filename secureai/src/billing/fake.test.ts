/**
 * In-memory fakes for the billing seam: a {@link FakeBillingGateway} that records
 * calls and returns canned URLs/events, plus a {@link stripeEvent} factory. They
 * let the route suites exercise the real handler code path with no Stripe SDK or
 * network, and assert exactly which gateway methods were invoked.
 *
 * Defined in a `.test.ts` file so they are excluded from the coverage surface yet
 * importable by the route suites (mirrors `db/memory.test.ts`).
 */

import { describe, expect, it } from 'vitest'
import type Stripe from 'stripe'
import type {
  ActiveSubscription,
  BillingGateway,
  CheckoutSessionParams,
  PortalSessionParams,
  SubscriptionChangeParams,
} from './stripe'
import { BillingError } from '../errors'

/** A scriptable {@link BillingGateway} double for route tests. */
export class FakeBillingGateway implements BillingGateway {
  /** Canned customer id returned by {@link ensureCustomer}. */
  public ensuredCustomerId = 'cus_fake'
  /** Canned checkout URL. */
  public checkoutUrl = 'https://checkout.stripe.test/session'
  /** Canned portal URL. */
  public portalUrl = 'https://billing.stripe.test/portal'
  /** When set, {@link constructEvent} returns this; else it rejects (bad sig). */
  public event: Stripe.Event | null = null
  /** When true, the session-creating methods throw a {@link BillingError}. */
  public failSessions = false

  /** Canned active subscription returned by {@link getActiveSubscription}. */
  public activeSubscription: ActiveSubscription | null = null

  /** Call log for assertions. */
  public readonly calls: string[] = []
  public lastCheckout: CheckoutSessionParams | null = null
  public lastPortal: PortalSessionParams | null = null
  public lastEnsure: { userId: string; email: string | null } | null = null
  public lastChange: SubscriptionChangeParams | null = null
  public lastCancelId: string | null = null

  public async ensureCustomer(userId: string, email: string | null): Promise<string> {
    this.calls.push('ensureCustomer')
    this.lastEnsure = { userId, email }
    return this.ensuredCustomerId
  }

  public async createCheckoutSession(params: CheckoutSessionParams): Promise<string> {
    this.calls.push('createCheckoutSession')
    this.lastCheckout = params
    if (this.failSessions) {
      throw new BillingError('fake: checkout failed')
    }
    return this.checkoutUrl
  }

  public async createPortalSession(params: PortalSessionParams): Promise<string> {
    this.calls.push('createPortalSession')
    this.lastPortal = params
    if (this.failSessions) {
      throw new BillingError('fake: portal failed')
    }
    return this.portalUrl
  }

  public async getActiveSubscription(_customerId: string): Promise<ActiveSubscription | null> {
    this.calls.push('getActiveSubscription')
    if (this.failSessions) {
      throw new BillingError('fake: getActiveSubscription failed')
    }
    return this.activeSubscription
  }

  public async changeSubscriptionPrice(params: SubscriptionChangeParams): Promise<void> {
    this.calls.push('changeSubscriptionPrice')
    this.lastChange = params
    if (this.failSessions) {
      throw new BillingError('fake: change failed')
    }
  }

  public async cancelSubscription(subscriptionId: string): Promise<ActiveSubscription> {
    this.calls.push('cancelSubscription')
    this.lastCancelId = subscriptionId
    if (this.failSessions) {
      throw new BillingError('fake: cancel failed')
    }
    const base: ActiveSubscription = this.activeSubscription ?? {
      subscriptionId,
      itemId: 'si_fake',
      priceId: 'price_fake',
      cancelAtPeriodEnd: false,
      currentPeriodEnd: null,
    }
    return { ...base, subscriptionId, cancelAtPeriodEnd: true }
  }

  public async constructEvent(_rawBody: string, _signature: string): Promise<Stripe.Event> {
    this.calls.push('constructEvent')
    if (this.event === null) {
      throw new BillingError('fake: invalid signature')
    }
    return this.event
  }
}

/**
 * Build a minimal {@link Stripe.Event} for a given type and data object. Only the
 * fields the webhook handler reads are populated; the structural cast keeps the
 * fixture small without dragging in the full Stripe event shape.
 */
export function stripeEvent(
  id: string,
  type: string,
  object: Record<string, unknown>,
): Stripe.Event {
  return { id, type, data: { object } } as unknown as Stripe.Event
}

/** Build a Subscription-shaped event object with one line item. */
export function subscriptionObject(
  customer: string,
  status: string,
  priceId: string,
  periodEndSeconds: number | null,
): Record<string, unknown> {
  return {
    customer,
    status,
    items: {
      data: [
        {
          price: { id: priceId },
          current_period_end: periodEndSeconds,
        },
      ],
    },
  }
}

describe('FakeBillingGateway', () => {
  it('returns canned URLs and logs the calls', async () => {
    const gw = new FakeBillingGateway()
    expect(await gw.ensureCustomer('u1', 'a@b.com')).toBe('cus_fake')
    expect(
      await gw.createCheckoutSession({
        customerId: 'cus_fake',
        priceId: 'price_pro',
        tier: 'pro',
        successUrl: 's',
        cancelUrl: 'c',
      }),
    ).toBe('https://checkout.stripe.test/session')
    expect(gw.calls).toEqual(['ensureCustomer', 'createCheckoutSession'])
  })

  it('constructEvent rejects when no event is scripted (bad signature)', async () => {
    const gw = new FakeBillingGateway()
    await expect(gw.constructEvent('{}', 'sig')).rejects.toBeInstanceOf(BillingError)
  })
})

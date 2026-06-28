/**
 * Stripe billing gateway: the thin seam every billing route depends on.
 *
 * Routes never import the `stripe` SDK directly. They depend on the narrow
 * {@link BillingGateway} interface, which the real {@link StripeBillingGateway}
 * implements over a Workers-correct Stripe client and which tests implement with
 * an in-memory double. This keeps the suite SDK-free and the routes mockable.
 *
 * Workers correctness (CLAUDE.md §6 model-inference discipline applied to the
 * payment provider):
 *   - The client is built ONCE per request lifecycle via {@link buildStripe},
 *     using `Stripe.createFetchHttpClient()` (Workers has no Node `http`).
 *   - Webhook verification is the async, SubtleCrypto-backed path
 *     (`constructEventAsync` + `createSubtleCryptoProvider()`); the synchronous
 *     `constructEvent` uses Node crypto and throws on Workers.
 *
 * PII/log discipline: this module logs only the Stripe error CLASS on failure,
 * never request bodies, customer emails, or secrets.
 */

import Stripe from 'stripe'
import type { ScannerConfig } from '../config/env'
import { BillingError } from '../errors'
import type { CircuitBreaker } from '../resilience/circuitBreaker'

/** Inputs for a subscription Checkout Session. */
export interface CheckoutSessionParams {
  /** The Stripe customer the subscription is billed to. */
  readonly customerId: string
  /** The recurring Price id to subscribe to (the Pro $12/mo price). */
  readonly priceId: string
  /** Where Stripe returns the buyer on success. */
  readonly successUrl: string
  /** Where Stripe returns the buyer on cancel. */
  readonly cancelUrl: string
}

/** Inputs for a Billing Portal Session. */
export interface PortalSessionParams {
  /** The Stripe customer whose subscription the portal manages. */
  readonly customerId: string
  /** Where Stripe returns the buyer when they leave the portal. */
  readonly returnUrl: string
}

/**
 * The narrow billing surface routes and tests depend on. Each method maps to a
 * single Stripe operation; the methods that return a redirect URL fail closed
 * (raise {@link BillingError}) when Stripe omits the URL.
 */
export interface BillingGateway {
  /**
   * Create or fetch a Stripe customer for an account, returning its id. Idempotent
   * per account: callers pass the user id so a replay reuses the same logical
   * customer rather than minting duplicates.
   */
  ensureCustomer(userId: string, email: string | null): Promise<string>

  /** Create a subscription Checkout Session; returns the hosted checkout URL. */
  createCheckoutSession(params: CheckoutSessionParams): Promise<string>

  /** Create a Billing Portal Session; returns the hosted portal URL. */
  createPortalSession(params: PortalSessionParams): Promise<string>

  /**
   * Verify a webhook signature and return the typed event. A failed verification
   * raises {@link BillingError}; the route maps that to a fail-closed 400 and
   * never trusts the unverified body.
   */
  constructEvent(rawBody: string, signature: string): Promise<Stripe.Event>
}

/**
 * Pin the Stripe API version so behavior is reproducible. This must match the
 * version the installed SDK's types are generated against (the `ApiVersion`
 * literal in `stripe@22`); a mismatch is a compile error, which keeps the pin
 * honest across SDK bumps.
 */
const STRIPE_API_VERSION = '2026-06-24.dahlia' as const

/**
 * The Stripe client options derived from config — extracted as a pure function so
 * the timeout / retry plumbing is unit-testable without constructing a live SDK.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function stripeClientOptions(
  config: ScannerConfig,
): NonNullable<ConstructorParameters<typeof Stripe>[1]> {
  return {
    apiVersion: STRIPE_API_VERSION,
    httpClient: Stripe.createFetchHttpClient(),
    // Bound each call so a hung Stripe request cannot stall a Worker; retries are
    // kept low because worst-case wall time ≈ timeout × (retries + 1).
    timeout: config.stripeTimeoutMs,
    maxNetworkRetries: config.stripeMaxNetworkRetries,
  }
}

/**
 * Build a Workers-correct Stripe client.
 *
 * Uses the fetch-based HTTP client (Workers has no Node `http`), a pinned API
 * version, and the config-driven timeout + retry count. Construct this once per
 * request lifecycle, not per call.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @param secret - The `STRIPE_SECRET_KEY`.
 * @param config - The validated config (supplies timeout + retry count).
 * @returns A configured {@link Stripe} client.
 */
export function buildStripe(secret: string, config: ScannerConfig): Stripe {
  return new Stripe(secret, stripeClientOptions(config))
}

/**
 * The production {@link BillingGateway}, backed by a real Stripe client built by
 * {@link buildStripe}. Every method narrows the Stripe SDK to the single
 * operation the route needs and translates a provider fault into a typed
 * {@link BillingError} so routes map it deterministically (→ 502).
 */
export class StripeBillingGateway implements BillingGateway {
  private readonly stripe: Stripe
  private readonly webhookSecret: string
  private readonly breaker: CircuitBreaker

  /**
   * @param stripe - A client from {@link buildStripe}.
   * @param webhookSecret - The `STRIPE_WEBHOOK_SECRET` used to verify events.
   * @param breaker - Circuit breaker guarding the Stripe network calls. The local
   *   webhook signature check ({@link constructEvent}) is NOT wrapped — it makes no
   *   network call.
   */
  public constructor(stripe: Stripe, webhookSecret: string, breaker: CircuitBreaker) {
    this.stripe = stripe
    this.webhookSecret = webhookSecret
    this.breaker = breaker
  }

  /**
   * Create a Stripe customer for an account. The user id is stamped into
   * metadata so the customer is traceable back to the account, and is also used
   * as the idempotency key so a retried checkout does not mint a duplicate
   * customer.
   *
   * Time complexity: O(1) — one Stripe API round-trip. Space complexity: O(1).
   *
   * @throws {BillingError} On any Stripe API failure.
   */
  public async ensureCustomer(userId: string, email: string | null): Promise<string> {
    return this.breaker.run(async () => {
      try {
        const customer = await this.stripe.customers.create(
          {
            email: email ?? undefined,
            metadata: { user_id: userId },
          },
          { idempotencyKey: `customer:${userId}` },
        )
        return customer.id
      } catch (error: unknown) {
        throw billingFault('ensureCustomer', error)
      }
    })
  }

  /**
   * Create a subscription-mode Checkout Session for a single recurring price.
   *
   * Time complexity: O(1) — one Stripe API round-trip. Space complexity: O(1).
   *
   * @throws {BillingError} On a Stripe failure, or if Stripe returns no URL.
   */
  public async createCheckoutSession(params: CheckoutSessionParams): Promise<string> {
    return this.breaker.run(async () => {
      let session: Stripe.Checkout.Session
      try {
        session = await this.stripe.checkout.sessions.create({
          mode: 'subscription',
          customer: params.customerId,
          line_items: [{ price: params.priceId, quantity: 1 }],
          success_url: params.successUrl,
          cancel_url: params.cancelUrl,
        })
      } catch (error: unknown) {
        throw billingFault('createCheckoutSession', error)
      }
      if (session.url === null) {
        throw new BillingError('Stripe returned a checkout session without a URL')
      }
      return session.url
    })
  }

  /**
   * Create a Billing Portal Session so the customer can manage their subscription.
   *
   * Time complexity: O(1) — one Stripe API round-trip. Space complexity: O(1).
   *
   * @throws {BillingError} On a Stripe failure.
   */
  public async createPortalSession(params: PortalSessionParams): Promise<string> {
    return this.breaker.run(async () => {
      try {
        const session = await this.stripe.billingPortal.sessions.create({
          customer: params.customerId,
          return_url: params.returnUrl,
        })
        return session.url
      } catch (error: unknown) {
        throw billingFault('createPortalSession', error)
      }
    })
  }

  /**
   * Verify a webhook signature and decode the event, using the async,
   * SubtleCrypto-backed verifier (the only one that works on Workers).
   *
   * Time complexity: O(n) in the raw body length (HMAC). Space complexity: O(n).
   *
   * @throws {BillingError} On a signature/parse failure — the route maps this to
   *   a fail-closed 400 and never reads the unverified body.
   */
  public async constructEvent(rawBody: string, signature: string): Promise<Stripe.Event> {
    try {
      return await this.stripe.webhooks.constructEventAsync(
        rawBody,
        signature,
        this.webhookSecret,
        undefined,
        Stripe.createSubtleCryptoProvider(),
      )
    } catch (error: unknown) {
      // Do NOT log the body or signature — only the class. An invalid signature
      // is expected adversarial traffic, not an internal fault.
      throw billingFault('constructEvent', error)
    }
  }
}

/**
 * Wrap a Stripe SDK error as a {@link BillingError}, logging only its class.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function billingFault(operation: string, error: unknown): BillingError {
  const name = error instanceof Error ? error.name : typeof error
  console.error(`[billing] ${operation} failed: ${name}`)
  return new BillingError(`Stripe ${operation} failed`, { cause: error })
}

/**
 * Transactional email delivery for two-factor sign-in codes, behind a narrow
 * {@link EmailSender} seam.
 *
 * The route depends only on the interface — never the concrete provider — so the
 * login flow is testable with a fake that captures sent messages, and the
 * production provider (Resend) is swapped in at the worker entry from
 * `env.RESEND_API_KEY`. The whole 2FA feature GATES on this seam: when
 * {@link buildEmailSender} returns `null` (no key configured), login issues a
 * session immediately as today; only when a sender exists does a password
 * success start an emailed-code challenge.
 *
 * Credential discipline (CLAUDE.md §6): a send failure throws {@link EmailError}
 * so the login route fails closed (no session issued). Only the upstream HTTP
 * status / error class is logged — never the code or the recipient's full
 * address.
 */

import type { Env, ScannerConfig } from '../config/env'
import { EmailError } from '../errors'

/** A single transactional email to deliver. */
export interface EmailMessage {
  /** Recipient address. */
  readonly to: string
  /** Subject line. */
  readonly subject: string
  /** HTML body. */
  readonly html: string
  /** Plain-text fallback body. */
  readonly text: string
}

/** The narrow email-delivery capability the auth routes depend on. */
export interface EmailSender {
  /**
   * Deliver one message. Resolves on success; throws {@link EmailError} on any
   * provider failure so the caller fails closed.
   */
  send(message: EmailMessage): Promise<void>
}

/** Resend's send endpoint. The only network dependency of the email layer. */
const RESEND_ENDPOINT = 'https://api.resend.com/emails'
/** Lowest HTTP status code considered a success (2xx). */
const HTTP_OK_MIN = 200
/** Lowest HTTP status code NOT considered a success (i.e. 300+). */
const HTTP_OK_MAX_EXCLUSIVE = 300

/**
 * {@link EmailSender} backed by the Resend HTTP API. Constructed once at startup
 * from `RESEND_API_KEY` and the configured `from` address (which must be on a
 * Resend-verified domain).
 */
export class ResendEmailSender implements EmailSender {
  /**
   * @param apiKey - The Resend API key (a secret, from `env.RESEND_API_KEY`).
   * @param from - The verified `From` address (from `config.emailFrom`).
   */
  public constructor(
    private readonly apiKey: string,
    private readonly from: string,
  ) {}

  /**
   * POST the message to Resend with bearer auth. A non-2xx response or a
   * transport failure throws {@link EmailError}; the thrown message carries only
   * the status / error class, never the email's contents.
   *
   * Time complexity: O(1) (one HTTP round trip). Space complexity: O(n) in the
   * body size.
   *
   * @throws {EmailError} On a non-2xx response or an unreachable provider.
   */
  public async send(message: EmailMessage): Promise<void> {
    let response: Response
    try {
      response = await fetch(RESEND_ENDPOINT, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: this.from,
          to: message.to,
          subject: message.subject,
          html: message.html,
          text: message.text,
        }),
      })
    } catch (error: unknown) {
      const name = error instanceof Error ? error.constructor.name : typeof error
      console.error(`[email] Resend request failed: ${name}`)
      throw new EmailError('email provider unreachable', { cause: error })
    }
    if (response.status < HTTP_OK_MIN || response.status >= HTTP_OK_MAX_EXCLUSIVE) {
      console.error(`[email] Resend rejected the send: HTTP ${response.status}`)
      throw new EmailError(`email provider returned status ${response.status}`)
    }
  }
}

/**
 * Build the configured {@link EmailSender}, or `null` when no provider key is
 * set. This is the 2FA gate: a `null` sender means email two-factor is
 * unavailable and the login route issues a session immediately (today's
 * behavior); a non-`null` sender activates the emailed-code challenge.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @param env - The worker env, read for the `RESEND_API_KEY` secret.
 * @param config - The validated config, read for the verified `from` address.
 * @returns A {@link ResendEmailSender} when a non-empty key is present, else `null`.
 */
export function buildEmailSender(env: Env, config: ScannerConfig): EmailSender | null {
  const apiKey = env.RESEND_API_KEY
  if (typeof apiKey !== 'string' || apiKey.length === 0) {
    return null
  }
  return new ResendEmailSender(apiKey, config.emailFrom)
}

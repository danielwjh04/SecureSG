/**
 * `POST /api/contact` handler: a PUBLIC contact-sales endpoint.
 *
 * A visitor submits `{ name, email, message }` and the inquiry is emailed to the
 * server-side-configured recipients (`config.contactRecipients`) via the same
 * Resend {@link EmailSender} the OTP flow uses. The recipient inboxes NEVER leave
 * the server — the public form carries only the visitor's own fields — so the
 * sales addresses cannot be scraped from the frontend.
 *
 * Abuse bound: a per-client-IP (CF-Connecting-IP) rate limit of
 * `config.contactRatePerHour` inquiries per clock hour, enforced via KV. When KV
 * is unbound the limit is skipped (the endpoint still functions). All visitor
 * input is HTML-escaped before it enters the HTML body, so a crafted name/message
 * cannot inject markup into the recipient's mail client.
 *
 * Failure mapping (fail loudly, then closed): a Zod parse failure → 422; no email
 * provider configured → 503; the provider rejecting/unreachable ({@link EmailError})
 * → 502; the per-IP hourly cap exceeded → 429.
 */

import type { ScannerConfig } from '../config/env'
import type { ContactPayload } from '../schemas/validate'
import type { EmailSender } from '../email/sender'
import { EmailError, ParseError, ScannerError } from '../errors'
import { contactSchema } from '../schemas/validate'

const STATUS_OK = 200
const STATUS_UNPROCESSABLE = 422
const STATUS_TOO_MANY_REQUESTS = 429
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502
const STATUS_SERVICE_UNAVAILABLE = 503

/** Cloudflare's true-client-IP header, used to key the per-IP rate limit. */
const CLIENT_IP_HEADER = 'CF-Connecting-IP'
/** Rate-limit key suffix when no client IP is present (one shared bucket). */
const UNKNOWN_IP = 'unknown'
/** Namespaced, versioned prefix for every contact rate-limit key. */
const RATE_KEY_PREFIX = 'contact:rl:v1:'
/** Seconds in one hour — the rate-limit window length and KV entry TTL. */
const SECONDS_PER_HOUR = 3600

/**
 * The minimal Cloudflare KV surface the rate limit uses: a string `get` and a
 * `put` with an optional `expirationTtl`. Declared structurally (rather than
 * depending on the full `KVNamespace` type) so a test can inject a tiny
 * `{ get, put }` fake, mirroring {@link ../scanner/verdictCache.VerdictCacheKv}.
 */
export interface ContactRateLimitKv {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/** A configured contact route's dependencies, assembled by the worker entry. */
export interface ContactDeps {
  /** The Resend-backed sender, or `null` when `RESEND_API_KEY` is unset (→ 503). */
  readonly emailSender: EmailSender | null
  /** The per-IP rate-limit store, or `null` when KV is unbound (limit skipped). */
  readonly kv: ContactRateLimitKv | null
  /** Validated config supplying the recipients, from address, and rate cap. */
  readonly config: ScannerConfig
}

/** HTML metacharacter → entity map, applied to every visitor-supplied string. */
const HTML_ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}
const HTML_ESCAPE_PATTERN = /[&<>"']/g

/**
 * Escape the five HTML-significant characters so untrusted text is safe to embed
 * in an HTML email body (it renders as literal text, never markup). `&` is in the
 * map so an already-escaped entity is double-escaped rather than passed through —
 * the value is plain text, not pre-escaped HTML.
 *
 * Time complexity: O(n) in the string length. Space complexity: O(n).
 */
function escapeHtml(value: string): string {
  return value.replace(HTML_ESCAPE_PATTERN, (char) => HTML_ESCAPES[char] ?? char)
}

/**
 * Resolve the client IP from the CF-Connecting-IP header, or a shared `unknown`
 * bucket when it is absent/blank. The IP only keys the rate limit; it is never
 * stored or emailed.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function clientIp(request: Request): string {
  const ip = request.headers.get(CLIENT_IP_HEADER)?.trim()
  return ip !== undefined && ip.length > 0 ? ip : UNKNOWN_IP
}

/**
 * Enforce the per-IP hourly cap against KV, returning `true` when the request is
 * within budget (and recording it) or `false` when the cap is already reached.
 *
 * Window model: a fixed clock-hour bucket keyed by `floor(now / 3600)`, so each
 * IP gets `limit` inquiries per hour; the KV entry is written with a one-hour
 * TTL so a stale bucket self-expires (no cleanup pass). The count is read, the
 * cap checked, then the incremented count written back — a benign race under
 * concurrency can only UNDER-count by a hair (two reads seeing the same value),
 * which is acceptable for an anti-abuse bound and never over-counts a legitimate
 * caller.
 *
 * Time complexity: O(1) — one KV read + one KV write. Space complexity: O(1).
 *
 * @param kv - The rate-limit store (non-null; the caller skips this on `null`).
 * @param ip - The client IP keying the bucket.
 * @param limit - The max inquiries per hour (`config.contactRatePerHour`).
 * @param nowSeconds - The current edge time in whole seconds (bucket selector).
 * @returns `true` if within budget (request recorded), else `false`.
 */
async function withinRateLimit(
  kv: ContactRateLimitKv,
  ip: string,
  limit: number,
  nowSeconds: number,
): Promise<boolean> {
  const bucket = Math.floor(nowSeconds / SECONDS_PER_HOUR)
  const key = `${RATE_KEY_PREFIX}${ip}:${bucket}`
  const raw = await kv.get(key)
  const used = raw === null ? 0 : Number.parseInt(raw, 10)
  // A corrupt/non-numeric entry fails closed: treat it as the cap so a poisoned
  // counter cannot be used to lift the limit.
  const current = Number.isFinite(used) && used >= 0 ? used : limit
  if (current >= limit) {
    return false
  }
  await kv.put(key, String(current + 1), { expirationTtl: SECONDS_PER_HOUR })
  return true
}

/**
 * Render the inquiry email's `subject`, `html`, and `text`. Every visitor field
 * is HTML-escaped in the HTML body; the plain-text body needs no escaping (it is
 * not interpreted as markup). The subject carries the name so the inbox shows who
 * wrote in.
 *
 * Time complexity: O(n) in the field lengths. Space complexity: O(n).
 */
function buildInquiryEmail(payload: ContactPayload): {
  subject: string
  html: string
  text: string
} {
  const subject = `SecureAI sales inquiry from ${payload.name}`
  const text =
    `New SecureAI sales inquiry.\n\n` +
    `Name: ${payload.name}\n` +
    `Email: ${payload.email}\n\n` +
    `Message:\n${payload.message}`
  const html =
    `<p>New SecureAI sales inquiry.</p>` +
    `<p><strong>Name:</strong> ${escapeHtml(payload.name)}</p>` +
    `<p><strong>Email:</strong> ${escapeHtml(payload.email)}</p>` +
    `<p><strong>Message:</strong></p>` +
    `<p style="white-space:pre-wrap;">${escapeHtml(payload.message)}</p>`
  return { subject, html, text }
}

/**
 * Parse + Zod-validate the JSON body into a {@link ContactPayload}, or throw
 * {@link ParseError} (→ 422). A body that is not JSON, or fails the strict
 * schema, never reaches the send path.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} On non-JSON or schema-invalid input.
 */
async function parseContactBody(request: Request): Promise<ContactPayload> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = contactSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid contact request: ${parsed.error.message}`)
  }
  return parsed.data
}

/** Map a thrown error to its HTTP status: ParseError → 422, else 500. */
function statusForError(error: unknown): number {
  if (error instanceof ParseError) {
    return STATUS_UNPROCESSABLE
  }
  if (error instanceof ScannerError) {
    return STATUS_SERVER_ERROR
  }
  return STATUS_SERVER_ERROR
}

/**
 * Handle `POST /api/contact`. Validates the body, enforces the per-IP hourly
 * rate limit (when KV is bound), then emails ONE inquiry to every configured
 * recipient with the visitor's address as `Reply-To`, so a reply reaches them
 * directly. Returns `200 { ok: true }` on success.
 *
 * Outcomes:
 *   - invalid body → 422 ({@link ParseError});
 *   - per-IP hourly cap exceeded → 429 (no email sent);
 *   - no email provider configured (`emailSender === null`) → 503;
 *   - provider rejected the send / unreachable → 502 ({@link EmailError}).
 *
 * The rate check runs BEFORE the send so a flood cannot drive provider cost; the
 * provider-configured (503) check runs first so an unconfigured deploy answers
 * deterministically without consuming a rate-limit slot.
 *
 * Time complexity: O(1) rate check + one email round trip (O(r) in recipients).
 * Space complexity: O(n) in the body size.
 */
export async function handleContact(request: Request, deps: ContactDeps): Promise<Response> {
  if (deps.emailSender === null) {
    return Response.json(
      { error: 'service_unavailable', message: 'contact is not configured' },
      { status: STATUS_SERVICE_UNAVAILABLE },
    )
  }
  try {
    const body = await parseContactBody(request)

    if (deps.kv !== null) {
      const allowed = await withinRateLimit(
        deps.kv,
        clientIp(request),
        deps.config.contactRatePerHour,
        Math.floor(Date.now() / 1000),
      )
      if (!allowed) {
        return Response.json(
          { error: 'rate_limited', message: 'too many inquiries; please try again later' },
          { status: STATUS_TOO_MANY_REQUESTS },
        )
      }
    }

    const { subject, html, text } = buildInquiryEmail(body)
    await deps.emailSender.send({
      to: deps.config.contactRecipients,
      replyTo: body.email,
      subject,
      html,
      text,
    })

    return Response.json({ ok: true }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleContact] ${className}`)
    if (error instanceof ParseError) {
      const message = error.message
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    // A send the provider rejected or could not receive fails closed: no inquiry
    // was delivered, so surface a 502 rather than a misleading success.
    if (error instanceof EmailError) {
      return Response.json({ error: 'email_send_failed' }, { status: STATUS_BAD_GATEWAY })
    }
    return Response.json({ error: 'contact_failed' }, { status: statusForError(error) })
  }
}

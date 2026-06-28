/**
 * `POST /api/contact` route tests: the public contact-sales endpoint that emails
 * an inquiry to the server-side-configured recipients via the Resend
 * {@link EmailSender}, behind a per-IP hourly rate limit.
 */

import { describe, expect, it } from 'vitest'
import type { ContactDeps, ContactRateLimitKv } from './contact'
import type { EmailMessage, EmailSender } from '../email/sender'
import { loadConfig } from '../config/env'
import { EmailError } from '../errors'
import { handleContact } from './contact'

const config = loadConfig({
  SCANNER_CONTACT_RECIPIENTS: 'sales-a@example.com,sales-b@example.com',
  SCANNER_CONTACT_RATE_PER_HOUR: '2',
})

/** An EmailSender that records every sent message (no network). */
class FakeEmailSender implements EmailSender {
  public readonly sent: EmailMessage[] = []
  public failNext = false
  public async send(message: EmailMessage): Promise<void> {
    if (this.failNext) {
      this.failNext = false
      throw new EmailError('injected email failure')
    }
    this.sent.push(message)
  }
}

/** An in-memory ContactRateLimitKv with a TTL-agnostic string map. */
class FakeKv implements ContactRateLimitKv {
  public readonly store = new Map<string, string>()
  public async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null
  }
  public async put(key: string, value: string): Promise<void> {
    this.store.set(key, value)
  }
}

function deps(overrides: Partial<ContactDeps> = {}): ContactDeps {
  return {
    emailSender: new FakeEmailSender(),
    kv: null,
    config,
    ...overrides,
  }
}

function contactReq(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request('https://secureai.test/api/contact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

const validBody = {
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  message: 'We would like an enterprise quote for 200 seats.',
}

describe('handleContact', () => {
  it('sends one email to BOTH configured recipients from emailFrom, reply-to the visitor', async () => {
    const sender = new FakeEmailSender()
    const res = await handleContact(contactReq(validBody), deps({ emailSender: sender }))

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })

    expect(sender.sent).toHaveLength(1)
    const message = sender.sent[0] as EmailMessage
    // ONE email, fanned out to every configured recipient.
    expect(message.to).toEqual(['sales-a@example.com', 'sales-b@example.com'])
    // A reply reaches the visitor, not the no-reply From.
    expect(message.replyTo).toBe('ada@example.com')
    // The From is the configured sender (asserted via the Resend layer, but the
    // route never overrides it — the sender owns `from`).
    expect(config.emailFrom).toBe('SecureAI <noreply@zurielst.com>')
  })

  it('puts the visitor name in the subject and the fields in both bodies', async () => {
    const sender = new FakeEmailSender()
    await handleContact(contactReq(validBody), deps({ emailSender: sender }))
    const message = sender.sent[0] as EmailMessage
    expect(message.subject).toBe('SecureAI sales inquiry from Ada Lovelace')
    expect(message.text).toContain('Ada Lovelace')
    expect(message.text).toContain('ada@example.com')
    expect(message.text).toContain('200 seats')
    expect(message.html).toContain('Ada Lovelace')
  })

  it('HTML-escapes visitor input in the HTML body (no markup injection)', async () => {
    const sender = new FakeEmailSender()
    const xss = {
      name: '<script>alert(1)</script>',
      email: 'attacker@example.com',
      message: 'hi <img src=x onerror=alert(2)> & "quoted" \'tick\'',
    }
    await handleContact(contactReq(xss), deps({ emailSender: sender }))
    const message = sender.sent[0] as EmailMessage
    // The raw tag never appears; its escaped form does.
    expect(message.html).not.toContain('<script>')
    expect(message.html).toContain('&lt;script&gt;')
    expect(message.html).not.toContain('<img')
    expect(message.html).toContain('&lt;img')
    expect(message.html).toContain('&amp;')
    expect(message.html).toContain('&quot;')
    expect(message.html).toContain('&#39;')
    // The subject is built from the same (already length-validated) name; the
    // plain-text body is not HTML, so it carries the raw text unescaped.
    expect(message.text).toContain('<img src=x onerror=alert(2)>')
  })

  it('rejects an invalid body with 422 and sends nothing', async () => {
    const sender = new FakeEmailSender()
    const res = await handleContact(
      contactReq({ name: '', email: 'not-an-email', message: '' }),
      deps({ emailSender: sender }),
    )
    expect(res.status).toBe(422)
    expect(sender.sent).toHaveLength(0)
  })

  it('rejects an unknown extra field with 422 (strict schema)', async () => {
    const res = await handleContact(
      contactReq({ ...validBody, company: 'ACME' }),
      deps(),
    )
    expect(res.status).toBe(422)
  })

  it('rejects a non-JSON body with 422', async () => {
    const res = await handleContact(
      new Request('https://secureai.test/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not json',
      }),
      deps(),
    )
    expect(res.status).toBe(422)
  })

  it('returns 503 when no email provider is configured', async () => {
    const res = await handleContact(contactReq(validBody), deps({ emailSender: null }))
    expect(res.status).toBe(503)
  })

  it('returns 502 when the provider rejects/unreachable (EmailError)', async () => {
    const sender = new FakeEmailSender()
    sender.failNext = true
    const res = await handleContact(contactReq(validBody), deps({ emailSender: sender }))
    expect(res.status).toBe(502)
  })

  it('enforces the per-IP hourly limit: returns 429 once the cap is exceeded', async () => {
    const sender = new FakeEmailSender()
    const kv = new FakeKv()
    const headers = { 'CF-Connecting-IP': '203.0.113.7' }
    // Cap is 2/hour for this config. First two succeed, the third is 429.
    const first = await handleContact(contactReq(validBody, headers), deps({ emailSender: sender, kv }))
    const second = await handleContact(contactReq(validBody, headers), deps({ emailSender: sender, kv }))
    const third = await handleContact(contactReq(validBody, headers), deps({ emailSender: sender, kv }))

    expect(first.status).toBe(200)
    expect(second.status).toBe(200)
    expect(third.status).toBe(429)
    // The blocked request sent no email.
    expect(sender.sent).toHaveLength(2)
  })

  it('rate-limits per IP independently (a different IP is unaffected)', async () => {
    const sender = new FakeEmailSender()
    const kv = new FakeKv()
    const ipA = { 'CF-Connecting-IP': '203.0.113.1' }
    const ipB = { 'CF-Connecting-IP': '203.0.113.2' }
    await handleContact(contactReq(validBody, ipA), deps({ emailSender: sender, kv }))
    await handleContact(contactReq(validBody, ipA), deps({ emailSender: sender, kv }))
    const ipABlocked = await handleContact(contactReq(validBody, ipA), deps({ emailSender: sender, kv }))
    const ipBOk = await handleContact(contactReq(validBody, ipB), deps({ emailSender: sender, kv }))

    expect(ipABlocked.status).toBe(429)
    expect(ipBOk.status).toBe(200)
  })

  it('skips the rate limit entirely when KV is null', async () => {
    const sender = new FakeEmailSender()
    const headers = { 'CF-Connecting-IP': '203.0.113.9' }
    // Far more than the cap; with no KV none are limited.
    for (let i = 0; i < 5; i += 1) {
      const res = await handleContact(contactReq(validBody, headers), deps({ emailSender: sender, kv: null }))
      expect(res.status).toBe(200)
    }
    expect(sender.sent).toHaveLength(5)
  })

  it('a poisoned (non-numeric) counter fails closed to 429', async () => {
    const sender = new FakeEmailSender()
    const kv = new FakeKv()
    // Seed the current-hour bucket with garbage for this IP.
    const bucket = Math.floor(Date.now() / 1000 / 3600)
    kv.store.set(`contact:rl:v1:203.0.113.50:${bucket}`, 'not-a-number')
    const res = await handleContact(
      contactReq(validBody, { 'CF-Connecting-IP': '203.0.113.50' }),
      deps({ emailSender: sender, kv }),
    )
    expect(res.status).toBe(429)
    expect(sender.sent).toHaveLength(0)
  })
})

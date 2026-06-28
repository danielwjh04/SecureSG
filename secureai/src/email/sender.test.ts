import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Env, ScannerConfig } from '../config/env'
import { loadConfig } from '../config/env'
import { EmailError } from '../errors'
import { ResendEmailSender, buildEmailSender } from './sender'

const config: ScannerConfig = loadConfig({})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('ResendEmailSender', () => {
  it('POSTs to the Resend endpoint with bearer auth and the from/to/subject body', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    const sender = new ResendEmailSender('re_test_key', 'SecureAI <noreply@zurielst.com>')
    await sender.send({ to: 'a@b.com', subject: 'Subj', html: '<p>h</p>', text: 't' })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('https://api.resend.com/emails')
    expect(init.method).toBe('POST')
    const headers = init.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer re_test_key')
    const body = JSON.parse(init.body as string) as Record<string, string>
    expect(body).toMatchObject({
      from: 'SecureAI <noreply@zurielst.com>',
      to: 'a@b.com',
      subject: 'Subj',
      html: '<p>h</p>',
      text: 't',
    })
  })

  it('throws EmailError on a non-2xx response (and never logs the body)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"error":"x"}', { status: 422 })))
    const sender = new ResendEmailSender('re_test_key', 'from@x.com')
    await expect(
      sender.send({ to: 'a@b.com', subject: 's', html: 'h', text: 't' }),
    ).rejects.toBeInstanceOf(EmailError)
  })

  it('throws EmailError when the provider is unreachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network down')
      }),
    )
    const sender = new ResendEmailSender('re_test_key', 'from@x.com')
    await expect(
      sender.send({ to: 'a@b.com', subject: 's', html: 'h', text: 't' }),
    ).rejects.toBeInstanceOf(EmailError)
  })
})

describe('buildEmailSender (the 2FA gate)', () => {
  it('returns null when RESEND_API_KEY is absent', () => {
    expect(buildEmailSender({} as Env, config)).toBeNull()
  })

  it('returns null when RESEND_API_KEY is an empty string', () => {
    expect(buildEmailSender({ RESEND_API_KEY: '' } as Env, config)).toBeNull()
  })

  it('returns a ResendEmailSender when RESEND_API_KEY is a non-empty string', () => {
    const sender = buildEmailSender({ RESEND_API_KEY: 're_live_key' } as Env, config)
    expect(sender).toBeInstanceOf(ResendEmailSender)
  })
})

// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  ApiError,
  fetchMe,
  fetchRecentScans,
  login,
  logout,
  removeMember,
  rotateApiKey,
  scanSkill,
  startCheckout,
  submitContact,
  verifyProof,
} from './client'
import { API } from '../config'
import type {
  AuthResponse,
  MeResponse,
  Proof,
  ScanRequest,
  ScanResult,
  VerifyResult,
} from './types'

function mockFetch(response: Partial<Response> & { ok: boolean }): void {
  vi.stubGlobal('fetch', vi.fn(async () => response as Response))
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('scanSkill', () => {
  it('returns the parsed JSON body on an ok response', async () => {
    const body = { verdict: 'BLOCK' } as unknown as ScanResult
    mockFetch({ ok: true, status: 200, json: async () => body })
    await expect(scanSkill({ content: 'x' })).resolves.toBe(body)
  })

  it('POSTs the request body to API.scan', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({}) as ScanResult,
    }) as Response)
    vi.stubGlobal('fetch', fetchMock)

    const req: ScanRequest = { sourceUrl: 'https://example.com/SKILL.md' }
    await scanSkill(req)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [path, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ]
    expect(path).toBe(API.scan)
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual(req)
  })

  it('throws ApiError with the status on a non-ok response', async () => {
    mockFetch({ ok: false, status: 422, json: async () => ({}) })
    await expect(scanSkill({ content: 'x' })).rejects.toMatchObject({
      name: 'ApiError',
      status: 422,
    })
  })

  it('throws ApiError(0) when the backend is unreachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network down')
      }),
    )
    const caught = await scanSkill({ content: 'x' }).catch((e: unknown) => e)
    expect(caught).toBeInstanceOf(ApiError)
    expect((caught as ApiError).status).toBe(0)
  })
})

describe('verifyProof', () => {
  it('POSTs the proof envelope to API.verify and returns the result', async () => {
    const proof = { genesisHash: 'g', steps: [], headHash: 'g' } as unknown as Proof
    const result: VerifyResult = { status: 'CHAIN_OK', firstInvalidIndex: null }
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => result,
    }) as Response)
    vi.stubGlobal('fetch', fetchMock)

    await expect(verifyProof(proof)).resolves.toEqual(result)
    const [path, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ]
    expect(path).toBe(API.verify)
    expect(JSON.parse(init.body as string)).toEqual({ proof })
  })
})

describe('account endpoints', () => {
  /** Capture the single fetch call so each test asserts path/method/credentials. */
  function captureFetch(body: unknown): ReturnType<typeof vi.fn> {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => body,
    }) as Response)
    vi.stubGlobal('fetch', fetchMock)
    return fetchMock
  }

  function lastInit(fetchMock: ReturnType<typeof vi.fn>): RequestInit {
    return (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1]
  }

  it('login POSTs credentials to API.login with the session cookie', async () => {
    const user: AuthResponse = { user: { email: 'a@b.com', tier: 'pro' } }
    const fetchMock = captureFetch(user)

    await expect(login({ email: 'a@b.com', password: 'pw' })).resolves.toEqual(user)

    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(path).toBe(API.login)
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('include')
    expect(JSON.parse(init.body as string)).toEqual({ email: 'a@b.com', password: 'pw' })
  })

  it('fetchMe GETs API.me with credentials and surfaces a 401 as ApiError', async () => {
    const me: MeResponse = {
      email: 'a@b.com',
      tier: 'free',
      createdAt: '2026-06-01T00:00:00.000Z',
      apiKeyPrefix: 'sk_live_ab',
      role: 'member',
      isAdmin: false,
      isOwner: false,
    }
    const fetchMock = captureFetch(me)
    await expect(fetchMe()).resolves.toEqual(me)
    const [path] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(path).toBe(API.me)
    expect(lastInit(fetchMock).credentials).toBe('include')

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false, status: 401, json: async () => ({}) }) as Response),
    )
    await expect(fetchMe()).rejects.toMatchObject({ name: 'ApiError', status: 401 })
  })

  it('fetchRecentScans GETs the recent endpoint with the limit and credentials', async () => {
    const body = {
      scans: [
        {
          id: 's1',
          verdict: 'BLOCK',
          source: { kind: 'url', ref: 'https://example.com' },
          flagged: 1,
          headHash: 'a'.repeat(64),
          scannedAt: '2026-06-28T00:00:00.000Z',
        },
      ],
    }
    const fetchMock = captureFetch(body)
    await expect(fetchRecentScans(3)).resolves.toEqual(body)
    const [path] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(path).toBe(`${API.recentScans}?limit=3`)
    expect(lastInit(fetchMock).credentials).toBe('include')
  })

  it('fetchRecentScans omits the query when no limit is given', async () => {
    const fetchMock = captureFetch({ scans: [] })
    await fetchRecentScans()
    const [path] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(path).toBe(API.recentScans)
  })

  it('removeMember POSTs the user id to the remove endpoint with credentials', async () => {
    const fetchMock = captureFetch({ removed: 'u1' })
    await expect(removeMember('u1')).resolves.toEqual({ removed: 'u1' })
    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(path).toBe(API.adminMemberRemove)
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('include')
    expect(JSON.parse(init.body as string)).toEqual({ userId: 'u1' })
  })

  it('removeMember surfaces a 403 as ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: false, status: 403, json: async () => ({}) }) as Response),
    )
    await expect(removeMember('u1')).rejects.toMatchObject({ name: 'ApiError', status: 403 })
  })

  it('logout, rotateApiKey, and startCheckout POST with credentials', async () => {
    const logoutFetch = captureFetch({})
    await logout()
    expect((logoutFetch.mock.calls[0] as unknown as [string, RequestInit])[0]).toBe(
      API.logout,
    )
    expect(lastInit(logoutFetch).method).toBe('POST')
    expect(lastInit(logoutFetch).credentials).toBe('include')

    const rotateFetch = captureFetch({ apiKey: 'sk_live_new' })
    await expect(rotateApiKey()).resolves.toEqual({ apiKey: 'sk_live_new' })
    expect((rotateFetch.mock.calls[0] as unknown as [string, RequestInit])[0]).toBe(
      API.rotateKey,
    )

    const checkoutFetch = captureFetch({ url: 'https://stripe.test/s' })
    await expect(startCheckout()).resolves.toEqual({ url: 'https://stripe.test/s' })
    expect((checkoutFetch.mock.calls[0] as unknown as [string, RequestInit])[0]).toBe(
      API.checkout,
    )
    expect(lastInit(checkoutFetch).credentials).toBe('include')
  })
})

describe('submitContact', () => {
  it('POSTs the enquiry body to API.contact and returns the result', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true }),
    }) as Response)
    vi.stubGlobal('fetch', fetchMock)

    const body = { name: 'Ada', email: 'ada@co.com', message: 'Hi' }
    await expect(submitContact(body)).resolves.toEqual({ ok: true })

    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(path).toBe(API.contact)
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual(body)
  })

  it('surfaces a 429 as ApiError so the form can map it to inline copy', async () => {
    mockFetch({ ok: false, status: 429, json: async () => ({}) })
    await expect(
      submitContact({ name: 'Ada', email: 'ada@co.com', message: 'Hi' }),
    ).rejects.toMatchObject({ name: 'ApiError', status: 429 })
  })
})

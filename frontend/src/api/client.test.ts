import { afterEach, expect, it, vi } from 'vitest'
import { ApiError, getAlerts, rpcCall } from './client'

function fakeResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  } as Response
}

afterEach(() => {
  vi.unstubAllGlobals()
})

it('parses an ok JSON response', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(fakeResponse([])))
  expect(await getAlerts()).toEqual([])
})

it('throws ApiError on a non-ok response', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(fakeResponse('nope', 500)))
  await expect(getAlerts()).rejects.toBeInstanceOf(ApiError)
})

it('throws ApiError when the backend is unreachable', async () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('failed to fetch')))
  await expect(getAlerts()).rejects.toBeInstanceOf(ApiError)
})

it('returns the JSON-RPC envelope for a blocked call at HTTP 200', async () => {
  const envelope = {
    jsonrpc: '2.0',
    id: 1,
    error: {
      code: -32001,
      message: 'blocked',
      data: { verdict: 'BLOCK', rule_id: 'taint.high_to_external' },
    },
  }
  const fetchMock = vi.fn().mockResolvedValue(fakeResponse(envelope))
  vi.stubGlobal('fetch', fetchMock)
  const result = await rpcCall('s1', { name: 'send_email', arguments: {} }, 1)
  expect('error' in result ? result.error.data?.rule_id : null).toBe(
    'taint.high_to_external',
  )
  const [, init] = fetchMock.mock.calls[0]
  expect(JSON.parse(init.body).params.name).toBe('send_email')
})

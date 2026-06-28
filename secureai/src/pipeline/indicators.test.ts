// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
import { ReputationError } from '../errors'
import type { ReputationReport } from '../schemas/contract'
import { DenylistReputationClient, type IndicatorKv } from './indicators'

/** A small denylist used across the static-match cases. */
const denylist: ReadonlySet<string> = new Set(['evil.com', 'malware.example'])

/** Assess a single url and return its (asserted-present) report. */
async function assessOne(
  client: DenylistReputationClient,
  url: string,
): Promise<ReputationReport> {
  const reports = await client.assessFinalUrls([url])
  expect(reports).toHaveLength(1)
  return reports[0]!
}

/** A tiny KV fake: `get` resolves to the value the test seeds, else null. */
function fakeKv(entries: Record<string, string> = {}): IndicatorKv {
  return {
    get: async (key: string) => (key in entries ? entries[key]! : null),
  }
}

describe('DenylistReputationClient — static matching', () => {
  it('flags an exact host hit with the denylisted report shape', async () => {
    const client = new DenylistReputationClient(denylist)
    const report = await assessOne(client, 'https://evil.com/path?q=1')
    expect(report).toEqual({
      url: 'https://evil.com/path?q=1',
      score: '1.00',
      summary: 'host on known-bad denylist',
      title: 'evil.com',
      flagged: true,
      status: 'denylisted',
    })
  })

  it('flags a subdomain via parent-domain match (deep nesting)', async () => {
    const client = new DenylistReputationClient(denylist)
    const report = await assessOne(client, 'https://a.b.evil.com/')
    expect(report.flagged).toBe(true)
    expect(report.status).toBe('denylisted')
    expect(report.title).toBe('a.b.evil.com')
  })

  it('does NOT flag a clean host', async () => {
    const client = new DenylistReputationClient(denylist)
    const report = await assessOne(client, 'https://example.com/safe')
    expect(report).toEqual({
      url: 'https://example.com/safe',
      score: '0.00',
      summary: 'host not on any known-bad denylist',
      title: 'example.com',
      flagged: false,
      status: 'clean',
    })
  })

  it('does NOT flag a sibling that merely SUFFIXES a denylist entry (notevil.com)', async () => {
    // A pure-string suffix check would wrongly match "notevil.com" against
    // "evil.com"; the label-boundary walk must not.
    const client = new DenylistReputationClient(denylist)
    const report = await assessOne(client, 'https://notevil.com/')
    expect(report.flagged).toBe(false)
  })

  it('lowercases the host before matching (case-insensitive)', async () => {
    const client = new DenylistReputationClient(denylist)
    const report = await assessOne(client, 'https://EVIL.COM/')
    expect(report.flagged).toBe(true)
    expect(report.title).toBe('evil.com')
  })

  it('returns one report per url, in input order', async () => {
    const client = new DenylistReputationClient(denylist)
    const reports = await client.assessFinalUrls([
      'https://example.com/',
      'https://malware.example/x',
    ])
    expect(reports.map((r) => r.flagged)).toEqual([false, true])
  })
})

describe('DenylistReputationClient — fail-closed on unparseable url', () => {
  it('flags an unparseable url with status "unparseable"', async () => {
    const client = new DenylistReputationClient(denylist)
    const report = await assessOne(client, 'not a url')
    expect(report).toEqual({
      url: 'not a url',
      score: '1.00',
      summary: 'destination URL could not be parsed for reputation lookup',
      title: 'not a url',
      flagged: true,
      status: 'unparseable',
    })
  })
})

describe('DenylistReputationClient — KV dynamic entries', () => {
  it('flags a host present in KV under host:<hostname> even when not in the static set', async () => {
    const kv = fakeKv({ 'host:dynamic-bad.test': '1' })
    const client = new DenylistReputationClient(new Set(), kv)
    const report = await assessOne(client, 'https://dynamic-bad.test/p')
    expect(report.flagged).toBe(true)
    expect(report.status).toBe('denylisted')
  })

  it('does NOT consult KV when the static set already flags the host (no KV read)', async () => {
    const get = vi.fn(async () => null)
    const client = new DenylistReputationClient(denylist, { get })
    const report = await assessOne(client, 'https://evil.com/')
    expect(report.flagged).toBe(true)
    expect(get).not.toHaveBeenCalled()
  })

  it('leaves a host clean when neither the static set nor KV flags it', async () => {
    const kv = fakeKv({ 'host:other.test': '1' })
    const client = new DenylistReputationClient(new Set(), kv)
    const report = await assessOne(client, 'https://safe.test/')
    expect(report.flagged).toBe(false)
    expect(report.status).toBe('clean')
  })

  it('raises ReputationError when a KV read throws (fail-closed, never swallowed)', async () => {
    const kv: IndicatorKv = {
      get: async () => {
        throw new Error('kv unavailable')
      },
    }
    const client = new DenylistReputationClient(new Set(), kv)
    await expect(client.assessFinalUrls(['https://safe.test/'])).rejects.toBeInstanceOf(
      ReputationError,
    )
  })
})

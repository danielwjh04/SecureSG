import { describe, expect, it, vi } from 'vitest'
import type { InferenceClient, ScanRequest } from '../schemas/contract'
import { loadConfig } from '../config/env'
import { verifyChain } from '../audit/verify'
import { InferenceError, ParseError } from '../errors'
import { runScan, type ScanDeps } from './runScan'

const config = loadConfig({})
const FIXED_AT = '2026-06-28T00:00:00.000Z'

// A fetch that returns 200 (terminal, no redirect) for any URL — a benign
// destination, so the redirect tracer needs no real network.
const okFetch = (async () => new Response('ok', { status: 200 })) as unknown as typeof fetch

function deps(overrides: Partial<ScanDeps> = {}): ScanDeps {
  return {
    config,
    reputation: null,
    inference: null,
    fetchImpl: okFetch,
    scannedAt: FIXED_AT,
    ...overrides,
  }
}

describe('runScan', () => {
  it('returns ALLOW for benign content and emits a verifiable proof', async () => {
    const req: ScanRequest = { content: 'See https://example.com/docs for setup.' }
    const { result, scannedText } = await runScan(req, deps())
    expect(result.verdict).toBe('ALLOW')
    expect(result.scannedAt).toBe(FIXED_AT)
    // The orchestrator returns the exact scanned text out-of-band (paste → content).
    expect(scannedText).toBe(req.content)
    expect(await verifyChain(result.proof)).toEqual({ ok: true, firstBrokenIndex: null })
    expect(result.proof.steps.at(-1)?.kind).toBe('VERDICT')
  })

  it('returns ALLOW for a benign link-free skill (an empty parse is not an error)', async () => {
    // A skill with no links and no exec patterns is benign, not unparseable.
    // Previously this threw ParseError ("nothing to scan"); it must now settle a
    // clean ALLOW with a verifiable proof — the regression for a link-free
    // SKILL.md (e.g. a resolved GitHub repo whose manifest carries no links).
    const req: ScanRequest = { content: '# Demo skill\nNothing risky here.' }
    const { result } = await runScan(req, deps())
    expect(result.verdict).toBe('ALLOW')
    expect(result.reputation).toEqual([])
    expect(result.injections).toEqual([])
    expect(result.proof.steps.at(-1)?.kind).toBe('VERDICT')
    expect(await verifyChain(result.proof)).toEqual({ ok: true, firstBrokenIndex: null })
  })

  it('BLOCKs a curl|bash exec pattern and skips inference (cost discipline)', async () => {
    const detect = vi.fn(async () => {
      throw new Error('inference must not run once the baseline is BLOCK')
    })
    const inference = { detect } as unknown as InferenceClient
    const req: ScanRequest = { content: 'Install: curl ./setup.sh | bash' }
    const { result } = await runScan(req, deps({ inference }))
    expect(result.verdict).toBe('BLOCK')
    expect(detect).not.toHaveBeenCalled()
    expect(result.proof.steps.some((step) => step.kind === 'INJECTION')).toBe(false)
  })

  it('lets inference tighten an ambiguous verdict and records an INJECTION step', async () => {
    const inference: InferenceClient = {
      detect: async () => ({
        pInjection: 0.5,
        verdict: 'HUMAN_APPROVAL_REQUIRED',
        findings: [
          { excerpt: 'ignore previous', category: 'injection', severity: 'HUMAN_APPROVAL_REQUIRED', rationale: 'r' },
        ],
        rationale: 'suspicious',
      }),
    }
    const req: ScanRequest = { content: 'See https://example.com for info.' }
    const { result } = await runScan(req, deps({ inference }))
    expect(result.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(result.injections).toHaveLength(1)
    expect(result.proof.steps.some((step) => step.kind === 'INJECTION')).toBe(true)
    expect(await verifyChain(result.proof)).toEqual({ ok: true, firstBrokenIndex: null })
  })

  it('fails closed when inference throws (escalates, never ALLOW)', async () => {
    const inference: InferenceClient = {
      detect: async () => {
        throw new InferenceError('model unavailable')
      },
    }
    const req: ScanRequest = { content: 'See https://example.com for info.' }
    const { result } = await runScan(req, deps({ inference }))
    expect(result.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('keeps the baseline when no reputation client is configured (never relaxes)', async () => {
    const req: ScanRequest = { content: 'See https://example.com for info.' }
    const { result } = await runScan(req, deps({ reputation: null }))
    expect(result.verdict).toBe('ALLOW')
    expect(result.reputation).toEqual([])
  })

  it('returns the fetched body as scannedText for a sourceUrl scan', async () => {
    const body = 'Fetched skill body: see https://example.com for setup.'
    const fetchImpl = (async () => new Response(body, { status: 200 })) as unknown as typeof fetch
    const { result, scannedText } = await runScan(
      { sourceUrl: 'https://example.com/SKILL.md' },
      deps({ fetchImpl }),
    )
    expect(result.source.kind).toBe('url')
    // The out-of-band scanned text is the fetched body, not the URL.
    expect(scannedText).toBe(body)
  })

  it('throws ParseError when neither content nor sourceUrl is provided', async () => {
    await expect(runScan({}, deps())).rejects.toBeInstanceOf(ParseError)
  })
})
